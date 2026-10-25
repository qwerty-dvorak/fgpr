/*
 * Protocol taken from libfprint-2-tod1-elan (efd_dev_* / efd_* state machine):
 *   every command is written to EP 0x01; replies come on EP 0x83,
 *   except the frame (00 09) which comes on EP 0x82 as w*h little-endian u16.
 */
#define _POSIX_C_SOURCE 200809L
#include "elan.h"

#include <libusb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ELAN_VID 0x04f3
#define ELAN_PID 0x0c4b

#define EP_OUT     0x01
#define EP_CMD_IN  0x83
#define EP_IMG_IN  0x82

#define TMO_CMD    2000
#define TMO_FINGER 11000  /* 40 3e / 40 3f wait for finger change */

/* efd_parameter_init() values for pid 0x0c4b */
#define CALIB_MAX_DELTA   500 /* |frame mean - sensor mean| for a valid bg */
#define FINGER_MIN_MEAN   500 /* mean of frame - bg that counts as a finger */
#define UNDER_BASE_DELTA  255 /* pixel this far below bg counts as "under base" */
#define UNDER_BASE_PCT    16  /* more than this % under base -> bg is stale */
#define FINGER_TRIES      10
#define CALIB_TRIES       3
#define LIFT_TRIES        3

int elan_verbose = 1;
#define LOG(...) do { if (elan_verbose) fprintf(stderr, __VA_ARGS__); } while (0)

static void msleep(long ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
	nanosleep(&ts, NULL);
}

static int xfer(struct elan *e, uint8_t ep, uint8_t *buf, int len, unsigned tmo)
{
	int n = 0;
	int r = libusb_bulk_transfer(e->usb, ep, buf, len, &n, tmo);

	if (r == LIBUSB_ERROR_TIMEOUT)
		return ELAN_ETIMEOUT;
	if (r || n != len) {
		LOG("elan: ep 0x%02x: %s (%d/%d bytes)\n", ep,
		    r ? libusb_error_name(r) : "short transfer", n, len);
		return ELAN_EIO;
	}
	return ELAN_OK;
}

/* Write cmd, then read rlen bytes from ep (rlen == 0: no reply). */
static int cmd(struct elan *e, const uint8_t *c, int clen, uint8_t ep,
	       void *resp, int rlen, unsigned tmo)
{
	uint8_t out[3];
	int r;

	memcpy(out, c, clen);
	r = xfer(e, EP_OUT, out, clen, tmo);
	if (r || !rlen)
		return r;
	if (c[0] == 0x40 && c[1] == 0x23)
		msleep(100); /* calibration status needs time to settle */
	return xfer(e, ep, resp, rlen, tmo);
}

/* Frame arrives as w*h little-endian u16, same as this x86_64 host. */
static int get_frame(struct elan *e, uint16_t *img)
{
	static const uint8_t c[] = { 0x00, 0x09 };

	return cmd(e, c, 2, EP_IMG_IN, img, e->w * e->h * 2, TMO_CMD);
}

static unsigned mean(const uint16_t *p, int n)
{
	uint64_t s = 0;

	for (int i = 0; i < n; i++)
		s += p[i];
	return (unsigned)((s + n / 2) / n);
}

static void sub_bg(const struct elan *e, uint16_t *img)
{
	for (int i = 0; i < e->w * e->h; i++)
		img[i] = img[i] > e->bg[i] ? img[i] - e->bg[i] : 0;
}

int elan_open(struct elan *e)
{
	static const uint8_t c_fw[] = { 0x40, 0x19 };
	static const uint8_t c_gen[] = { 0x40, 0x21, 0x0a };
	static const uint8_t c_dim[] = { 0x00, 0x0c };
	uint8_t b[4];
	int r;

	memset(e, 0, sizeof(*e));
	if (libusb_init(&e->ctx))
		return ELAN_EIO;
	e->usb = libusb_open_device_with_vid_pid(e->ctx, ELAN_VID, ELAN_PID);
	if (!e->usb) {
		LOG("elan: %04x:%04x not found or no permission\n",
		    ELAN_VID, ELAN_PID);
		goto fail;
	}
	r = libusb_claim_interface(e->usb, 0);
	if (r) {
		LOG("elan: claim interface: %s\n", libusb_error_name(r));
		goto fail;
	}

	if (cmd(e, c_fw, 2, EP_CMD_IN, b, 2, TMO_CMD))
		goto fail;
	e->fw = (uint16_t)(b[0] << 8 | b[1]);

	if (cmd(e, c_gen, 3, EP_CMD_IN, b, 1, TMO_CMD))
		goto fail;
	e->gen = (b[0] >> 4) & 7;

	if (cmd(e, c_dim, 2, EP_CMD_IN, b, 4, TMO_CMD))
		goto fail;
	e->w = (uint16_t)((b[0] + 1) & ~1);
	e->h = (uint16_t)((b[2] + 1) & ~1);

	e->bg = calloc((size_t)e->w * e->h, sizeof(*e->bg));
	if (!e->bg)
		goto fail;
	return ELAN_OK;

fail:
	elan_close(e);
	return ELAN_EIO;
}

void elan_close(struct elan *e)
{
	static const uint8_t c_stop[] = { 0x00, 0x0b }; /* led off, stop scan */

	if (e->usb) {
		cmd(e, c_stop, 2, 0, NULL, 0, TMO_CMD);
		libusb_release_interface(e->usb, 0);
		libusb_close(e->usb);
	}
	if (e->ctx)
		libusb_exit(e->ctx);
	free(e->bg);
	memset(e, 0, sizeof(*e));
}

static int run_calibration(struct elan *e)
{
	static const uint8_t c[] = { 0x40, 0x23 };
	uint8_t st;

	for (int i = 0; i < CALIB_TRIES; i++) {
		int r = cmd(e, c, 2, EP_CMD_IN, &st, 1, TMO_CMD);

		if (r)
			return r;
		if (st == 0x03)
			return ELAN_OK;
	}
	LOG("elan: calibration status 0x%02x\n", st);
	return ELAN_ERECAL;
}

int elan_calibrate(struct elan *e, int force)
{
	static const uint8_t c_mean[] = { 0x40, 0x24 };
	uint8_t b[2];
	int r;

	for (int i = 0; i < CALIB_TRIES; i++, force = 1) {
		if (force && (r = run_calibration(e)))
			return r;
		if ((r = get_frame(e, e->bg)))
			return r;
		if ((r = cmd(e, c_mean, 2, EP_CMD_IN, b, 2, TMO_CMD)))
			return r;

		unsigned dev = (unsigned)(b[0] << 8 | b[1]);
		unsigned img = mean(e->bg, e->w * e->h);
		unsigned d = dev > img ? dev - img : img - dev;

		if (dev && img && d <= CALIB_MAX_DELTA)
			return ELAN_OK;
	}
	return ELAN_ERECAL;
}

int elan_finger_off(struct elan *e)
{
	static const uint8_t c[] = { 0x40, 0x3e };
	uint8_t st;
	int r = ELAN_ERETRY;

	for (int i = 0; i < LIFT_TRIES; i++) {
		r = cmd(e, c, 2, EP_CMD_IN, &st, 1, TMO_FINGER);
		if (r == ELAN_OK && st == 0xaa)
			return ELAN_OK;
		if (r == ELAN_EIO)
			return r;
		if (r == ELAN_OK)
			r = ELAN_ERETRY;
	}
	return r;
}

int elan_capture(struct elan *e, uint16_t *img)
{
	static const uint8_t c_wait[] = { 0x40, 0x3f };
	static const uint8_t c_discard[] = { 0x9a, 0x14 };
	int n = e->w * e->h;
	uint8_t st;
	int r = cmd(e, c_wait, 2, EP_CMD_IN, &st, 1, TMO_FINGER);

	if (r == ELAN_ETIMEOUT) {
		elan_finger_off(e); /* take the sensor out of wait mode */
		return r;
	}
	if (r)
		return r;
	switch (st) {
	case 0x55: /* finger detected */
		break;
	case 0xaf: /* sensor wants recalibration */
		return ELAN_ERECAL;
	case 0xca: /* prefetched image pending */
	case 0xcc: /* "re-initialize SGX" */
		r = cmd(e, c_discard, 2, 0, NULL, 0, TMO_CMD);
		return r ? r : ELAN_ERETRY;
	default:
		LOG("elan: unknown wait result 0x%02x\n", st);
		return ELAN_EIO;
	}

	for (int i = 0;; i++) {
		if (i == FINGER_TRIES) {
			elan_finger_off(e);
			return ELAN_ERETRY;
		}
		if ((r = get_frame(e, img)))
			return r;

		/* background drifted (pixels far below it): need a new one */
		int under = 0;
		for (int k = 0; k < n; k++)
			under += e->bg[k] - img[k] > UNDER_BASE_DELTA;

		sub_bg(e, img);
		if (mean(img, n) <= FINGER_MIN_MEAN)
			continue;
		if (under * 100 > UNDER_BASE_PCT * n)
			return ELAN_ERECAL;
		return ELAN_OK;
	}
}

static void say(elan_say_fn fn, void *arg, const char *msg)
{
	if (fn)
		fn(msg, arg);
}

int elan_scan(struct elan *e, uint16_t *img, int windows, elan_say_fn fn,
	      void *arg)
{
	int r = ELAN_ETIMEOUT;

	for (int tries = 0; tries < windows + 3; tries++) {
		r = elan_capture(e, img);
		if (r == ELAN_OK || r == ELAN_EIO)
			return r;
		if (r == ELAN_ETIMEOUT) {
			if (--windows <= 0)
				return r;
		} else if (r == ELAN_ERETRY) {
			say(fn, arg, "Bad touch, lift and place your finger again");
		} else if (r == ELAN_ERECAL) {
			say(fn, arg, "Recalibrating, lift your finger");
			elan_finger_off(e);
			if ((r = elan_calibrate(e, 1)))
				return r;
			say(fn, arg, "Place your finger again");
		}
	}
	return r;
}
