/* Driver for the ELAN 04f3:0c4b match-on-host fingerprint sensor. */
#ifndef ELAN_H
#define ELAN_H

#include <stdint.h>

enum {
	ELAN_OK = 0,
	ELAN_EIO = -1,
	ELAN_ERECAL = -5,   /* background stale / sensor asks for calibration */
	ELAN_ETIMEOUT = -7, /* no finger (or finger not lifted) in time */
	ELAN_ERETRY = -8,   /* bad touch or stale prefetch, scan again */
};

struct libusb_context;
struct libusb_device_handle;

struct elan {
	struct libusb_context *ctx;
	struct libusb_device_handle *usb;
	uint16_t fw;
	uint8_t gen;
	uint16_t w, h;  /* frame size in pixels, row-major, stride w */
	uint16_t *bg;   /* background frame (no finger), w*h */
};

/* 0: no messages on stderr (used inside PAM) */
extern int elan_verbose;

typedef void (*elan_say_fn)(const char *msg, void *arg);

int elan_open(struct elan *e);
void elan_close(struct elan *e);
/* Capture a new background; force=1 runs the sensor calibration first. */
int elan_calibrate(struct elan *e, int force);
/* Wait up to ~11 s for a finger, then fill img (w*h) with frame - background. */
int elan_capture(struct elan *e, uint16_t *img);
/* Wait up to ~11 s for the finger to be lifted. */
int elan_finger_off(struct elan *e);
/*
 * elan_capture() with the retry policy: bad touches and recalibration are
 * handled here, `windows` bounds the number of ~11 s waits for a finger.
 * say() (may be NULL) receives user prompts.
 */
int elan_scan(struct elan *e, uint16_t *img, int windows, elan_say_fn say,
	      void *arg);

#endif
