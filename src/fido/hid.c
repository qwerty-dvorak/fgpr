#define _POSIX_C_SOURCE 200809L
#include "hid.h"
#include "auth.h"
#include "uhid.h"
#include "ctap.h"
#include "elan.h"
#include "match.h"
#include "store.h"

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define HID_PING      0x81
#define HID_INIT      0x86
#define HID_CBOR      0x90
#define HID_CANCEL    0x91
#define HID_KEEPALIVE 0xbb
#define HID_ERROR     0xbf
#define BROADCAST     UINT32_MAX
#define MAX_CHANNELS  32
#define RX_TIMEOUT_MS 3000
#define UV_TIMEOUT_MS 45000

struct server {
	int fd, io_error, resynced;
	const char *user, *template_dir;
	volatile sig_atomic_t *stop;
	uint32_t channels[MAX_CHANNELS], next_channel, active, ctap_channel;
	unsigned nchannels;
	struct ctap *ctap;
};

static int64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static uint32_t get_cid(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | p[3];
}

static void put_cid(uint8_t *p, uint32_t id)
{
	p[0] = (uint8_t)(id >> 24);
	p[1] = (uint8_t)(id >> 16);
	p[2] = (uint8_t)(id >> 8);
	p[3] = (uint8_t)id;
}

static void send_message(struct server *s, uint32_t cid, uint8_t cmd,
			 const uint8_t *data, size_t len)
{
	uint8_t report[64] = { 0 };
	size_t offset = len < 57 ? len : 57;

	put_cid(report, cid);
	report[4] = cmd;
	report[5] = (uint8_t)(len >> 8);
	report[6] = (uint8_t)len;
	if (offset)
		memcpy(report + 7, data, offset);
	if (fido_uhid_send(s->fd, report))
		s->io_error = 1;
	for (unsigned seq = 0; offset < len && !s->io_error; seq++) {
		size_t n = len - offset < 59 ? len - offset : 59;

		memset(report + 4, 0, 60);
		report[4] = (uint8_t)seq;
		memcpy(report + 5, data + offset, n);
		offset += n;
		if (fido_uhid_send(s->fd, report))
			s->io_error = 1;
	}
}

static void send_error(struct server *s, uint32_t cid, uint8_t error)
{
	send_message(s, cid, HID_ERROR, &error, 1);
}

static int known_channel(const struct server *s, uint32_t cid)
{
	for (unsigned i = 0; i < s->nchannels; i++)
		if (s->channels[i] == cid)
			return 1;
	return 0;
}

static void clear_continuation(struct server *s)
{
	static const uint8_t invalid = 0;
	uint8_t status;

	ctap_request(s->ctap, &invalid, 1, &status, 1);
	s->ctap_channel = 0;
}

static int init_channel(struct server *s, const uint8_t *report)
{
	uint32_t cid = get_cid(report), assigned = cid;
	uint8_t reply[17] = { 0 };

	if (report[5] != 0 || report[6] != 8) {
		send_error(s, cid, 0x03); /* INVALID_LEN */
		return 0;
	}
	if (cid == BROADCAST) {
		assigned = ++s->next_channel;
		/* Bounded allocation: evict the oldest slot if many clients probe. */
		s->channels[(assigned - 1) % MAX_CHANNELS] = assigned;
		if (s->nchannels < MAX_CHANNELS)
			s->nchannels++;
	} else if (!known_channel(s, cid)) {
		send_error(s, cid, 0x0b); /* INVALID_CHANNEL */
		return 0;
	}
	memcpy(reply, report + 7, 8);
	put_cid(reply + 8, assigned);
	reply[12] = 2; /* CTAPHID protocol version */
	reply[13] = 1; /* device version 1.0.0 */
	reply[16] = 0x0c; /* CBOR supported; CTAP1 MSG not supported */
	send_message(s, cid, HID_INIT, reply, sizeof(reply));
	return 1;
}

/* Real fingerprint comparison. No touch-only or password-based success. */
static int fingerprint(const struct fp_user *u)
{
	struct fp_auth_session session;
	int result = 2;

	elan_verbose = 0;
	if (fp_auth_open(&session, u) != FP_AUTH_OPEN_OK)
		return result;
	for (int i = 0; i < 3; i++) {
		int score, area;
		int r = fp_auth_scan(&session, NULL, NULL, &score, &area);

		if (r)
			break;
		if (score >= FP_THRESHOLD) {
			result = 0;
			break;
		}
		result = 1;
		if (i < 2 && fp_auth_finger_off(&session))
			break;
	}
	fp_auth_close(&session);
	return result;
}

/* Keep HID responsive while the sensor worker blocks. SIGTERM/SIGINT are
 * handled by the server, not USB code: kill/reap then STOP turns the LED off. */
static int verify_user(void *arg)
{
	struct server *s = arg;
	struct fp_user u;
	int status, result = 0x2f; /* USER_ACTION_TIMEOUT */
	int64_t deadline = now_ms() + UV_TIMEOUT_MS;
	pid_t child;

	if (!fp_user_load(s->template_dir, s->user, &u)) {
		fprintf(stderr, "elanfp-fido: no fingerprints enrolled for %s\n", s->user);
		return 0x27; /* OPERATION_DENIED */
	}
	child = fork();
	if (child == 0) {
		signal(SIGINT, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		close(s->fd);
		_exit(fingerprint(&u));
	}
	fp_user_free(&u);
	if (child < 0)
		return 0x27;
	while (!*s->stop && !s->io_error && now_ms() < deadline) {
		struct pollfd pfd = { .fd = s->fd, .events = POLLIN };
		uint8_t report[64], needed = 2;
		pid_t done = waitpid(child, &status, WNOHANG);

		if (done == child) {
			if (!WIFEXITED(status)) {
				elan_cancel_scan();
				return 0x27;
			}
			return WEXITSTATUS(status) == 0 ? 0 :
			       WEXITSTATUS(status) == 1 ? 0x27 : 0x2f;
		}
		if (done < 0 && errno != EINTR)
			break;
		send_message(s, s->active, HID_KEEPALIVE, &needed, 1);
		int n = poll(&pfd, 1, 100);
		if (n < 0 && errno != EINTR)
			break;
		if (n <= 0)
			continue;
		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
			break;
		n = fido_uhid_recv(s->fd, report);
		if (n < 0) {
			s->io_error = 1;
			break;
		}
		if (n == 0)
			continue;
		uint32_t cid = get_cid(report);
		if (cid == s->active && report[4] == HID_CANCEL &&
		    report[5] == 0 && report[6] == 0) {
			result = 0x2d; /* KEEPALIVE_CANCEL */
			break;
		}
		if (cid == s->active && report[4] == HID_INIT) {
			if (init_channel(s, report)) {
				s->resynced = 1;
				result = 0x2d;
				break;
			}
			continue;
		}
		send_error(s, cid, 0x06); /* CHANNEL_BUSY */
	}
	kill(child, SIGKILL);
	while (waitpid(child, &status, 0) < 0 && errno == EINTR)
		;
	elan_cancel_scan();
	return result;
}

int fido_hid_run(int fd, const char *user, const char *template_dir,
		 const char *credential_dir, volatile sig_atomic_t *stop)
{
	struct server s = { .fd = fd, .user = user,
		.template_dir = template_dir, .stop = stop };
	uint8_t in[CTAP_MAX_MSG], out[CTAP_MAX_MSG], report[64], command = 0;
	size_t total = 0, received = 0;
	unsigned seq = 0;
	int64_t deadline = 0;

	s.ctap = ctap_new(credential_dir, verify_user, &s);
	if (!s.ctap)
		return -1;
	while (!*stop && !s.io_error) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		int n = poll(&pfd, 1, 100);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (s.active && now_ms() > deadline) {
			send_error(&s, s.active, 0x05); /* MSG_TIMEOUT */
			s.active = 0;
		}
		if (!n)
			continue;
		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			s.io_error = 1;
			break;
		}
		n = fido_uhid_recv(fd, report);
		if (n < 0) {
			s.io_error = 1;
			break;
		}
		if (!n)
			continue;
		uint32_t cid = get_cid(report);
		if (!cid || (cid == BROADCAST && report[4] != HID_INIT)) {
			send_error(&s, cid, 0x0b);
			continue;
		}
		if (report[4] == HID_INIT && (!s.active || s.active == cid)) {
			if (init_channel(&s, report)) {
				clear_continuation(&s);
				s.active = 0;
			}
			continue;
		}
		if (!known_channel(&s, cid)) {
			send_error(&s, cid, 0x0b);
			continue;
		}
		if (s.active && s.active != cid) {
			send_error(&s, cid, 0x06);
			continue;
		}
		if (report[4] == HID_CANCEL) {
			clear_continuation(&s);
			s.active = 0;
			continue;
		}
		if (report[4] & 0x80) {
			if (s.active) {
				send_error(&s, cid, 0x04); /* INVALID_SEQ */
				s.active = 0;
				continue;
			}
			command = report[4];
			total = (size_t)report[5] << 8 | report[6];
			if (total > sizeof(in)) {
				send_error(&s, cid, 0x03);
				continue;
			}
			s.active = cid;
			received = total < 57 ? total : 57;
			seq = 0;
			memcpy(in, report + 7, received);
		} else {
			if (!s.active)
				continue; /* Ignore stray continuation reports. */
			if (report[4] != seq++) {
				send_error(&s, cid, 0x04);
				s.active = 0;
				continue;
			}
			size_t part = total - received < 59 ? total - received : 59;
			memcpy(in + received, report + 5, part);
			received += part;
		}
		deadline = now_ms() + RX_TIMEOUT_MS;
		if (received != total)
			continue;
		if (command == HID_CBOR) {
			if (s.ctap_channel != cid)
				clear_continuation(&s);
			s.ctap_channel = cid;
			s.resynced = 0;
			size_t len = ctap_request(s.ctap, in, total, out, sizeof(out));
			if (!s.resynced && !*stop)
				send_message(&s, cid, command, out, len);
			if (s.resynced)
				clear_continuation(&s);
		} else if (command == HID_PING) {
			send_message(&s, cid, command, in, total);
		} else {
			send_error(&s, cid, 0x01); /* INVALID_CMD */
		}
		s.active = 0;
	}
	ctap_free(s.ctap);
	return s.io_error ? -1 : 0;
}
