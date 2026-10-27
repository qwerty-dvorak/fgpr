#define _GNU_SOURCE
#include "uhid.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/uhid.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

/* FIDO usage page, authenticator application, 64-byte IN/OUT, no report ID. */
static const uint8_t descriptor[] = {
	0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01,
	0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00,
	0x75, 0x08, 0x95, 0x40, 0x81, 0x02,
	0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00,
	0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xc0
};

static int event_write(int fd, const struct uhid_event *e)
{
	ssize_t n;

	do {
		n = write(fd, e, sizeof(*e));
	} while (n < 0 && errno == EINTR);
	return n == sizeof(*e) ? 0 : -1;
}

int fido_uhid_open(void)
{
	struct uhid_event e = { .type = UHID_CREATE2 };
	int fd = open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);

	if (fd < 0)
		return -1;
	memcpy(e.u.create2.name, "elanfp FIDO2", sizeof("elanfp FIDO2"));
	memcpy(e.u.create2.phys, "elanfp/fido", sizeof("elanfp/fido"));
	memcpy(e.u.create2.uniq, "elanfp-local", sizeof("elanfp-local"));
	e.u.create2.rd_size = sizeof(descriptor);
	e.u.create2.bus = BUS_USB;
	/* Local virtual identifier, not an assigned public USB product ID. */
	e.u.create2.vendor = 0x1209;
	e.u.create2.product = 0xef01;
	e.u.create2.version = 1;
	memcpy(e.u.create2.rd_data, descriptor, sizeof(descriptor));
	if (event_write(fd, &e)) {
		close(fd);
		return -1;
	}
	return fd;
}

int fido_uhid_recv(int fd, uint8_t report[64])
{
	struct uhid_event e = { 0 }, reply = { 0 };
	ssize_t n = read(fd, &e, sizeof(e));

	if (n < 0 && (errno == EAGAIN || errno == EINTR))
		return 0;
	if (n < (ssize_t)sizeof(e.type))
		return -1;
	switch (e.type) {
	case UHID_OUTPUT: {
		size_t size = e.u.output.size;
		const uint8_t *p = e.u.output.data;

		if (e.u.output.rtype != UHID_OUTPUT_REPORT ||
		    n < (ssize_t)(offsetof(struct uhid_event, u.output.rtype) + 1))
			return 0;
		if (size == 65 && p[0] == 0) {
			p++;
			size--;
		}
		if (size != 64)
			return 0;
		memcpy(report, p, 64);
		return 1;
	}
	case UHID_GET_REPORT:
		reply.type = UHID_GET_REPORT_REPLY;
		reply.u.get_report_reply.id = e.u.get_report.id;
		reply.u.get_report_reply.err = EIO;
		return event_write(fd, &reply);
	case UHID_SET_REPORT:
		reply.type = UHID_SET_REPORT_REPLY;
		reply.u.set_report_reply.id = e.u.set_report.id;
		reply.u.set_report_reply.err = EIO;
		return event_write(fd, &reply);
	default:
		return 0;
	}
}

int fido_uhid_send(int fd, const uint8_t report[64])
{
	struct uhid_event e = { .type = UHID_INPUT2 };

	e.u.input2.size = 64;
	memcpy(e.u.input2.data, report, 64);
	return event_write(fd, &e);
}

void fido_uhid_close(int fd)
{
	/* Closing the last fd destroys the virtual device, including hidraw. */
	close(fd);
}
