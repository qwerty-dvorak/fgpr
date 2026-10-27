#ifndef ELANFP_UHID_H
#define ELANFP_UHID_H

#include <stdint.h>

/* One 64-byte FIDO report per send/receive. Receive returns 1 for a report,
 * 0 for a kernel lifecycle event, -1 on error. The fd is pollable. */
int fido_uhid_open(void);
int fido_uhid_recv(int fd, uint8_t report[64]);
int fido_uhid_send(int fd, const uint8_t report[64]);
void fido_uhid_close(int fd);

#endif
