#ifndef ELANFP_FIDO_HID_H
#define ELANFP_FIDO_HID_H

#include <signal.h>

/* Serve CTAPHID until stop is set or transport fails. The caller owns fd. */
int fido_hid_run(int fd, const char *user, const char *template_dir,
		 const char *credential_dir, volatile sig_atomic_t *stop);

#endif
