/* Shared sensor session for PAM and FIDO fingerprint verification. */
#ifndef ELANFP_AUTH_H
#define ELANFP_AUTH_H

#include "elan.h"
#include "match.h"

enum fp_auth_open_result {
	FP_AUTH_OPEN_OK,
	FP_AUTH_OPEN_UNAVAILABLE,
	FP_AUTH_OPEN_CALIBRATION_FAILED
};

struct fp_auth_session {
	struct elan sensor;
	const struct fp_user *user;
};

/* On failure, any acquired sensor resources are released. */
enum fp_auth_open_result fp_auth_open(struct fp_auth_session *session,
				     const struct fp_user *user);
/* One existing elan_scan window. Returns ELAN_*; score/area set on success. */
int fp_auth_scan(struct fp_auth_session *session, elan_say_fn say, void *arg,
		 int *score, int *area);
int fp_auth_finger_off(struct fp_auth_session *session);
void fp_auth_close(struct fp_auth_session *session);

#endif
