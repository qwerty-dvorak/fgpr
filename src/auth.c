#include "auth.h"

#include <stdint.h>

enum fp_auth_open_result fp_auth_open(struct fp_auth_session *session,
				     const struct fp_user *user)
{
	session->user = user;
	if (elan_open(&session->sensor))
		return FP_AUTH_OPEN_UNAVAILABLE;
	if (session->sensor.w != FP_W || session->sensor.h != FP_H ||
	    elan_calibrate(&session->sensor, 0)) {
		elan_close(&session->sensor);
		return FP_AUTH_OPEN_CALIBRATION_FAILED;
	}
	return FP_AUTH_OPEN_OK;
}

int fp_auth_scan(struct fp_auth_session *session, elan_say_fn say, void *arg,
		 int *score, int *area)
{
	uint16_t img[FP_N];
	struct fp_probe *probe;
	int r = elan_scan(&session->sensor, img, 1, say, arg);

	if (r)
		return r;
	probe = fp_probe_new(img);
	if (!probe)
		return ELAN_EIO;
	*score = fp_user_match(session->user, probe);
	*area = fp_probe_area(probe);
	fp_probe_free(probe);
	return ELAN_OK;
}

int fp_auth_finger_off(struct fp_auth_session *session)
{
	return elan_finger_off(&session->sensor);
}

void fp_auth_close(struct fp_auth_session *session)
{
	elan_close(&session->sensor);
}
