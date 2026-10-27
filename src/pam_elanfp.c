/*
 * PAM auth module: accept the user if their finger matches any finger
 * enrolled with `elanfp enroll <user> [finger]`. Meant to be stacked as
 *     auth sufficient pam_elanfp.so
 * in front of the password modules, so any failure (no template, no sensor,
 * timeout, mismatch, remote session) falls through to the password prompt.
 *
 * Options: dir=<template dir> (default /var/lib/elanfp)
 */
#define _POSIX_C_SOURCE 200809L
#include "auth.h"
#include "elan.h"
#include "match.h"
#include "store.h"

#include <errno.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#define TRIES 3
#define EXPORT __attribute__((visibility("default")))

static void say(const char *msg, void *pamh)
{
	pam_info(pamh, "%s", msg);
}

static int is_remote(pam_handle_t *pamh)
{
	const void *rhost = NULL;

	if (getenv("SSH_CONNECTION") || getenv("SSH_CLIENT") || getenv("SSH_TTY"))
		return 1;
	if (pam_get_item(pamh, PAM_RHOST, &rhost) == PAM_SUCCESS && rhost &&
	    *(const char *)rhost && strcmp(rhost, "localhost"))
		return 1;
	return 0;
}

/* Runs in the child: returns 0 match, 1 no match, 2 unavailable. */
static int fingerprint(pam_handle_t *pamh, const char *user,
		       const struct fp_user *u)
{
	struct fp_auth_session session;
	enum fp_auth_open_result opened;
	int ret = 2;

	elan_verbose = 0;
	opened = fp_auth_open(&session, u);
	if (opened != FP_AUTH_OPEN_OK) {
		pam_syslog(pamh, LOG_WARNING, "%s",
			   opened == FP_AUTH_OPEN_UNAVAILABLE ?
			   "fingerprint sensor unavailable" :
			   "fingerprint sensor calibration failed");
		return 2;
	}

	for (int i = 0; i < TRIES; i++) {
		say("Place your finger on the fingerprint reader", pamh);
		int score, area;
		int r = fp_auth_scan(&session, say, pamh, &score, &area);
		if (r) {
			/* nobody touched it: quietly go on to the password */
			ret = i == 0 && r == ELAN_ETIMEOUT ? 2 : 1;
			break;
		}
		if (score >= FP_THRESHOLD) {
			pam_syslog(pamh, LOG_NOTICE, "fingerprint accepted for %s (score %d)",
				   user, score);
			ret = 0;
			break;
		}
		pam_syslog(pamh, LOG_NOTICE, "fingerprint rejected for %s (score %d)",
			   user, score);
		ret = 1;
		say(area < FP_MIN_AREA ? "Fingerprint not recognized, press flatter"
				       : "Fingerprint not recognized", pamh);
		fp_auth_finger_off(&session);
	}
	fp_auth_close(&session);
	return ret;
}

EXPORT int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
			       const char **argv)
{
	const char *dir = FP_DEFAULT_DIR, *user = NULL;
	struct fp_user u;
	pid_t pid;
	int st;

	(void)flags;
	for (int i = 0; i < argc; i++)
		if (!strncmp(argv[i], "dir=", 4))
			dir = argv[i] + 4;

	if (is_remote(pamh))
		return PAM_AUTHINFO_UNAVAIL;
	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user)
		return PAM_AUTHINFO_UNAVAIL;
	if (!fp_user_load(dir, user, &u))
		return PAM_AUTHINFO_UNAVAIL; /* not enrolled (or unusable name) */

	/*
	 * USB and matching run in a child so that no failure in this code
	 * (crash, hang on a signal, leaked state) can affect the calling
	 * program; anything but a clean verdict means "use the password".
	 */
	pid = fork();
	if (pid == 0)
		_exit(fingerprint(pamh, user, &u));
	fp_user_free(&u);
	if (pid < 0)
		return PAM_AUTHINFO_UNAVAIL;
	while (waitpid(pid, &st, 0) < 0)
		if (errno != EINTR)
			return PAM_AUTHINFO_UNAVAIL;
	if (!WIFEXITED(st)) {
		pam_syslog(pamh, LOG_ERR, "fingerprint helper died (status %d)", st);
		return PAM_AUTHINFO_UNAVAIL;
	}
	switch (WEXITSTATUS(st)) {
	case 0:
		return PAM_SUCCESS;
	case 1:
		return PAM_AUTH_ERR;
	default:
		return PAM_AUTHINFO_UNAVAIL;
	}
}

EXPORT int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
			  const char **argv)
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return PAM_SUCCESS;
}
