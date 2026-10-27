#define _POSIX_C_SOURCE 200809L
#include "hid.h"
#include "uhid.h"
#include "store.h"

#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static volatile sig_atomic_t stopping;

static void stop(int sig)
{
	(void)sig;
	stopping = 1;
}

int main(int argc, char **argv)
{
	const char *templates = FP_DEFAULT_DIR;
	const char *credentials = "/var/lib/elanfp-fido";
	struct sigaction sa = { .sa_handler = stop };
	struct fp_user u;
	int fd, r;

	if (argc < 2 || argc > 4) {
		fprintf(stderr, "usage: elanfp-fido <unix-user> [credential-dir [template-dir]]\n");
		return 2;
	}
	if (!fp_valid_name(argv[1]) || !getpwnam(argv[1])) {
		fprintf(stderr, "elanfp-fido: invalid Unix user\n");
		return 2;
	}
	if (argc > 2)
		credentials = argv[2];
	if (argc > 3)
		templates = argv[3];
	if (!fp_user_load(templates, argv[1], &u)) {
		fprintf(stderr, "elanfp-fido: enroll a finger first: sudo elanfp enroll %s\n",
			argv[1]);
		return 1;
	}
	fp_user_free(&u);
	umask(0077);
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	fd = fido_uhid_open();
	if (fd < 0) {
		fprintf(stderr, "elanfp-fido: /dev/uhid: %s (root and CONFIG_UHID required)\n",
			strerror(errno));
		return 1;
	}
	fprintf(stderr, "elanfp-fido: serving fingerprints for %s; software FIDO2 key\n",
		argv[1]);
	r = fido_hid_run(fd, argv[1], templates, credentials, &stopping);
	if (r)
		fprintf(stderr, "elanfp-fido: transport or credential store failed: %s\n",
			strerror(errno));
	fido_uhid_close(fd);
	return r ? 1 : 0;
}
