/* elanfp: capture, enroll and verify fingerprints on the ELAN 04f3:0c4b. */
#include "elan.h"
#include "image.h"
#include "match.h"
#include "store.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const char *const placement[] = {
	"centre", "a bit higher (towards the tip)", "a bit lower",
	"shifted left", "shifted right", "tilted left", "tilted right",
	"the way you would for sudo",
};

static void say(const char *msg, void *arg)
{
	(void)arg;
	puts(msg);
	fflush(stdout);
}

/* Open the sensor and take a background frame. */
static int open_ready(struct elan *e)
{
	int r;

	if (elan_open(e))
		return -1;
	if (e->w != FP_W || e->h != FP_H) {
		fprintf(stderr, "unexpected frame size %ux%u\n", e->w, e->h);
		elan_close(e);
		return -1;
	}
	say("Calibrating, keep the sensor untouched...", NULL);
	if ((r = elan_calibrate(e, 0))) {
		fprintf(stderr, "calibration failed (%d)\n", r);
		elan_close(e);
		return -1;
	}
	return 0;
}

static int cmd_capture(const char *out)
{
	uint16_t img[FP_N];
	uint8_t img8[FP_N];
	struct elan e;
	int r;

	if (open_ready(&e))
		return 1;
	printf("ELAN fw 0x%04x gen %u, %ux%u\n", e.fw, e.gen, e.w, e.h);
	say("Place your finger on the sensor", NULL);
	r = elan_scan(&e, img, 6, say, NULL);
	if (r == ELAN_OK) {
		img_to_8bit(img, FP_N, img8);
		if (img_write_pgm(out, img8, FP_W, FP_H)) {
			perror(out);
			r = -1;
		} else {
			printf("Wrote %s (area %d%%), lift your finger\n", out,
			       fp_area(img));
			elan_finger_off(&e);
		}
	} else {
		fprintf(stderr, "capture failed (%d)\n", r);
	}
	elan_close(&e);
	return r ? 1 : 0;
}

static int cmd_enroll(const char *dir, const char *user, const char *finger)
{
	struct fp_tpl *t;
	struct elan e;
	char path[4096], msg[160];
	int r = 0;

	snprintf(path, sizeof(path), "%s/%s", dir, user);
	if ((mkdir(dir, 0700) && errno != EEXIST) ||
	    (mkdir(path, 0700) && errno != EEXIST)) {
		perror(path);
		return 1;
	}
	snprintf(path, sizeof(path), "%s/%s/%s.tpl", dir, user, finger);
	t = calloc(1, sizeof(*t));
	if (!t || open_ready(&e)) {
		free(t);
		return 1;
	}
	printf("Enrolling finger '%s' for %s: %d touches, use only this finger\n",
	       finger, user, FP_MAX_SAMPLES);
	while (t->n < FP_MAX_SAMPLES) {
		snprintf(msg, sizeof(msg), "Touch %d/%d: place the finger %s",
			 t->n + 1, FP_MAX_SAMPLES,
			 placement[t->n % (sizeof(placement) / sizeof(*placement))]);
		say(msg, NULL);
		if ((r = elan_scan(&e, t->raw[t->n], 3, say, NULL)))
			break;
		int area = fp_area(t->raw[t->n]);
		if (area < FP_MIN_AREA) {
			snprintf(msg, sizeof(msg),
				 "Only %d%% usable area, press flatter and retry", area);
			say(msg, NULL);
		} else {
			t->n++;
		}
		say("Lift your finger", NULL);
		elan_finger_off(&e);
	}
	elan_close(&e);
	if (r) {
		fprintf(stderr, "enrollment aborted (%d), nothing saved\n", r);
	} else if (fp_tpl_save(path, t)) {
		fprintf(stderr, "%s: %s\n", path, strerror(errno));
		r = -1;
	} else {
		printf("Enrolled %d samples into %s\n", t->n, path);
	}
	free(t);
	return r ? 1 : 0;
}

static int cmd_verify(const char *dir, const char *user)
{
	struct fp_probe *p = NULL;
	struct fp_user u;
	uint16_t img[FP_N];
	struct elan e;
	int r, score = 0;

	if (!fp_user_load(dir, user, &u)) {
		fprintf(stderr, "no fingers enrolled for %s in %s\n", user, dir);
		return 1;
	}
	if (open_ready(&e)) {
		fp_user_free(&u);
		return 1;
	}
	say("Place your finger on the sensor", NULL);
	r = elan_scan(&e, img, 3, say, NULL);
	if (r == ELAN_OK && (p = fp_probe_new(img))) {
		score = fp_user_match(&u, p);
		printf("score %d (threshold %d): %s\n", score, FP_THRESHOLD,
		       score >= FP_THRESHOLD ? "MATCH" : "no match");
		elan_finger_off(&e);
	} else {
		fprintf(stderr, "capture failed (%d)\n", r);
	}
	fp_probe_free(p);
	elan_close(&e);
	fp_user_free(&u);
	return score >= FP_THRESHOLD ? 0 : 1;
}

static int usage(void)
{
	fputs("usage: elanfp capture [out.pgm]\n"
	      "       elanfp enroll <user> [finger] [-d dir]   (default finger '1')\n"
	      "       elanfp verify <user> [-d dir]\n"
	      "templates: <dir>/<user>/<finger>.tpl, dir defaults to "
	      FP_DEFAULT_DIR "\n"
	      "remove a finger by deleting its .tpl file\n", stderr);
	return 2;
}

int main(int argc, char **argv)
{
	const char *dir = FP_DEFAULT_DIR, *args[2] = { NULL, NULL };
	int na = 0;

	if (argc < 2)
		return usage();
	for (int i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "-d") && i + 1 < argc)
			dir = argv[++i];
		else if (na < 2)
			args[na++] = argv[i];
		else
			return usage();
	}

	if (!strcmp(argv[1], "capture") && na <= 1)
		return cmd_capture(na ? args[0] : "finger.pgm");
	if (!na || !fp_valid_name(args[0]))
		return usage();
	if (!strcmp(argv[1], "verify") && na == 1)
		return cmd_verify(dir, args[0]);
	if (!strcmp(argv[1], "enroll")) {
		const char *finger = na == 2 ? args[1] : "1";

		if (!fp_valid_name(finger))
			return usage();
		return cmd_enroll(dir, args[0], finger);
	}
	return usage();
}
