/*
 * Fingerprint matcher for the 80x80 ELAN frames.
 *
 * Frames are band-pass filtered and contrast normalised into a ridge signal
 * plus a mask of usable finger area. Two frames are compared by masked
 * normalised cross-correlation (NCC) over rotations and shifts: a coarse
 * search at half resolution, then refinement of the best candidates at full
 * resolution. A finger template is a set of enrolment frames; its score is
 * the second best sample score, because a genuine finger correlates with
 * several samples while a chance alignment of another finger rarely does.
 */
#ifndef MATCH_H
#define MATCH_H

#include <stdint.h>

#define FP_W 80
#define FP_H 80
#define FP_N (FP_W * FP_H)
#define FP_MAX_SAMPLES 16
#define FP_MAX_FINGERS 10

/*
 * Accept threshold (0..1000). Measured on this sensor with 12-sample
 * templates: genuine >= 729, other fingers <= 602.
 */
#define FP_THRESHOLD 680
/* minimum usable finger area of an enrolment frame, percent */
#define FP_MIN_AREA 40

struct fp_tpl {
	int n;
	uint16_t raw[FP_MAX_SAMPLES][FP_N]; /* background-subtracted frames */
};

struct fp_user {
	int n;
	struct fp_tpl *f[FP_MAX_FINGERS];
};

/* Percentage of the frame covered by usable ridge area. */
int fp_area(const uint16_t *raw);

/* A frame prepared for matching (features and rotations), reusable. */
struct fp_probe;

struct fp_probe *fp_probe_new(const uint16_t *raw);
void fp_probe_free(struct fp_probe *p);
int fp_probe_area(const struct fp_probe *p);

/* Score 0..1000 against one finger; stops early with a score >= stop. */
int fp_match(const struct fp_probe *p, const struct fp_tpl *t, int stop);
/* Best score over all of the user's fingers, stopping at FP_THRESHOLD. */
int fp_user_match(const struct fp_user *u, const struct fp_probe *p);

#endif
