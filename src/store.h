/*
 * Enrolled finger storage: one file per finger at <dir>/<user>/<finger>.tpl
 * holding the raw (background subtracted) enrolment frames, root-only.
 *
 * File format (native endian): "ELANFP1\n", u16 width, u16 height,
 * u32 sample count, then count * width * height u16 pixels.
 */
#ifndef STORE_H
#define STORE_H

#include "match.h"

#define FP_DEFAULT_DIR "/var/lib/elanfp"

/* User and finger names become path components: [A-Za-z0-9._-], no leading . or - */
int fp_valid_name(const char *s);

int fp_tpl_load(const char *path, struct fp_tpl *t);
/* Atomic replace, mode 0600. */
int fp_tpl_save(const char *path, const struct fp_tpl *t);

/* Load every finger of user; returns the number loaded (0 = not enrolled). */
int fp_user_load(const char *dir, const char *user, struct fp_user *u);
void fp_user_free(struct fp_user *u);

#endif
