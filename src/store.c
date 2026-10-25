#define _POSIX_C_SOURCE 200809L
#include "store.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAGIC     "ELANFP1\n"
#define MAGIC_LEN 8

int fp_valid_name(const char *s)
{
	if (!s || !*s || *s == '.' || *s == '-' || strlen(s) > 64)
		return 0;
	for (; *s; s++)
		if (!(*s >= 'a' && *s <= 'z') && !(*s >= 'A' && *s <= 'Z') &&
		    !(*s >= '0' && *s <= '9') && !strchr("._-", *s))
			return 0;
	return 1;
}

int fp_tpl_load(const char *path, struct fp_tpl *t)
{
	FILE *f = fopen(path, "rb");
	char m[MAGIC_LEN];
	uint16_t wh[2];
	uint32_t n;
	int ok;

	if (!f)
		return -1;
	ok = fread(m, MAGIC_LEN, 1, f) == 1 && !memcmp(m, MAGIC, MAGIC_LEN) &&
	     fread(wh, sizeof(wh), 1, f) == 1 && wh[0] == FP_W && wh[1] == FP_H &&
	     fread(&n, sizeof(n), 1, f) == 1 && n > 0 && n <= FP_MAX_SAMPLES &&
	     fread(t->raw, sizeof(t->raw[0]), n, f) == n;
	fclose(f);
	t->n = ok ? (int)n : 0;
	return ok ? 0 : -1;
}

int fp_tpl_save(const char *path, const struct fp_tpl *t)
{
	char tmp[4096];
	uint16_t wh[2] = { FP_W, FP_H };
	uint32_t n = (uint32_t)t->n;
	FILE *f;
	int fd, ok;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
		return -1;
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	f = fdopen(fd, "wb");
	if (!f) {
		close(fd);
		unlink(tmp);
		return -1;
	}
	ok = fwrite(MAGIC, MAGIC_LEN, 1, f) == 1 &&
	     fwrite(wh, sizeof(wh), 1, f) == 1 &&
	     fwrite(&n, sizeof(n), 1, f) == 1 &&
	     fwrite(t->raw, sizeof(t->raw[0]), n, f) == n &&
	     fflush(f) == 0 && fsync(fd) == 0;
	ok = (fclose(f) == 0) && ok;
	if (!ok || rename(tmp, path)) {
		unlink(tmp);
		return -1;
	}
	return 0;
}

int fp_user_load(const char *dir, const char *user, struct fp_user *u)
{
	char path[4096];
	struct dirent *de;
	DIR *d;

	u->n = 0;
	if (!fp_valid_name(user) ||
	    snprintf(path, sizeof(path), "%s/%s", dir, user) >= (int)sizeof(path))
		return 0;
	d = opendir(path);
	if (!d)
		return 0;
	while ((de = readdir(d)) && u->n < FP_MAX_FINGERS) {
		size_t l = strlen(de->d_name);
		struct fp_tpl *t;

		if (de->d_name[0] == '.' || l < 5 || strcmp(de->d_name + l - 4, ".tpl"))
			continue;
		if (snprintf(path, sizeof(path), "%s/%s/%s", dir, user, de->d_name) >=
		    (int)sizeof(path))
			continue;
		t = malloc(sizeof(*t));
		if (t && !fp_tpl_load(path, t))
			u->f[u->n++] = t;
		else
			free(t);
	}
	closedir(d);
	return u->n;
}

void fp_user_free(struct fp_user *u)
{
	for (int i = 0; i < u->n; i++)
		free(u->f[i]);
	u->n = 0;
}
