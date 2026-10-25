#include "image.h"

#include <stdio.h>
#include <string.h>

void img_to_8bit(const uint16_t *img, int n, uint8_t *out)
{
	unsigned hist[65536] = { 0 }; /* 256 KiB of stack, used once per image */
	unsigned lo = 0, hi = 65535, acc = 0;

	for (int i = 0; i < n; i++)
		hist[img[i]]++;
	while (lo < 65535 && (acc += hist[lo]) <= (unsigned)n / 100)
		lo++;
	for (acc = 0; hi > lo && (acc += hist[hi]) <= (unsigned)n / 100;)
		hi--;
	if (hi <= lo)
		hi = lo + 1;
	for (int i = 0; i < n; i++) {
		unsigned v = img[i] < lo ? 0 : img[i] > hi ? 255 :
			(img[i] - lo) * 255 / (hi - lo);
		out[i] = (uint8_t)(255 - v); /* finger contact is bright: invert */
	}
}

int img_write_pgm(const char *path, const uint8_t *p, int w, int h)
{
	FILE *f = fopen(path, "wb");
	size_t n;

	if (!f)
		return -1;
	fprintf(f, "P5\n%d %d\n255\n", w, h);
	n = fwrite(p, 1, (size_t)w * h, f);
	return (fclose(f) || n != (size_t)w * h) ? -1 : 0;
}
