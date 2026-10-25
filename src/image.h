/* Helpers to turn sensor frames into viewable images. */
#ifndef IMAGE_H
#define IMAGE_H

#include <stdint.h>

/* Stretch the 1st..99th percentile of img to 0..255, ridges dark. */
void img_to_8bit(const uint16_t *img, int n, uint8_t *out);
/* Write an 8-bit greyscale binary PGM. */
int img_write_pgm(const char *path, const uint8_t *p, int w, int h);

#endif
