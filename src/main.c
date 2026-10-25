/* elanfp: capture fingerprint images from the ELAN 04f3:0c4b. */
#include "elan.h"
#include "image.h"

#include <stdio.h>
#include <stdlib.h>

static void say(const char *msg, void *arg)
{
	(void)arg;
	puts(msg);
	fflush(stdout);
}

int main(int argc, char **argv)
{
	const char *out = argc > 1 ? argv[1] : "finger.pgm";
	uint16_t *img = NULL;
	uint8_t *img8 = NULL;
	struct elan e;
	int r = -1;

	if (elan_open(&e))
		return 1;
	printf("ELAN fw 0x%04x gen %u, %ux%u\n", e.fw, e.gen, e.w, e.h);
	img = malloc((size_t)e.w * e.h * sizeof(*img));
	img8 = malloc((size_t)e.w * e.h);
	if (!img || !img8)
		goto out;

	say("Calibrating, keep the sensor untouched...", NULL);
	if ((r = elan_calibrate(&e, 0))) {
		fprintf(stderr, "calibration failed (%d)\n", r);
		goto out;
	}
	say("Place your finger on the sensor", NULL);
	if ((r = elan_scan(&e, img, 6, say, NULL))) {
		fprintf(stderr, "capture failed (%d)\n", r);
		goto out;
	}
	img_to_8bit(img, e.w * e.h, img8);
	if ((r = img_write_pgm(out, img8, e.w, e.h))) {
		perror(out);
		goto out;
	}
	printf("Wrote %s, lift your finger\n", out);
	elan_finger_off(&e);
out:
	free(img);
	free(img8);
	elan_close(&e);
	return r ? 1 : 0;
}
