#include "match.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#define CW (FP_W / 2)
#define CH (FP_H / 2)

#define BORDER       3   /* pixels lost to filter edge effects */
#define ANG_MAX      30  /* coarse search: degrees either way */
#define ANG_STEP     5
#define NANG         (2 * ANG_MAX / ANG_STEP + 1)
#define REFINE_ANG   4   /* refinement: degrees around a candidate, step 2 */
#define FINE_MAX     (ANG_MAX + REFINE_ANG)
#define NFINE        (2 * FINE_MAX + 1)
#define SHIFT_MAX    (CW / 2) /* coarse shift range, half the frame */
#define REFINE_SHIFT 3   /* full resolution pixels around a candidate */
#define TOPK         4   /* coarse candidates refined per sample */
#define MIN_OVL      20  /* minimum overlap of both masks, % of the frame */

/* Ridge values are fixed point with |v| <= VMAX, so v^2 fits int16 and
 * every correlation term is an int16 dot product (SIMD multiply-add). */
#define VSCALE 32
#define VMAX   127
#define DEG    0.017453292f

/*
 * One resolution level of a frame: ridge signal v (0 outside the mask),
 * v^2, mask m (0/1) and the mask bounding box [x0,x1) x [y0,y1).
 */
struct plane {
	int w, h, x0, y0, x1, y1;
	int16_t v[FP_N], v2[FP_N], m[FP_N];
};

struct feat {
	struct plane fine, coarse;
	int area;
};

struct fp_probe {
	struct feat f;
	struct plane coarse[NANG]; /* coarse level at each coarse angle */
	struct plane fine[NFINE];  /* full resolution at -FINE_MAX..FINE_MAX deg */
};

struct cand {
	float s;
	int ang, dx, dy;
};

/* Separable box blur with edge renormalisation. */
static void box(const float *in, float *out, int r)
{
	float t[FP_N];

	for (int y = 0; y < FP_H; y++)
		for (int x = 0; x < FP_W; x++) {
			int a = x - r < 0 ? 0 : x - r;
			int b = x + r >= FP_W ? FP_W - 1 : x + r;
			float s = 0;

			for (int k = a; k <= b; k++)
				s += in[y * FP_W + k];
			t[y * FP_W + x] = s / (float)(b - a + 1);
		}
	for (int y = 0; y < FP_H; y++)
		for (int x = 0; x < FP_W; x++) {
			int a = y - r < 0 ? 0 : y - r;
			int b = y + r >= FP_H ? FP_H - 1 : y + r;
			float s = 0;

			for (int k = a; k <= b; k++)
				s += t[k * FP_W + x];
			out[y * FP_W + x] = s / (float)(b - a + 1);
		}
}

/* q-quantile of FP_N values (quickselect on a copy). */
static float percentile(const float *p, float q)
{
	float s[FP_N];
	int lo = 0, hi = FP_N - 1, k = (int)(q * (FP_N - 1));

	memcpy(s, p, sizeof(s));
	while (lo < hi) {
		float piv = s[(lo + hi) / 2];
		int i = lo, j = hi;

		while (i <= j) {
			while (s[i] < piv)
				i++;
			while (s[j] > piv)
				j--;
			if (i <= j) {
				float t = s[i];
				s[i++] = s[j];
				s[j--] = t;
			}
		}
		if (k <= j)
			hi = j;
		else if (k >= i)
			lo = i;
		else
			break;
	}
	return s[k];
}

/* Fill v2 and the bounding box from v and m. */
static void plane_finish(struct plane *p)
{
	p->x0 = p->w;
	p->y0 = p->h;
	p->x1 = p->y1 = 0;
	for (int y = 0; y < p->h; y++)
		for (int x = 0; x < p->w; x++) {
			int i = y * p->w + x;

			p->v2[i] = (int16_t)(p->v[i] * p->v[i]);
			if (!p->m[i])
				continue;
			if (x < p->x0)
				p->x0 = x;
			if (x >= p->x1)
				p->x1 = x + 1;
			if (y < p->y0)
				p->y0 = y;
			if (y >= p->y1)
				p->y1 = y + 1;
		}
	if (p->x1 <= p->x0)
		p->x0 = p->x1 = p->y0 = p->y1 = 0;
}

static void extract(const uint16_t *raw, struct feat *f)
{
	float a[FP_N], d[FP_N], t[FP_N], lo[FP_N], en[FP_N], ct[FP_N];
	struct plane *pf = &f->fine, *pc = &f->coarse;

	for (int i = 0; i < FP_N; i++)
		a[i] = raw[i];
	/* difference of (approximate) gaussians keeps the ridge frequency */
	box(a, t, 1);
	box(t, d, 1);
	box(a, t, 4);
	box(t, lo, 4);
	for (int i = 0; i < FP_N; i++) {
		d[i] -= lo[i];
		t[i] = d[i] * d[i];
	}
	box(t, en, 5); /* local ridge energy */
	box(a, ct, 5); /* local contact level */

	float pe = percentile(en, 0.95f), pc95 = percentile(ct, 0.95f);

	pf->w = FP_W;
	pf->h = FP_H;
	f->area = 0;
	for (int y = 0; y < FP_H; y++)
		for (int x = 0; x < FP_W; x++) {
			int i = y * FP_W + x;
			int m = x >= BORDER && x < FP_W - BORDER &&
				y >= BORDER && y < FP_H - BORDER &&
				ct[i] > 0.3f * pc95 && en[i] > 0.05f * pe && en[i] > 0;
			float v = m ? d[i] / sqrtf(en[i]) * VSCALE : 0;

			pf->m[i] = (int16_t)m;
			pf->v[i] = (int16_t)(v > VMAX ? VMAX : v < -VMAX ? -VMAX : v);
			f->area += m;
		}
	plane_finish(pf);

	pc->w = CW;
	pc->h = CH;
	for (int y = 0; y < CH; y++)
		for (int x = 0; x < CW; x++) {
			int i = 2 * y * FP_W + 2 * x, o = y * CW + x;
			int16_t m = pf->m[i] & pf->m[i + 1] & pf->m[i + FP_W] &
				    pf->m[i + FP_W + 1];

			pc->m[o] = m;
			pc->v[o] = m ? (int16_t)((pf->v[i] + pf->v[i + 1] +
				pf->v[i + FP_W] + pf->v[i + FP_W + 1]) / 4) : 0;
		}
	plane_finish(pc);
}

/* dst = src rotated by deg around the centre (bilinear). */
static void rotate(const struct plane *src, float deg, struct plane *dst)
{
	int w = src->w, h = src->h;
	float c = cosf(deg * DEG), s = sinf(deg * DEG);
	float cx = (float)(w - 1) / 2, cy = (float)(h - 1) / 2;

	dst->w = w;
	dst->h = h;
	for (int y = 0; y < h; y++)
		for (int x = 0; x < w; x++) {
			float dx = (float)x - cx, dy = (float)y - cy;
			float sx = c * dx + s * dy + cx, sy = -s * dx + c * dy + cy;
			int x0 = (int)floorf(sx), y0 = (int)floorf(sy);
			int o = y * w + x, i = y0 * w + x0;

			dst->v[o] = dst->m[o] = 0;
			if (x0 < 0 || y0 < 0 || x0 + 1 >= w || y0 + 1 >= h ||
			    !(src->m[i] & src->m[i + 1] & src->m[i + w] & src->m[i + w + 1]))
				continue;

			float fx = sx - (float)x0, fy = sy - (float)y0;
			const int16_t *v = src->v;

			dst->m[o] = 1;
			dst->v[o] = (int16_t)lrintf(
				(v[i] * (1 - fx) + v[i + 1] * fx) * (1 - fy) +
				(v[i + w] * (1 - fx) + v[i + w + 1] * fx) * fy);
		}
	plane_finish(dst);
}

/*
 * NCC of a(x, y) against b(x - dx, y - dy) over pixels where both masks are
 * set, or -1 if fewer than minn such pixels. v is 0 outside its mask, so
 * only the energies need the other mask. Sums fit int32: FP_N * VMAX^2.
 */
static float ncc(const struct plane *a, const struct plane *b, int dx, int dy,
		 int minn)
{
	int w = a->w;
	int x0 = a->x0 > b->x0 + dx ? a->x0 : b->x0 + dx;
	int x1 = a->x1 < b->x1 + dx ? a->x1 : b->x1 + dx;
	int y0 = a->y0 > b->y0 + dy ? a->y0 : b->y0 + dy;
	int y1 = a->y1 < b->y1 + dy ? a->y1 : b->y1 + dy;
	int32_t sab = 0, saa = 0, sbb = 0, n = 0;

	if (x1 <= x0 || y1 <= y0 || (x1 - x0) * (y1 - y0) < minn)
		return -1;
	for (int y = y0; y < y1; y++) {
		int ia = y * w, ib = (y - dy) * w - dx;
		const int16_t *va = a->v + ia, *qa = a->v2 + ia, *ma = a->m + ia;
		const int16_t *vb = b->v + ib, *qb = b->v2 + ib, *mb = b->m + ib;

		for (int x = x0; x < x1; x++) {
			sab += va[x] * vb[x];
			saa += qa[x] * mb[x];
			sbb += qb[x] * ma[x];
			n += ma[x] * mb[x];
		}
	}
	if (n < minn || saa <= 0 || sbb <= 0)
		return -1;
	return (float)sab / sqrtf((float)saa * (float)sbb);
}

/* Best NCC of the probe against one enrolment sample. */
static float match_one(const struct feat *a, const struct fp_probe *p)
{
	struct cand top[TOPK];
	float best = -1;

	for (int k = 0; k < TOPK; k++)
		top[k].s = -2;

	for (int ai = 0; ai < NANG; ai++)
		for (int dy = -SHIFT_MAX; dy <= SHIFT_MAX; dy++)
			for (int dx = -SHIFT_MAX; dx <= SHIFT_MAX; dx++) {
				float s = ncc(&a->coarse, &p->coarse[ai], dx, dy,
					      CW * CH * MIN_OVL / 100);
				int k = TOPK - 1;

				if (s <= top[k].s)
					continue;
				for (; k > 0 && top[k - 1].s < s; k--)
					top[k] = top[k - 1];
				top[k] = (struct cand){ s, ai * ANG_STEP - ANG_MAX, dx, dy };
			}

	for (int k = 0; k < TOPK && top[k].s >= 0; k++)
		for (int da = -REFINE_ANG; da <= REFINE_ANG; da += 2) {
			const struct plane *r = &p->fine[top[k].ang + da + FINE_MAX];

			for (int dy = 2 * top[k].dy - REFINE_SHIFT;
			     dy <= 2 * top[k].dy + REFINE_SHIFT; dy++)
				for (int dx = 2 * top[k].dx - REFINE_SHIFT;
				     dx <= 2 * top[k].dx + REFINE_SHIFT; dx++) {
					float s = ncc(&a->fine, r, dx, dy,
						      FP_N * MIN_OVL / 100);
					if (s > best)
						best = s;
				}
		}
	return best;
}

struct fp_probe *fp_probe_new(const uint16_t *raw)
{
	struct fp_probe *p = malloc(sizeof(*p));

	if (!p)
		return NULL;
	extract(raw, &p->f);
	for (int i = 0; i < NANG; i++)
		rotate(&p->f.coarse, (float)(i * ANG_STEP - ANG_MAX), &p->coarse[i]);
	for (int i = 0; i < NFINE; i++)
		rotate(&p->f.fine, (float)(i - FINE_MAX), &p->fine[i]);
	return p;
}

void fp_probe_free(struct fp_probe *p)
{
	free(p);
}

int fp_area(const uint16_t *raw)
{
	struct feat *f = malloc(sizeof(*f));
	int area = 0;

	if (f) {
		extract(raw, f);
		area = f->area * 100 / FP_N;
	}
	free(f);
	return area;
}

int fp_probe_area(const struct fp_probe *p)
{
	return p->f.area * 100 / FP_N;
}

int fp_match(const struct fp_probe *p, const struct fp_tpl *t, int stop)
{
	struct feat *a = malloc(sizeof(*a));
	float best = 0, second = 0;

	if (!a)
		return 0;
	for (int i = 0; i < t->n; i++) {
		extract(t->raw[i], a);
		float s = match_one(a, p);
		if (s > best) {
			second = best;
			best = s;
		} else if (s > second) {
			second = s;
		}
		if (t->n > 1 && (int)(second * 1000) >= stop)
			break;
	}
	free(a);
	return (int)((t->n == 1 ? best : second) * 1000);
}

int fp_user_match(const struct fp_user *u, const struct fp_probe *p)
{
	int best = 0;

	for (int i = 0; i < u->n && best < FP_THRESHOLD; i++) {
		int s = fp_match(p, u->f[i], FP_THRESHOLD);
		if (s > best)
			best = s;
	}
	return best;
}
