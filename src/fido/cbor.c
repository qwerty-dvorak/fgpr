#include "cbor.h"

#include <string.h>

static int utf8(const unsigned char *p, size_t n)
{
    size_t i = 0;
    while (i < n) {
        unsigned c = p[i++], v, need, min;
        if (c < 0x80) continue;
        if (c >= 0xc2 && c <= 0xdf) { v = c & 31; need = 1; min = 0x80; }
        else if (c >= 0xe0 && c <= 0xef) { v = c & 15; need = 2; min = 0x800; }
        else if (c >= 0xf0 && c <= 0xf4) { v = c & 7; need = 3; min = 0x10000; }
        else return 0;
        if (need > n - i) return 0;
        while (need--) {
            c = p[i++];
            if ((c & 0xc0) != 0x80) return 0;
            v = (v << 6) | (c & 63);
        }
        if (v < min || v > 0x10ffff || (v >= 0xd800 && v <= 0xdfff)) return 0;
    }
    return 1;
}

struct parser { struct cbor_doc *d; const unsigned char *p, *end; };

static int item(struct parser *p, unsigned depth)
{
    if (p->p == p->end) return 0x12;
    if (p->d->count == CBOR_NODES) return 0x15;
    unsigned index = p->d->count++;
    struct cbor_item *v = &p->d->items[index];
    unsigned b = *p->p++, ai = b & 31, type = b >> 5;
    uint64_t n = 0;
    if (type == 6 || ai == 31 || ai == 28 || ai == 29 || ai == 30) return 0x12;
    if (ai < 24) n = ai;
    else {
        unsigned bytes = 1u << (ai - 24);
        if ((size_t)(p->end - p->p) < bytes) return 0x12;
        for (unsigned i = 0; i < bytes; ++i) n = (n << 8) | *p->p++;
        if (type != 7 && ((bytes == 1 && n < 24) || (bytes == 2 && n <= 255) ||
            (bytes == 4 && n <= 65535) || (bytes == 8 && n <= UINT32_MAX))) return 0x12;
        if (type == 7 && ai == 24 && n < 32) return 0x12;
    }
    v->type = (unsigned char)type;
    v->value = n;
    v->data = p->p;
    v->len = type == 7 && ai >= 24 ? (size_t)1u << (ai - 24) : 0;
    if (type == 2 || type == 3) {
        if (n > (uint64_t)(p->end - p->p)) return 0x12;
        v->len = (size_t)n;
        if (type == 3 && !utf8(p->p, v->len)) return 0x12;
        p->p += v->len;
    } else if (type == 4 || type == 5) {
        if (depth == 4 || n > CBOR_NODES / (type == 5 ? 2u : 1u)) return 0x15;
        v->len = (size_t)n;
        /* Firefox serializes some options in insertion order (uv, then up).
         * Accept map-key permutations, but never ambiguous duplicate keys. */
        for (uint64_t i = 0; i < n; ++i) {
            /* Entries are stored as key subtree followed by value subtree. */
            unsigned key = p->d->count;
            int err = item(p, depth + 1);
            if (err) return err;
            if (type == 5) {
                unsigned kt = p->d->items[key].type;
                if (kt == 4 || kt == 5) return 0x12;
                for (unsigned old = index + 1; old < key;
                     old = p->d->items[p->d->items[old].end].end) {
                    const struct cbor_item *a = &p->d->items[old];
                    const struct cbor_item *b = &p->d->items[key];
                    if (a->type == b->type && a->value == b->value &&
                        a->len == b->len &&
                        ((kt != 2 && kt != 3) || !memcmp(a->data, b->data, a->len)))
                        return 0x12;
                }
                err = item(p, depth + 1);
                if (err) return err;
            }
        }
    }
    v->end = p->d->count;
    return 0;
}

int cbor_parse(struct cbor_doc *d, const unsigned char *data, size_t len)
{
    d->count = 0;
    if (!data || !len) return 0x12;
    struct parser p = { d, data, data + len };
    int err = item(&p, 0);
    return err ? err : p.p == p.end ? 0 : 0x12;
}

int cbor_is_text(const struct cbor_item *v, const char *s)
{
    return v && v->type == 3 && v->len == strlen(s) && !memcmp(v->data, s, v->len);
}

static const struct cbor_item *lookup(const struct cbor_doc *d,
    const struct cbor_item *map, uint64_t key, const char *text)
{
    if (!map || map->type != 5) return NULL;
    unsigned i = (unsigned)(map - d->items) + 1;
    for (size_t n = 0; n < map->len; ++n) {
        const struct cbor_item *k = &d->items[i];
        const struct cbor_item *v = &d->items[k->end];
        if (text ? cbor_is_text(k, text) : k->type == 0 && k->value == key) return v;
        i = v->end;
    }
    return NULL;
}

const struct cbor_item *cbor_int(const struct cbor_doc *d, const struct cbor_item *m, uint64_t key)
{ return lookup(d, m, key, NULL); }
const struct cbor_item *cbor_text(const struct cbor_doc *d, const struct cbor_item *m, const char *key)
{ return lookup(d, m, 0, key); }

void cbor_raw(struct cbor_writer *w, const void *data, size_t len)
{
    if (w->error) return;
    if (len > w->cap - w->len) { w->error = 1; return; }
    if (len) memcpy(w->data + w->len, data, len);
    w->len += len;
}

void cbor_head(struct cbor_writer *w, unsigned type, uint64_t n)
{
    unsigned char b[9];
    unsigned bytes = n < 24 ? 0 : n <= UINT8_MAX ? 1 : n <= UINT16_MAX ? 2 : n <= UINT32_MAX ? 4 : 8;
    b[0] = (unsigned char)((type << 5) | (bytes == 0 ? n : bytes == 1 ? 24 : bytes == 2 ? 25 : bytes == 4 ? 26 : 27));
    for (unsigned i = 0; i < bytes; ++i) b[bytes - i] = (unsigned char)(n >> (8 * i));
    cbor_raw(w, b, bytes + 1);
}
void cbor_bytes(struct cbor_writer *w, const void *data, size_t len)
{ cbor_head(w, 2, len); cbor_raw(w, data, len); }
void cbor_string(struct cbor_writer *w, const char *data, size_t len)
{ cbor_head(w, 3, len); cbor_raw(w, data, len); }
void cbor_cstr(struct cbor_writer *w, const char *s)
{ cbor_string(w, s, strlen(s)); }
void cbor_bool(struct cbor_writer *w, int value)
{ cbor_head(w, 7, value ? 21 : 20); }
