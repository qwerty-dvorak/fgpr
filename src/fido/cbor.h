#ifndef FGPR_FIDO_CBOR_H
#define FGPR_FIDO_CBOR_H

#include <stddef.h>
#include <stdint.h>

#define CBOR_NODES 4096
struct cbor_item {
    const unsigned char *data;
    size_t len;
    uint64_t value;
    unsigned end;
    unsigned char type;
};
struct cbor_doc {
    struct cbor_item items[CBOR_NODES];
    unsigned count;
};
/* Exactly one definite-length item; accepts key order permutations, not duplicates. */
int cbor_parse(struct cbor_doc *d, const unsigned char *data, size_t len);
const struct cbor_item *cbor_int(const struct cbor_doc *d, const struct cbor_item *map, uint64_t key);
const struct cbor_item *cbor_text(const struct cbor_doc *d, const struct cbor_item *map, const char *key);
int cbor_is_text(const struct cbor_item *v, const char *s);
struct cbor_writer {
    unsigned char *data;
    size_t len, cap;
    int error;
};
void cbor_head(struct cbor_writer *w, unsigned type, uint64_t n);
void cbor_bytes(struct cbor_writer *w, const void *data, size_t len);
void cbor_string(struct cbor_writer *w, const char *data, size_t len);
void cbor_cstr(struct cbor_writer *w, const char *s);
void cbor_bool(struct cbor_writer *w, int value);
void cbor_raw(struct cbor_writer *w, const void *data, size_t len);

#endif
