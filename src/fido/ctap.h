#ifndef FGPR_FIDO_CTAP_H
#define FGPR_FIDO_CTAP_H

#include <stddef.h>

#define CTAP_MAX_MSG 4096
struct ctap;
/* Return CTAP status: 0 verified, 0x27 denied, 0x2f timeout, 0x2d cancelled. */
typedef int (*ctap_verify_fn)(void *arg);
struct ctap *ctap_new(const char *credential_dir, ctap_verify_fn verify, void *arg);
void ctap_free(struct ctap *c);
/* First input/output byte is CTAP command/status. Single-threaded, serialized use.
 * Always returns at least one byte if out and outcap are nonzero. */
size_t ctap_request(struct ctap *c, const unsigned char *in, size_t inlen,
    unsigned char *out, size_t outcap);

#endif
