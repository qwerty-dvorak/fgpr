#ifndef FGPR_FIDO_CREDENTIAL_H
#define FGPR_FIDO_CREDENTIAL_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

#define CREDENTIAL_ID_LEN 32
#define CREDENTIAL_LIMIT 256
#define CREDENTIAL_DER_MAX 256
struct credential {
    unsigned char id[CREDENTIAL_ID_LEN], rp[32], user[64];
    char name[64], display[64];
    size_t user_len, name_len, display_len, der_len;
    unsigned char der[CREDENTIAL_DER_MAX];
    uint64_t created;
    uint32_t counter;
    int resident;
};
struct credential_store { int fd; };
int credential_store_open(struct credential_store *s, const char *path);
void credential_store_close(struct credential_store *s);
/* read: 1 found, 0 absent, -1 unsafe or corrupt state / I/O error. */
int credential_read(struct credential_store *s, const unsigned char id[32], struct credential *c);
int credential_write(struct credential_store *s, const struct credential *c, int replace);
int credential_remove(struct credential_store *s, const unsigned char id[32]);
/* Bounded complete enumeration; every credential file is validated. */
int credential_list(struct credential_store *s, unsigned char ids[CREDENTIAL_LIMIT][32], size_t *count);
int credential_generate(struct credential *c, unsigned char public_key[65]);
int credential_sign(const struct credential *c, const unsigned char *data, size_t len,
    unsigned char signature[80], size_t *signature_len);

#endif
