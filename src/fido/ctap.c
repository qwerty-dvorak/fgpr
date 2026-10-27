#define _POSIX_C_SOURCE 200809L
#include "ctap.h"
#include "cbor.h"
#include "credential.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum {
    OK = 0, INVALID_COMMAND = 0x01, INVALID_PARAMETER = 0x02, INVALID_LENGTH = 0x03,
    CBOR_TYPE = 0x11, INVALID_CBOR = 0x12, MISSING_PARAMETER = 0x14,
    LIMIT_EXCEEDED = 0x15, CREDENTIAL_EXCLUDED = 0x19, UNSUPPORTED_ALGORITHM = 0x26,
    OPERATION_DENIED = 0x27, KEY_STORE_FULL = 0x28, UNSUPPORTED_OPTION = 0x2b,
    INVALID_OPTION = 0x2c, NO_CREDENTIALS = 0x2e, NOT_ALLOWED = 0x30, OTHER = 0x7f
};
#define LIST_LIMIT 32
#define RP_LIMIT 253
/* Reserve one on-disk slot to complete resident replacement after a crash. */
#define ACTIVE_CREDENTIAL_LIMIT (CREDENTIAL_LIMIT - 1)

/* Software-only, model identifier; no identifying per-device attestation. */
static const unsigned char aaguid[16] = {
    0x68, 0x29, 0xc5, 0x87, 0x42, 0x6b, 0x4e, 0xb8,
    0x9c, 0x47, 0x60, 0x4d, 0x7e, 0x08, 0x6a, 0x35
};

struct ctap {
    struct credential_store store;
    ctap_verify_fn verify;
    void *verify_arg;
    struct cbor_doc doc;
    unsigned char ids[CREDENTIAL_LIMIT][32];
    unsigned char pending[CREDENTIAL_LIMIT][32];
    uint64_t order[CREDENTIAL_LIMIT];
    size_t pending_count, pending_next;
    unsigned char rp[32], client_hash[32], flags;
    struct timespec touched;
    uint64_t sequence;
    int failed;
};

static void clear_assertion(struct ctap *c)
{
    c->pending_count = c->pending_next = 0;
    c->flags = 0;
    OPENSSL_cleanse(c->client_hash, sizeof(c->client_hash));
}

static int hash_rp(const struct cbor_item *v, unsigned char rp[32])
{
    if (!v) return MISSING_PARAMETER;
    if (v->type != 3) return CBOR_TYPE;
    if (!v->len || v->len > RP_LIMIT || memchr(v->data, 0, v->len)) return INVALID_LENGTH;
    unsigned n = 0;
    return EVP_Digest(v->data, v->len, rp, &n, EVP_sha256(), NULL) == 1 && n == 32 ? OK : OTHER;
}

static int map_strings(const struct cbor_doc *d, const struct cbor_item *m)
{
    if (m->type != 5) return CBOR_TYPE;
    unsigned i = (unsigned)(m - d->items) + 1;
    for (size_t n = 0; n < m->len; ++n) {
        const struct cbor_item *key = &d->items[i];
        if (key->type != 3) return CBOR_TYPE;
        i = d->items[key->end].end;
    }
    return OK;
}

static int optional_map(struct ctap *c, unsigned key)
{
    const struct cbor_item *v = cbor_int(&c->doc, &c->doc.items[0], key);
    return v ? map_strings(&c->doc, v) : OK;
}

static int option(struct ctap *c, const struct cbor_item *options, const char *key, int fallback, int *value)
{
    const struct cbor_item *v = cbor_text(&c->doc, options, key);
    *value = fallback;
    if (!v) return OK;
    if (v->type != 7 || v->len != 0 || (v->value != 20 && v->value != 21)) return CBOR_TYPE;
    *value = v->value == 21;
    return OK;
}

static int pin_parameters(struct ctap *c, unsigned param, unsigned protocol)
{
    const struct cbor_item *p = cbor_int(&c->doc, &c->doc.items[0], param);
    const struct cbor_item *v = cbor_int(&c->doc, &c->doc.items[0], protocol);
    if (p && p->type != 2) return CBOR_TYPE;
    if (v && v->type != 0) return CBOR_TYPE;
    if (p && !v) return MISSING_PARAMETER;
    /* No PIN protocol, token, or PIN-based UV is implemented. */
    return p || v ? INVALID_PARAMETER : OK;
}

static int verify_user(struct ctap *c)
{
    if (!c->verify) return OPERATION_DENIED;
    int status = c->verify(c->verify_arg);
    if (status == OK || status == OPERATION_DENIED || status == 0x2d || status == 0x2f) return status;
    return OPERATION_DENIED;
}

static int descriptors(struct ctap *c, const struct cbor_item *list)
{
    if (!list) return OK;
    if (list->type != 4) return CBOR_TYPE;
    if (list->len > LIST_LIMIT) return LIMIT_EXCEEDED;
    unsigned i = (unsigned)(list - c->doc.items) + 1;
    for (size_t n = 0; n < list->len; ++n) {
        const struct cbor_item *m = &c->doc.items[i];
        int err = map_strings(&c->doc, m);
        if (err) return err;
        const struct cbor_item *id = cbor_text(&c->doc, m, "id");
        const struct cbor_item *type = cbor_text(&c->doc, m, "type");
        if (!id || !type) return MISSING_PARAMETER;
        if (id->type != 2 || type->type != 3) return CBOR_TYPE;
        if (!id->len || id->len > 1024) return INVALID_LENGTH;
        const struct cbor_item *t = cbor_text(&c->doc, m, "transports");
        if (t) {
            if (t->type != 4) return CBOR_TYPE;
            unsigned j = (unsigned)(t - c->doc.items) + 1;
            for (size_t k = 0; k < t->len; ++k) {
                if (c->doc.items[j].type != 3) return CBOR_TYPE;
                j = c->doc.items[j].end;
            }
        }
        i = m->end;
    }
    return OK;
}

static int listed(struct ctap *c, const struct cbor_item *list, const unsigned char id[32])
{
    if (!list) return 0;
    unsigned i = (unsigned)(list - c->doc.items) + 1;
    for (size_t n = 0; n < list->len; ++n) {
        const struct cbor_item *m = &c->doc.items[i];
        const struct cbor_item *v = cbor_text(&c->doc, m, "id");
        if (cbor_is_text(cbor_text(&c->doc, m, "type"), "public-key") &&
            v->len == 32 && !CRYPTO_memcmp(v->data, id, 32)) return 1;
        i = m->end;
    }
    return 0;
}

static void descriptor(struct cbor_writer *w, const unsigned char id[32])
{
    cbor_head(w, 5, 2);
    cbor_cstr(w, "id"); cbor_bytes(w, id, 32);
    cbor_cstr(w, "type"); cbor_cstr(w, "public-key");
}

static void counter_bytes(unsigned char data[4], uint32_t n)
{
    data[0] = (unsigned char)(n >> 24); data[1] = (unsigned char)(n >> 16);
    data[2] = (unsigned char)(n >> 8); data[3] = (unsigned char)n;
}

static int get_info(struct cbor_writer *w)
{
    cbor_head(w, 5, 8);
    cbor_head(w, 0, 1); cbor_head(w, 4, 1); cbor_cstr(w, "FIDO_2_0");
    cbor_head(w, 0, 3); cbor_bytes(w, aaguid, sizeof(aaguid));
    cbor_head(w, 0, 4); cbor_head(w, 5, 4);
    cbor_cstr(w, "rk"); cbor_bool(w, 1);
    cbor_cstr(w, "up"); cbor_bool(w, 1);
    cbor_cstr(w, "uv"); cbor_bool(w, 1);
    cbor_cstr(w, "plat"); cbor_bool(w, 0);
    cbor_head(w, 0, 5); cbor_head(w, 0, CTAP_MAX_MSG);
    cbor_head(w, 0, 7); cbor_head(w, 0, LIST_LIMIT);
    cbor_head(w, 0, 8); cbor_head(w, 0, 32);
    cbor_head(w, 0, 9); cbor_head(w, 4, 1); cbor_cstr(w, "usb");
    cbor_head(w, 0, 10); cbor_head(w, 4, 1); cbor_head(w, 5, 2);
    cbor_cstr(w, "alg"); cbor_head(w, 1, 6);
    cbor_cstr(w, "type"); cbor_cstr(w, "public-key");
    return w->error ? OTHER : OK;
}

static int text_metadata(struct ctap *c, const struct cbor_item *map, const char *key, char data[64], size_t *len)
{
    const struct cbor_item *v = cbor_text(&c->doc, map, key);
    *len = 0;
    if (!v) return OK;
    if (v->type != 3) return CBOR_TYPE;
    size_t n = v->len < 64 ? v->len : 64;
    /* Truncate at a complete UTF-8 code point, not within a continuation. */
    if (n < v->len) while (n && (v->data[n] & 0xc0) == 0x80) --n;
    memcpy(data, v->data, n);
    *len = n;
    return OK;
}

static int make_credential(struct ctap *c, struct cbor_writer *w)
{
    const struct cbor_item *root = &c->doc.items[0];
    const struct cbor_item *hash = cbor_int(&c->doc, root, 1);
    const struct cbor_item *rp = cbor_int(&c->doc, root, 2);
    const struct cbor_item *user = cbor_int(&c->doc, root, 3);
    const struct cbor_item *params = cbor_int(&c->doc, root, 4);
    const struct cbor_item *exclude = cbor_int(&c->doc, root, 5);
    const struct cbor_item *options = cbor_int(&c->doc, root, 7);
    if (!hash || !rp || !user || !params) return MISSING_PARAMETER;
    if (hash->type != 2 || params->type != 4) return CBOR_TYPE;
    if (hash->len != 32) return INVALID_LENGTH;
    int err = map_strings(&c->doc, rp);
    if (err) return err;
    if ((err = map_strings(&c->doc, user)) || (err = optional_map(c, 6)) ||
        (err = optional_map(c, 7)) || (err = pin_parameters(c, 8, 9)) ||
        (err = descriptors(c, exclude))) return err;
    int resident, uv;
    if ((err = option(c, options, "rk", 0, &resident)) ||
        (err = option(c, options, "uv", 0, &uv))) return err;
    /* CTAP2.0 does not accept the MakeCredential 'up' option at all. */
    if (cbor_text(&c->doc, options, "up")) return INVALID_OPTION;
    (void)uv; /* Biometric verification is always required for key creation. */
    struct credential fresh = {0};
    if ((err = hash_rp(cbor_text(&c->doc, rp, "id"), fresh.rp))) return err;
    const struct cbor_item *uid = cbor_text(&c->doc, user, "id");
    if (!uid) return MISSING_PARAMETER;
    if (uid->type != 2) return CBOR_TYPE;
    if (uid->len > 64) return INVALID_LENGTH;
    fresh.user_len = uid->len;
    memcpy(fresh.user, uid->data, uid->len);
    fresh.resident = resident;
    if ((err = text_metadata(c, user, "name", fresh.name, &fresh.name_len)) ||
        (err = text_metadata(c, user, "displayName", fresh.display, &fresh.display_len))) return err;
    const struct cbor_item *icon = cbor_text(&c->doc, user, "icon");
    const struct cbor_item *rpname = cbor_text(&c->doc, rp, "name");
    const struct cbor_item *rpicon = cbor_text(&c->doc, rp, "icon");
    if ((icon && icon->type != 3) || (rpname && rpname->type != 3) || (rpicon && rpicon->type != 3)) return CBOR_TYPE;
    int supported = 0;
    unsigned i = (unsigned)(params - c->doc.items) + 1;
    for (size_t n = 0; n < params->len; ++n) {
        const struct cbor_item *m = &c->doc.items[i];
        if ((err = map_strings(&c->doc, m))) return err;
        const struct cbor_item *alg = cbor_text(&c->doc, m, "alg");
        const struct cbor_item *type = cbor_text(&c->doc, m, "type");
        if (!alg || !type) return MISSING_PARAMETER;
        if ((alg->type != 0 && alg->type != 1) || type->type != 3) return CBOR_TYPE;
        if (alg->type == 1 && alg->value == 6 && cbor_is_text(type, "public-key")) supported = 1;
        i = m->end;
    }
    if (!supported) return UNSUPPORTED_ALGORITHM;
    size_t count;
    if (credential_list(&c->store, c->ids, &count) < 0) return OTHER;
    unsigned char previous[32];
    int have_previous = 0, excluded = 0;
    for (size_t n = 0; n < count; ++n) {
        struct credential stored;
        if (credential_read(&c->store, c->ids[n], &stored) != 1) return OTHER;
        int same_rp = !CRYPTO_memcmp(stored.rp, fresh.rp, 32);
        if (same_rp && listed(c, exclude, stored.id)) excluded = 1;
        if (resident && same_rp && stored.resident && stored.user_len == fresh.user_len &&
            !CRYPTO_memcmp(stored.user, fresh.user, fresh.user_len)) {
            memcpy(previous, stored.id, 32); have_previous = 1;
        }
        OPENSSL_cleanse(&stored, sizeof(stored));
    }
    if ((err = verify_user(c))) return err;
    if (excluded) return CREDENTIAL_EXCLUDED;
    if ((!have_previous && count >= ACTIVE_CREDENTIAL_LIMIT) || c->sequence == UINT64_MAX) return KEY_STORE_FULL;
    fresh.created = ++c->sequence;
    unsigned char public_key[65], auth[256];
    if (credential_generate(&fresh, public_key) < 0) { OPENSSL_cleanse(&fresh, sizeof(fresh)); return OTHER; }
    /* A random-ID collision never overwrites a credential. */
    for (size_t n = 0; n < count; ++n) {
        if (!CRYPTO_memcmp(c->ids[n], fresh.id, 32)) { OPENSSL_cleanse(&fresh, sizeof(fresh)); return OTHER; }
    }
    memcpy(auth, fresh.rp, 32); auth[32] = 0x45; counter_bytes(auth + 33, 0);
    memcpy(auth + 37, aaguid, 16); auth[53] = 0; auth[54] = 32;
    memcpy(auth + 55, fresh.id, 32);
    struct cbor_writer key = { auth, 87, sizeof(auth), 0 };
    cbor_head(&key, 5, 5);
    cbor_head(&key, 0, 1); cbor_head(&key, 0, 2);
    cbor_head(&key, 0, 3); cbor_head(&key, 1, 6);
    cbor_head(&key, 1, 0); cbor_head(&key, 0, 1);
    cbor_head(&key, 1, 1); cbor_bytes(&key, public_key + 1, 32);
    cbor_head(&key, 1, 2); cbor_bytes(&key, public_key + 33, 32);
    cbor_head(w, 5, 3);
    cbor_head(w, 0, 1); cbor_cstr(w, "none");
    cbor_head(w, 0, 2); cbor_bytes(w, auth, key.len);
    cbor_head(w, 0, 3); cbor_head(w, 5, 0);
    err = OK;
    if (key.error || w->error) err = OTHER;
    else if (credential_write(&c->store, &fresh, 0) < 0) { c->failed = 1; err = OTHER; }
    else if (have_previous && credential_remove(&c->store, previous) < 0) { c->failed = 1; err = OTHER; }
    OPENSSL_cleanse(&fresh, sizeof(fresh));
    return err;
}

static int assertion(struct ctap *c, struct cbor_writer *w, int first, int include_user)
{
    struct credential cred;
    if (credential_read(&c->store, c->pending[c->pending_next], &cred) != 1) return OTHER;
    int err = OTHER;
    if (CRYPTO_memcmp(cred.rp, c->rp, 32) || cred.counter == UINT32_MAX) goto out;
    unsigned char signed_data[69], sig[80];
    memcpy(signed_data, c->rp, 32); signed_data[32] = c->flags;
    counter_bytes(signed_data + 33, ++cred.counter);
    memcpy(signed_data + 37, c->client_hash, 32);
    size_t sig_len = 0;
    /* Silent probes are the CTAP-defined exception: no UP/UV claims, and
     * resident user entities contain only the opaque user ID. Every ordinary
     * assertion is gated by a successful biometric callback; continuations
     * inherit only that immediately preceding, bounded authorization. */
    if (credential_sign(&cred, signed_data, sizeof(signed_data), sig, &sig_len) < 0) goto out;
    int multiple = first && c->pending_count > 1;
    cbor_head(w, 5, 3 + (include_user ? 1 : 0) + (multiple ? 1 : 0));
    cbor_head(w, 0, 1); descriptor(w, cred.id);
    cbor_head(w, 0, 2); cbor_bytes(w, signed_data, 37);
    cbor_head(w, 0, 3); cbor_bytes(w, sig, sig_len);
    if (include_user) {
        int personal = !!(c->flags & 4);
        cbor_head(w, 0, 4);
        cbor_head(w, 5, 1 + (personal && cred.name_len ? 1 : 0) + (personal && cred.display_len ? 1 : 0));
        cbor_cstr(w, "id"); cbor_bytes(w, cred.user, cred.user_len);
        if (personal && cred.name_len) { cbor_cstr(w, "name"); cbor_string(w, cred.name, cred.name_len); }
        if (personal && cred.display_len) { cbor_cstr(w, "displayName"); cbor_string(w, cred.display, cred.display_len); }
    }
    if (multiple) { cbor_head(w, 0, 5); cbor_head(w, 0, c->pending_count); }
    if (w->error) goto out;
    /* Persist before releasing any signature. On uncertain persistence, stop
     * using this context: restart reloads the on-disk monotonic counter. */
    if (credential_write(&c->store, &cred, 1) < 0) { c->failed = 1; goto out; }
    ++c->pending_next;
    if (clock_gettime(CLOCK_MONOTONIC, &c->touched) < 0) goto out;
    err = OK;
out:
    OPENSSL_cleanse(&cred, sizeof(cred));
    return err;
}

static int get_assertion(struct ctap *c, struct cbor_writer *w)
{
    const struct cbor_item *root = &c->doc.items[0];
    const struct cbor_item *rp = cbor_int(&c->doc, root, 1);
    const struct cbor_item *hash = cbor_int(&c->doc, root, 2);
    const struct cbor_item *allow = cbor_int(&c->doc, root, 3);
    const struct cbor_item *options = cbor_int(&c->doc, root, 5);
    if (!rp || !hash) return MISSING_PARAMETER;
    if (hash->type != 2) return CBOR_TYPE;
    if (hash->len != 32) return INVALID_LENGTH;
    int err;
    if ((err = hash_rp(rp, c->rp)) || (err = descriptors(c, allow)) ||
        (err = optional_map(c, 4)) || (err = optional_map(c, 5)) ||
        (err = pin_parameters(c, 6, 7))) return err;
    int up, uv;
    if ((err = option(c, options, "up", 1, &up)) ||
        (err = option(c, options, "uv", 0, &uv))) return err;
    if (cbor_text(&c->doc, options, "rk")) return UNSUPPORTED_OPTION;
    if (uv && (err = verify_user(c))) return err;
    size_t count;
    if (credential_list(&c->store, c->ids, &count) < 0) return OTHER;
    for (size_t n = 0; n < count; ++n) {
        struct credential cred;
        if (credential_read(&c->store, c->ids[n], &cred) != 1) return OTHER;
        if (!CRYPTO_memcmp(cred.rp, c->rp, 32) && (allow ? listed(c, allow, cred.id) : cred.resident)) {
            size_t index = c->pending_count++;
            memcpy(c->pending[index], cred.id, 32);
            c->order[index] = cred.created;
        }
        OPENSSL_cleanse(&cred, sizeof(cred));
    }
    if (!c->pending_count) return NO_CREDENTIALS;
    if (!allow) {
        for (size_t i = 1; i < c->pending_count; ++i) {
            size_t j = i;
            while (j && c->order[j] > c->order[j-1]) {
                unsigned char tmp[32];
                memcpy(tmp, c->pending[j], 32); memcpy(c->pending[j], c->pending[j-1], 32); memcpy(c->pending[j-1], tmp, 32);
                uint64_t order = c->order[j]; c->order[j] = c->order[j-1]; c->order[j-1] = order;
                --j;
            }
        }
    } else c->pending_count = 1;
    if (up && !uv && (err = verify_user(c))) return err;
    c->flags = up || uv ? 0x05 : 0;
    memcpy(c->client_hash, hash->data, 32);
    return assertion(c, w, 1, !allow);
}

static int next_assertion(struct ctap *c, struct cbor_writer *w)
{
    struct timespec now;
    if (c->pending_next >= c->pending_count) return NOT_ALLOWED;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return OTHER;
    time_t seconds = now.tv_sec - c->touched.tv_sec;
    if (seconds > 30 || (seconds == 30 && now.tv_nsec > c->touched.tv_nsec)) return NOT_ALLOWED;
    return assertion(c, w, 0, 1);
}

struct ctap *ctap_new(const char *credential_dir, ctap_verify_fn verify, void *arg)
{
    if (!verify) return NULL;
    struct ctap *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->store.fd = -1;
    c->verify = verify; c->verify_arg = arg;
    if (credential_store_open(&c->store, credential_dir) < 0) goto fail;
    size_t count;
    if (credential_list(&c->store, c->ids, &count) < 0) goto fail;
    /* Finish an interrupted replacement: newest resident RP/account wins.
     * A new credential is durable before the previous one is removed. */
    for (size_t i = 0; i < count; ++i) {
        struct credential current;
        int found = credential_read(&c->store, c->ids[i], &current);
        if (found < 0) goto fail;
        if (!found) continue;
        if (current.created > c->sequence) c->sequence = current.created;
        if (current.resident) {
            for (size_t j = i + 1; j < count; ++j) {
                struct credential other;
                found = credential_read(&c->store, c->ids[j], &other);
                if (found < 0) { OPENSSL_cleanse(&current, sizeof(current)); goto fail; }
                if (!found) continue;
                int duplicate = other.resident && other.user_len == current.user_len &&
                    !CRYPTO_memcmp(other.rp, current.rp, 32) &&
                    !CRYPTO_memcmp(other.user, current.user, current.user_len);
                if (other.created > c->sequence) c->sequence = other.created;
                if (duplicate) {
                    const unsigned char *old = other.created > current.created ? current.id : other.id;
                    if (credential_remove(&c->store, old) < 0) {
                        OPENSSL_cleanse(&other, sizeof(other)); OPENSSL_cleanse(&current, sizeof(current)); goto fail;
                    }
                    if (other.created > current.created) {
                        OPENSSL_cleanse(&other, sizeof(other)); break;
                    }
                }
                OPENSSL_cleanse(&other, sizeof(other));
            }
        }
        OPENSSL_cleanse(&current, sizeof(current));
    }
    if (credential_list(&c->store, c->ids, &count) < 0 || count > ACTIVE_CREDENTIAL_LIMIT) goto fail;
    return c;
fail:
    ctap_free(c);
    return NULL;
}

void ctap_free(struct ctap *c)
{
    if (!c) return;
    credential_store_close(&c->store);
    OPENSSL_cleanse(c, sizeof(*c));
    free(c);
}

size_t ctap_request(struct ctap *c, const unsigned char *in, size_t inlen,
    unsigned char *out, size_t outcap)
{
    if (!out || !outcap) return 0;
    out[0] = OTHER;
    if (!c) return 1;
    if (!in || !inlen || inlen > CTAP_MAX_MSG) {
        clear_assertion(c); out[0] = INVALID_LENGTH; return 1;
    }
    unsigned command = in[0];
    if (command != 8) clear_assertion(c);
    if (c->failed) { clear_assertion(c); return 1; }
    struct cbor_writer w = { out + 1, 0, outcap - 1 < CTAP_MAX_MSG - 1 ? outcap - 1 : CTAP_MAX_MSG - 1, 0 };
    int status = OK;
    if (command == 1 || command == 2) {
        status = cbor_parse(&c->doc, in + 1, inlen - 1);
        if (!status && c->doc.items[0].type != 5) status = CBOR_TYPE;
        if (!status) {
            const struct cbor_item *root = &c->doc.items[0];
            unsigned i = 1;
            for (size_t n = 0; n < root->len; ++n) {
                if (c->doc.items[i].type != 0) { status = CBOR_TYPE; break; }
                i = c->doc.items[c->doc.items[i].end].end;
            }
        }
        if (!status) status = command == 1 ? make_credential(c, &w) : get_assertion(c, &w);
    } else if (command == 4 || command == 8) {
        if (inlen != 1) status = INVALID_LENGTH;
        else status = command == 4 ? get_info(&w) : next_assertion(c, &w);
    } else status = INVALID_COMMAND;
    if (w.error && !status) status = OTHER;
    out[0] = (unsigned char)status;
    if (status) { clear_assertion(c); return 1; }
    return w.len + 1;
}
