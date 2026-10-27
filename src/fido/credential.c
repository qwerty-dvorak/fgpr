#define _GNU_SOURCE
#include "credential.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define RECORD_MAX 538
#define RECORD_HEADER 90

static void filename(const unsigned char id[32], char name[70])
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) { name[2*i] = hex[id[i] >> 4]; name[2*i+1] = hex[id[i] & 15]; }
    memcpy(name + 64, ".cred", 6);
}

static int safe_file(const struct stat *st)
{
    return S_ISREG(st->st_mode) && st->st_uid == geteuid() &&
        (st->st_mode & 07777) == 0600 && st->st_nlink == 1;
}

int credential_store_open(struct credential_store *s, const char *path)
{
    s->fd = -1;
    if (!path || !*path || strlen(path) >= PATH_MAX) { errno = EINVAL; return -1; }
    char copy[PATH_MAX];
    memcpy(copy, path, strlen(path) + 1);
    int fd = open(path[0] == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    char *save = NULL, *part = strtok_r(copy, "/", &save);
    if (!part) { close(fd); errno = EINVAL; return -1; }
    while (part) {
        char *next = strtok_r(NULL, "/", &save);
        if (!strcmp(part, ".") || !strcmp(part, "..")) { close(fd); errno = EINVAL; return -1; }
        int nfd = openat(fd, part, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (nfd < 0 && errno == ENOENT && !next) {
            if (mkdirat(fd, part, 0700) < 0 && errno != EEXIST) { close(fd); return -1; }
            if (fsync(fd) < 0) { close(fd); return -1; }
            nfd = openat(fd, part, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        }
        if (nfd < 0) { close(fd); return -1; }
        if (close(fd) < 0) { close(nfd); return -1; }
        fd = nfd;
        part = next;
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 07777) != 0700 || flock(fd, LOCK_EX | LOCK_NB) < 0) {
        close(fd); errno = EACCES; return -1;
    }
    s->fd = fd;
    return 0;
}

void credential_store_close(struct credential_store *s)
{
    if (s->fd >= 0) close(s->fd);
    s->fd = -1;
}

static void put_integer(unsigned char *p, uint64_t v, size_t n)
{
    while (n) { p[--n] = (unsigned char)v; v >>= 8; }
}
static uint64_t get_integer(const unsigned char *p, size_t n)
{
    uint64_t v = 0;
    while (n--) v = (v << 8) | *p++;
    return v;
}

int credential_read(struct credential_store *s, const unsigned char id[32], struct credential *c)
{
    char name[70];
    filename(id, name);
    int fd = openat(s->fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    struct stat st;
    unsigned char record[RECORD_MAX];
    int result = -1;
    if (fstat(fd, &st) < 0 || !safe_file(&st) || st.st_size < RECORD_HEADER || st.st_size > RECORD_MAX) goto out;
    size_t size = (size_t)st.st_size, pos = 0;
    while (pos < size) {
        ssize_t n = read(fd, record + pos, size - pos);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto out;
        pos += (size_t)n;
    }
    unsigned char extra;
    ssize_t tail;
    do { tail = read(fd, &extra, 1); } while (tail < 0 && errno == EINTR);
    if (tail != 0 || memcmp(record, "FGPRFID1", 8) || memcmp(record + 8, id, 32)) goto out;
    memset(c, 0, sizeof(*c));
    memcpy(c->id, record + 8, 32);
    memcpy(c->rp, record + 40, 32);
    c->created = get_integer(record + 72, 8);
    c->counter = (uint32_t)get_integer(record + 80, 4);
    c->resident = record[84];
    c->user_len = record[85]; c->name_len = record[86]; c->display_len = record[87];
    c->der_len = (size_t)get_integer(record + 88, 2);
    if (c->resident > 1 || !c->created || c->user_len > 64 || c->name_len > 64 ||
        c->display_len > 64 || !c->der_len || c->der_len > CREDENTIAL_DER_MAX ||
        RECORD_HEADER + c->user_len + c->name_len + c->display_len + c->der_len != size) goto out;
    pos = RECORD_HEADER;
    memcpy(c->user, record + pos, c->user_len); pos += c->user_len;
    memcpy(c->name, record + pos, c->name_len); pos += c->name_len;
    memcpy(c->display, record + pos, c->display_len); pos += c->display_len;
    memcpy(c->der, record + pos, c->der_len);
    result = 1;
out:
    OPENSSL_cleanse(record, sizeof(record));
    if (close(fd) < 0) result = -1;
    if (result < 0) OPENSSL_cleanse(c, sizeof(*c));
    return result;
}

int credential_write(struct credential_store *s, const struct credential *c, int replace)
{
    if (c->user_len > 64 || c->name_len > 64 || c->display_len > 64 ||
        !c->der_len || c->der_len > CREDENTIAL_DER_MAX || !c->created ||
        (c->resident != 0 && c->resident != 1)) return -1;
    unsigned char record[RECORD_MAX], random[32];
    char name[70], temp[70];
    filename(c->id, name);
    struct stat st;
    if (fstatat(s->fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!replace || !safe_file(&st)) return -1;
    } else if (errno != ENOENT || replace) return -1;
    if (RAND_bytes(random, sizeof(random)) != 1) return -1;
    filename(random, temp);
    memcpy(temp + 64, ".tmp", 5);
    int fd = openat(s->fd, temp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    int result = -1;
    memcpy(record, "FGPRFID1", 8);
    memcpy(record + 8, c->id, 32); memcpy(record + 40, c->rp, 32);
    put_integer(record + 72, c->created, 8); put_integer(record + 80, c->counter, 4);
    record[84] = (unsigned char)c->resident;
    record[85] = (unsigned char)c->user_len; record[86] = (unsigned char)c->name_len; record[87] = (unsigned char)c->display_len;
    put_integer(record + 88, c->der_len, 2);
    size_t size = RECORD_HEADER;
    memcpy(record + size, c->user, c->user_len); size += c->user_len;
    memcpy(record + size, c->name, c->name_len); size += c->name_len;
    memcpy(record + size, c->display, c->display_len); size += c->display_len;
    memcpy(record + size, c->der, c->der_len); size += c->der_len;
    if (fchmod(fd, 0600) < 0 || fstat(fd, &st) < 0 || !safe_file(&st)) goto out;
    size_t pos = 0;
    while (pos < size) {
        ssize_t n = write(fd, record + pos, size - pos);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto out;
        pos += (size_t)n;
    }
    if (fsync(fd) < 0) goto out;
    if (close(fd) < 0) { fd = -1; goto out; }
    fd = -1;
    if (replace) {
        if (renameat(s->fd, temp, s->fd, name) < 0) goto out;
    } else {
        if (renameat2(s->fd, temp, s->fd, name, RENAME_NOREPLACE) < 0) goto out;
    }
    if (fsync(s->fd) < 0) goto out;
    result = 0;
out:
    OPENSSL_cleanse(record, sizeof(record));
    if (fd >= 0 && close(fd) < 0) result = -1;
    if (result < 0 && unlinkat(s->fd, temp, 0) < 0 && errno != ENOENT) return -1;
    return result;
}

int credential_remove(struct credential_store *s, const unsigned char id[32])
{
    char name[70];
    struct stat st;
    filename(id, name);
    if (fstatat(s->fd, name, &st, AT_SYMLINK_NOFOLLOW) < 0 || !safe_file(&st) ||
        unlinkat(s->fd, name, 0) < 0 || fsync(s->fd) < 0) return -1;
    return 0;
}

int credential_list(struct credential_store *s, unsigned char ids[CREDENTIAL_LIMIT][32], size_t *count)
{
    int fd = openat(s->fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    DIR *dir = fdopendir(fd);
    if (!dir) { close(fd); return -1; }
    *count = 0;
    int result = 0;
    struct dirent *entry;
    for (;;) {
        errno = 0;
        entry = readdir(dir);
        if (!entry) { if (errno) result = -1; break; }
        size_t len = strlen(entry->d_name);
        if (len != 69 || strcmp(entry->d_name + 64, ".cred")) continue;
        if (*count == CREDENTIAL_LIMIT) { result = -1; break; }
        unsigned char id[32];
        for (size_t i = 0; i < 64; ++i) {
            unsigned char ch = (unsigned char)entry->d_name[i];
            unsigned v = ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : 16;
            if (v == 16) { result = -1; break; }
            if (!(i & 1)) id[i/2] = (unsigned char)(v << 4);
            else id[i/2] |= (unsigned char)v;
        }
        if (result < 0) break;
        struct credential c;
        if (credential_read(s, id, &c) != 1) { result = -1; break; }
        OPENSSL_cleanse(&c, sizeof(c));
        memcpy(ids[(*count)++], id, 32);
    }
    if (closedir(dir) < 0) result = -1;
    return result;
}

int credential_generate(struct credential *c, unsigned char public_key[65])
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *key = NULL;
    int result = -1;
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(ctx, &key) <= 0) goto out;
    unsigned char *p = c->der;
    int size = i2d_PrivateKey(key, NULL);
    size_t public_len = 0;
    if (size <= 0 || size > CREDENTIAL_DER_MAX || i2d_PrivateKey(key, &p) != size ||
        EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, public_key, 65, &public_len) != 1 ||
        public_len != 65 || public_key[0] != 4 || RAND_bytes(c->id, 32) != 1) goto out;
    c->der_len = (size_t)size;
    result = 0;
out:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return result;
}

int credential_sign(const struct credential *c, const unsigned char *data, size_t len,
    unsigned char signature[80], size_t *signature_len)
{
    const unsigned char *p = c->der;
    EVP_PKEY *key = d2i_AutoPrivateKey(NULL, &p, (long)c->der_len);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *check = key ? EVP_PKEY_CTX_new(key, NULL) : NULL;
    int result = -1;
    char group[32];
    size_t group_len = 0;
    *signature_len = 80;
    if (!key || !ctx || !check || p != c->der + c->der_len ||
        !EVP_PKEY_is_a(key, "EC") ||
        EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group), &group_len) != 1 ||
        strcmp(group, "prime256v1") || EVP_PKEY_private_check(check) != 1 ||
        EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) != 1 ||
        EVP_DigestSign(ctx, signature, signature_len, data, len) != 1 || *signature_len > 80) goto out;
    result = 0;
out:
    EVP_PKEY_CTX_free(check);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return result;
}
