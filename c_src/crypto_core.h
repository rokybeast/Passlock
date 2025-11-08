#ifndef CRYPTO_CORE_H
#define CRYPTO_CORE_H

#include <stddef.h>

void xor_buf(unsigned char *d, size_t len, const unsigned char *k, size_t klen);
int gen_rand(unsigned char *buf, size_t n);
unsigned long hash_str(const char *s);
void sec_zero(void *p, size_t n);
int safe_cmp(const char *a, const char *b, size_t n);

#endif