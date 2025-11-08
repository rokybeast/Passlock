#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void xor_buf(unsigned char *d, size_t len, const unsigned char *k, size_t klen) {
    for (size_t i = 0; i < len; i++) {
        d[i] ^= k[i % klen];
    }
}

int gen_rand(unsigned char *buf, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        srand(time(NULL));
        for (size_t i = 0; i < n; i++) {
            buf[i] = rand() % 256;
        }
        return 0;
    }
    
    size_t rd = fread(buf, 1, n, f);
    fclose(f);
    return rd == n ? 0 : -1;
}

unsigned long hash_str(const char *s) {
    unsigned long h = 5381;
    int c;
    while ((c = *s++)) {
        h = ((h << 5) + h) + c;
    }
    return h;
}

void sec_zero(void *p, size_t n) {
    volatile unsigned char *vp = p;
    while (n--) {
        *vp++ = 0;
    }
}

int safe_cmp(const char *a, const char *b, size_t n) {
    unsigned char r = 0;
    for (size_t i = 0; i < n; i++) {
        r |= a[i] ^ b[i];
    }
    return r;
}