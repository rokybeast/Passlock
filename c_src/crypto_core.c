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

#ifdef TEST_MODE

void test_xor_buf() {
    printf("Testing xor_buf... ");
    unsigned char data[] = {0xAA, 0xBB, 0xCC, 0xDD};
    unsigned char key[] = {0x12, 0x34};
    unsigned char expected[] = {0xAA^0x12, 0xBB^0x34, 0xCC^0x12, 0xDD^0x34};
    
    xor_buf(data, sizeof(data), key, sizeof(key));
    
    if (memcmp(data, expected, sizeof(data)) == 0) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
    }
}

void test_gen_rand() {
    printf("Testing gen_rand... ");
    unsigned char buf[16];
    
    if (gen_rand(buf, sizeof(buf)) == 0) {
        int all_zero = 1;
        for (int i = 0; i < sizeof(buf); i++) {
            if (buf[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (!all_zero) {
            printf("PASS\n");
        } else {
            printf("FAIL (all zeros)\n");
        }
    } else {
        printf("FAIL (gen_rand returned error)\n");
    }
}

void test_hash_str() {
    printf("Testing hash_str... ");
    unsigned long h1 = hash_str("hello");
    unsigned long h2 = hash_str("hello");
    unsigned long h3 = hash_str("world");
    
    if (h1 == h2 && h1 != h3) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
    }
}

void test_sec_zero() {
    printf("Testing sec_zero... ");
    char secret[] = "sensitive data";
    sec_zero(secret, sizeof(secret));
    
    int is_zero = 1;
    for (size_t i = 0; i < sizeof(secret); i++) {
        if (secret[i] != 0) {
            is_zero = 0;
            break;
        }
    }
    
    if (is_zero) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
    }
}

void test_safe_cmp() {
    printf("Testing safe_cmp... ");
    char a[] = "test123";
    char b[] = "test123";
    char c[] = "test124";
    
    int r1 = safe_cmp(a, b, strlen(a));
    int r2 = safe_cmp(a, c, strlen(a));
    
    if (r1 == 0 && r2 != 0) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
    }
}

int main() {
    printf("Running crypto tests...\n\n");
    
    test_xor_buf();
    test_gen_rand();
    test_hash_str();
    test_sec_zero();
    test_safe_cmp();
    
    printf("\nAll tests completed!\n");
    return 0;
}

#endif