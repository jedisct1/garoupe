#include <stdint.h>
#include <string.h>

#include "garoupe-256.h"

#if !defined(__clang__) && !defined(__GNUC__)
#ifdef __attribute__
#undef __attribute__
#endif
#define __attribute__(a)
#endif

#ifndef CRYPTO_ALIGN
#if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#define CRYPTO_ALIGN(x) __declspec(align(x))
#else
#define CRYPTO_ALIGN(x) __attribute__((aligned(x)))
#endif
#endif

typedef uint32_t HalfState[8];

typedef struct State_ {
    HalfState x;
    HalfState y;
} State CRYPTO_ALIGN(32);

#define ROTR32(X, Y) (((X) >> (Y)) | ((X) << (32 - (Y))))

static void
state_sbox(State *st)
{
    const uint32_t  rc[8] = { 0xb7e15162, 0xbf715880, 0x38b4da56, 0x324e7738,
                             0xbb1185eb, 0x4f7c7b57, 0xcfbfa1c8, 0xc2b3293d };
    uint32_t *const x     = &st->x[0];
    uint32_t *const y     = &st->y[0];
    size_t          i;

    for (i = 0; i < 8; i++) {
        x[i] += ROTR32(y[i], 31);
    }
    for (i = 0; i < 8; i++) {
        y[i] += ROTR32(x[i], 24);
    }
    for (i = 0; i < 8; i++) {
        x[i] ^= rc[i];
    }

    for (i = 0; i < 8; i++) {
        x[i] += ROTR32(y[i], 17);
    }
    for (i = 0; i < 8; i++) {
        y[i] += ROTR32(x[i], 17);
    }
    for (i = 0; i < 8; i++) {
        x[i] ^= rc[i];
    }

    for (i = 0; i < 8; i++) {
        x[i] += y[i];
    }
    for (i = 0; i < 8; i++) {
        y[i] += ROTR32(x[i], 31);
    }
    for (i = 0; i < 8; i++) {
        x[i] ^= rc[i];
    }

    for (i = 0; i < 8; i++) {
        x[i] += ROTR32(y[i], 24);
    }
    for (i = 0; i < 8; i++) {
        y[i] += ROTR32(x[i], 16);
    }
    for (i = 0; i < 8; i++) {
        x[i] ^= rc[i];
    }
}

static void
state_update(State *st, uint64_t d1, uint64_t d2)
{
    uint64_t st_p[16];
    memcpy(st_p, st, sizeof st_p);

    state_sbox(st);
    uint64_t *st64 = (uint64_t *) st;

    size_t i;
    for (i = 0; i < 8; i++) {
        st64[i] ^= st_p[(i - 1) % 8];
    }
    st64[0] ^= d1;
    st64[4] ^= d2;
}

static void
state_init(State *restrict st, const uint8_t key[32], const uint8_t nonce[20])
{
    static const HalfState x0 = { 0x243f6a88, 0x85a308d3, 0x13198a2e,
                                  0x03707344, 0xa4093822, 0x299f31d0,
                                  0x082efa98, 0xec4e6c89 };
    static const HalfState y0 = { 0x452821e6, 0x38d01377, 0xbe5466cf,
                                  0x34e90c6c, 0xc0ac29b7, 0xc97c50dd,
                                  0x3f84d5b5, 0xb5470917 };
    size_t                 i;

    memcpy(st->x, x0, sizeof st->x);
    memcpy(st->y, y0, sizeof st->y);

    uint8_t *x8 = (uint8_t *) st->x;
    uint8_t *y8 = (uint8_t *) st->y;
    for (i = 0; i < 32; i++) {
        x8[i] ^= key[i];
    }
    for (i = 0; i < 20; i++) {
        y8[i] ^= nonce[i];
    }
    for (i = 0; i < 20; i++) {
        state_update(st, i, i);
    }
}

static void
enc(State *restrict st, uint8_t dst[16], const uint8_t src[16])
{
    size_t   i;
    uint8_t  c[16];
    uint8_t *st8_1 = &((uint8_t *) st)[16];
    uint8_t *st8_2 = &((uint8_t *) st)[48];
    for (i = 0; i < 16; i++) {
        c[i] = src[i] ^ st8_1[i] ^ st8_2[i];
    }
    uint64_t d1, d2;
    memcpy(&d1, src, 8);
    memcpy(&d2, src + 8, 8);
    memcpy(dst, c, 16);
    state_update(st, d1, d2);
}

static void
dec(State *restrict st, uint8_t dst[16], const uint8_t src[16])
{
    size_t   i;
    uint8_t  m[16];
    uint8_t *st8_1 = &((uint8_t *) st)[16];
    uint8_t *st8_2 = &((uint8_t *) st)[48];
    for (i = 0; i < 16; i++) {
        m[i] = src[i] ^ st8_1[i] ^ st8_2[i];
    }
    uint64_t d1, d2;
    memcpy(&d1, m, 8);
    memcpy(&d2, m + 8, 8);
    memcpy(dst, m, 16);
    state_update(st, d1, d2);
}

static void
mac(State *restrict st, uint8_t tag[16], size_t ad_len, size_t m_len)
{
    size_t i;
    for (i = 0; i < 10; i++) {
        state_update(st, (uint64_t) ad_len, (uint64_t) m_len);
    }
    uint8_t  tag_[16];
    uint8_t *st8_0 = &((uint8_t *) st)[0];
    uint8_t *st8_1 = &((uint8_t *) st)[16];
    uint8_t *st8_2 = &((uint8_t *) st)[32];
    uint8_t *st8_3 = &((uint8_t *) st)[48];
    memcpy(tag_, st8_0, 16);
    for (i = 0; i < 16; i++) {
        tag_[i] ^= st8_1[i];
    }
    for (i = 0; i < 16; i++) {
        tag_[i] ^= st8_2[i];
    }
    for (i = 0; i < 16; i++) {
        tag_[i] ^= st8_3[i];
    }
    memcpy(tag, tag_, 16);
}

void
garoupe256_encrypt(uint8_t *c, uint8_t tag[garoupe256_MACBYTES],
                   const uint8_t *m, size_t m_len, const uint8_t *ad,
                   size_t ad_len, const uint8_t nonce[garoupe256_NONCEBYTES],
                   const uint8_t key[garoupe256_KEYBYTES])
{
    State   st;
    uint8_t src[16];
    uint8_t dst[16];
    size_t  i;

    state_init(&st, key, nonce);
    for (i = 0; i + 16 <= ad_len; i += 16) {
        enc(&st, dst, ad + i);
    }
    if (ad_len % 16 != 0) {
        memset(src, 0, 16);
        memcpy(src, ad + i, ad_len % 16);
        enc(&st, dst, src);
    }
    for (i = 0; i + 16 <= m_len; i += 16) {
        enc(&st, c + i, m + i);
    }
    if (m_len % 16 != 0) {
        memset(src, 0, 16);
        memcpy(src, m + i, m_len % 16);
        enc(&st, dst, src);
        memcpy(c + i, dst, m_len % 16);
    }
    mac(&st, tag, ad_len, m_len);
}

int
garoupe256_decrypt(uint8_t *m, const uint8_t *c, size_t c_len,
                   const uint8_t tag[garoupe256_MACBYTES], const uint8_t *ad,
                   size_t ad_len, const uint8_t nonce[garoupe256_NONCEBYTES],
                   const uint8_t key[garoupe256_KEYBYTES])
{
    State   st;
    uint8_t src[16];
    uint8_t dst[16];
    size_t  i;

    state_init(&st, key, nonce);
    for (i = 0; i + 16 <= ad_len; i += 16) {
        enc(&st, dst, ad + i);
    }
    if (ad_len % 16 != 0) {
        memset(src, 0, 16);
        memcpy(src, ad + i, ad_len % 16);
        enc(&st, dst, src);
    }
    for (i = 0; i + 16 <= c_len; i += 16) {
        dec(&st, m + i, c + i);
    }
    if (c_len % 16 != 0) {
        memset(src, 0, 16);
        memcpy(src, c + i, c_len % 16);
        dec(&st, dst, src);
        memcpy(m + i, dst, c_len % 16);
        memset(dst, 0, c_len % 16);
        uint8_t *restrict st8_1 = &((uint8_t *) &st)[0];
        uint8_t *restrict st8_2 = &((uint8_t *) &st)[32];
        for (i = 0; i < 8; i++) {
            st8_1[i] ^= dst[i];
            st8_2[i] ^= dst[i + 8];
        }
    }

    uint8_t computed_tag[16];
    mac(&st, computed_tag, ad_len, c_len);

    uint8_t z = 0;
    for (i = 0; i < 16; i++) {
        z |= computed_tag[i] ^ tag[i];
    }
    if (z != 0) {
        memset(m, 0xd0, c_len);
        return -1;
    }
    return 0;
}
