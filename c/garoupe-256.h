#ifndef garoupe_256_H
#define garoupe_256_H 1

#include <stddef.h>
#include <stdint.h>

#define garoupe256_MACBYTES 16
#define garoupe256_KEYBYTES 32
#define garoupe256_NONCEBYTES 20

void garoupe256_encrypt(uint8_t *c, uint8_t tag[garoupe256_MACBYTES],
                        const uint8_t *m, size_t m_len, const uint8_t *ad,
                        size_t        ad_len,
                        const uint8_t nonce[garoupe256_NONCEBYTES],
                        const uint8_t key[garoupe256_KEYBYTES]);

int garoupe256_decrypt(uint8_t *m, const uint8_t *c, size_t c_len,
                       const uint8_t  tag[garoupe256_MACBYTES],
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t nonce[garoupe256_NONCEBYTES],
                       const uint8_t key[garoupe256_KEYBYTES]);

#endif
