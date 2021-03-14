#ifndef garoupe_256_H
#define garoupe_256_H 1

#include <stddef.h>
#include <stdint.h>

#define MACBYTES 16
#define KEYBYTES 32
#define NONCEBYTES 20

void encrypt(uint8_t *c, uint8_t tag[MACBYTES], const uint8_t *m, size_t m_len,
             const uint8_t *ad, size_t ad_len, const uint8_t nonce[NONCEBYTES],
             const uint8_t key[KEYBYTES]);

int decrypt(uint8_t *m, const uint8_t tag[MACBYTES], const uint8_t *c,
            size_t c_len, const uint8_t *ad, size_t ad_len,
            const uint8_t nonce[NONCEBYTES], const uint8_t key[KEYBYTES]);

#endif
