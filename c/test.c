
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "garoupe-256.h"

int
main(void)
{
    uint8_t key[KEYBYTES];
    uint8_t nonce[NONCEBYTES];
    uint8_t ad[20];
    uint8_t m[100];

    memset(key, 0x01, sizeof key);
    memset(nonce, 0x02, sizeof nonce);
    memset(ad, 0x03, sizeof ad);
    memset(m, 0x04, sizeof m);

    uint8_t c[100];
    uint8_t tag[MACBYTES];
    encrypt(c, tag, m, sizeof m, ad, sizeof ad, nonce, key);

    uint8_t m2[100];
    if (decrypt(m2, tag, c, sizeof c, ad, sizeof ad, nonce, key) != 0) {
        puts("Authentication failed");
    }
    if (memcmp(m, m2, sizeof m) != 0) {
        puts("Decryption failed");
    }

    char   hex[100 * 2 + 1];
    size_t i;
    for (i = 0; i < sizeof c; i++) {
        snprintf(hex + i * 2, 3, "%02x", c[i]);
    }
    const char *expected_c =
        "9ebd0cba7f8e8f2248e724d536558926497724bbaf9f7e2c488c571916de00b12e9712"
        "313732c9bdcf4adb4ca1508660190757ea6fcf0476b8312696e8236cc706d46ce95aa2"
        "1fbe7cc52a88233b343a86f5ef16b2ebe6ae1849ad2c7a9cb03cabaf95b4";
    if (strcmp(hex, expected_c) != 0) {
        puts("Unexpected ciphertext");
    }

    for (i = 0; i < sizeof tag; i++) {
        snprintf(hex + i * 2, 3, "%02x", tag[i]);
    }
    const char *expected_tag = "46d8e9c4c9da3aef2bb9f484f965b320";
    if (strcmp(hex, expected_tag) != 0) {
        puts("Unexpected tag");
    }

    return 0;
}
