# Garoupe-256

Garoupe-256 is an **experimental** authenticated cipher with the following properties:
- 512 bit internal state, processing 128 input bit at a time
- 256 bit key
- 160 bit nonce
- 128 bit security level (if forgery is considered a successful attack)
- ARX-based
- Key commiting
- Compact and simple to implement
- Very fast on a wide range of 64 bit environments without AES acceleration, including WebAssembly

Unique (nonce, key) pairs are required for each message. Reuse with different messages would immediately disclose the difference between plaintexts and allow forgery. However, nonces can be randomly chosen with negligible collision probability.

## Benchmarks

WebAssembly (WAVM, vs non-fixsliced software AES)

```text
      garoupe-256:        907 MiB/s
       aegis-128l:        753 MiB/s
        aegis-256:        546 MiB/s
 chacha20Poly1305:        242 MiB/s
       aes128-ocb:        215 MiB/s
       aes128-gcm:        181 MiB/s
       aes256-ocb:        170 MiB/s
       aes256-gcm:        156 MiB/s
       gimli-aead:        114 MiB/s
        isapa128a:         93 MiB/s
```

Raspberry Pi 3 (vs non-fixsliced software AES)

```text
      garoupe-256:        152 MiB/s
 chacha20Poly1305:         69 MiB/s
       aegis-128l:         59 MiB/s
       aes128-ocb:         40 MiB/s
        aegis-256:         33 MiB/s
       aes256-ocb:         30 MiB/s
       gimli-aead:         28 MiB/s
        isapa128a:         21 MiB/s
       aes128-gcm:         18 MiB/s
       aes256-gcm:         16 MiB/s
```

## Specification, security analysis

TBD.
