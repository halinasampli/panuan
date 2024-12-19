#include "hmac.h"
#include "sha256.h"
#include <string.h>

void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out) {
    uint8_t o_key_pad[64], i_key_pad[64], temp_key[32], temp_hash[32];
    size_t i;

    if (key_len > 64) {
        sha256(key, key_len, temp_key);
        key = temp_key;
        key_len = 32;
    }

    memset(o_key_pad, 0x5c, 64);
    memset(i_key_pad, 0x36, 64);

    for (i = 0; i < key_len; i++) {
        o_key_pad[i] ^= key[i];
        i_key_pad[i] ^= key[i];
    }

    sha256(i_key_pad, 64, temp_hash);
    memcpy(temp_hash + 32, data, data_len);
    sha256(temp_hash, 64 + data_len, out);
}
