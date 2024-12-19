#include "pbkdf2.h"
#include "hmac.h"
#include <string.h>

void pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len, const uint8_t *salt, size_t salt_len, uint32_t iterations, uint8_t *out, size_t out_len) {
    uint8_t block[32], temp[32], count[4];
    uint32_t i, j, k;

    for (i = 1; out_len > 0; ++i, out_len -= 32) {
        count[0] = (i >> 24) & 0xff;
        count[1] = (i >> 16) & 0xff;
        count[2] = (i >> 8) & 0xff;
        count[3] = i & 0xff;

        hmac_sha256(password, password_len, salt, salt_len, block);
        memcpy(temp, block, 32);

        for (j = 1; j < iterations; ++j) {
            hmac_sha256(password, password_len, temp, 32, temp);
            for (k = 0; k < 32; ++k)
                block[k] ^= temp[k];
        }

        memcpy(out, block, (out_len < 32) ? out_len : 32);
        out += 32;
    }
}
