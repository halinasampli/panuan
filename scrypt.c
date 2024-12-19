#include "scrypt.h"
#include "pbkdf2.h"
#include <stdlib.h>
#include <string.h>

static void xor_salsa8(uint32_t B[16]) {
    int i;
    uint32_t x[16];

    memcpy(x, B, sizeof(x));
    for (i = 0; i < 8; i += 2) {
        x[4] ^= (x[0] + x[12]) << 7 | (x[0] + x[12]) >> (32 - 7);
        x[8] ^= (x[4] + x[0]) << 9 | (x[4] + x[0]) >> (32 - 9);
        x[12] ^= (x[8] + x[4]) << 13 | (x[8] + x[4]) >> (32 - 13);
        x[0] ^= (x[12] + x[8]) << 18 | (x[12] + x[8]) >> (32 - 18);
        x[9] ^= (x[5] + x[1]) << 7 | (x[5] + x[1]) >> (32 - 7);
        x[13] ^= (x[9] + x[5]) << 9 | (x[9] + x[5]) >> (32 - 9);
        x[1] ^= (x[13] + x[9]) << 13 | (x[13] + x[9]) >> (32 - 13);
        x[5] ^= (x[1] + x[13]) << 18 | (x[1] + x[13]) >> (32 - 18);
        x[14] ^= (x[10] + x[6]) << 7 | (x[10] + x[6]) >> (32 - 7);
        x[2] ^= (x[14] + x[10]) << 9 | (x[14] + x[10]) >> (32 - 9);
        x[6] ^= (x[2] + x[14]) << 13 | (x[2] + x[14]) >> (32 - 13);
        x[10] ^= (x[6] + x[2]) << 18 | (x[6] + x[2]) >> (32 - 18);
        x[3] ^= (x[15] + x[11]) << 7 | (x[15] + x[11]) >> (32 - 7);
        x[7] ^= (x[3] + x[15]) << 9 | (x[3] + x[15]) >> (32 - 9);
        x[11] ^= (x[7] + x[3]) << 13 | (x[7] + x[3]) >> (32 - 13);
        x[15] ^= (x[11] + x[7]) << 18 | (x[11] + x[7]) >> (32 - 18);

        x[1] ^= (x[0] + x[3]) << 7 | (x[0] + x[3]) >> (32 - 7);
        x[2] ^= (x[1] + x[0]) << 9 | (x[1] + x[0]) >> (32 - 9);
        x[3] ^= (x[2] + x[1]) << 13 | (x[2] + x[1]) >> (32 - 13);
        x[0] ^= (x[3] + x[2]) << 18 | (x[3] + x[2]) >> (32 - 18);
        x[6] ^= (x[5] + x[4]) << 7 | (x[5] + x[4]) >> (32 - 7);
        x[7] ^= (x[6] + x[5]) << 9 | (x[6] + x[5]) >> (32 - 9);
        x[4] ^= (x[7] + x[6]) << 13 | (x[7] + x[6]) >> (32 - 13);
        x[5] ^= (x[4] + x[7]) << 18 | (x[4] + x[7]) >> (32 - 18);
        x[11] ^= (x[10] + x[9]) << 7 | (x[10] + x[9]) >> (32 - 7);
        x[8] ^= (x[11] + x[10]) << 9 | (x[11] + x[10]) >> (32 - 9);
        x[9] ^= (x[8] + x[11]) << 13 | (x[8] + x[11]) >> (32 - 13);
        x[10] ^= (x[9] + x[8]) << 18 | (x[9] + x[8]) >> (32 - 18);
        x[12] ^= (x[15] + x[14]) << 7 | (x[15] + x[14]) >> (32 - 7);
        x[13] ^= (x[12] + x[15]) << 9 | (x[12] + x[15]) >> (32 - 9);
        x[14] ^= (x[13] + x[12]) << 13 | (x[13] + x[12]) >> (32 - 13);
        x[15] ^= (x[14] + x[13]) << 18 | (x[14] + x[13]) >> (32 - 18);
    }
    memcpy(B, x, sizeof(x));
}

static void blockmix_salsa8(uint32_t *B, uint32_t *Y, size_t r) {
    size_t i, j;
    uint32_t X[16];

    memcpy(X, &B[(2 * r - 1) * 16], 64);
    for (i = 0; i < 2 * r; i++) {
        for (j = 0; j < 16; j++)
            X[j] ^= B[i * 16 + j];
        xor_salsa8(X);
        memcpy(&Y[i * 16], X, 64);
    }

    for (i = 0; i < r; i++) {
        memcpy(&B[i * 16], &Y[(i * 2) * 16], 64);
        memcpy(&B[(i + r) * 16], &Y[(i * 2 + 1) * 16], 64);
    }
}

void scrypt(const uint8_t *password, size_t password_len, const uint8_t *salt, size_t salt_len, uint32_t N, uint32_t r, uint32_t p, uint8_t *out, size_t out_len) {
    size_t i, j, B_len = 128 * r * p;
    uint32_t *B = malloc(B_len);
    uint32_t *V = malloc(128 * r * N);
    uint32_t *Y = malloc(128 * r);
    uint32_t *X;

    if (!B || !V || !Y) {
        free(B);
        free(V);
        free(Y);
        return;
    }

    pbkdf2_hmac_sha256(password, password_len, salt, salt_len, 1, (uint8_t *)B, B_len);

    for (i = 0; i < p; i++) {
        X = &B[i * 32 * r];
        for (j = 0; j < N; j++) {
            memcpy(&V[j * 32 * r], X, 128 * r);
            blockmix_salsa8(X, Y, r);
        }

        for (j = 0; j < N; j++) {
            uint32_t k = X[16 * r - 1] % N;
            for (size_t m = 0; m < 32 * r; m++)
                X[m] ^= V[k * 32 * r + m];
            blockmix_salsa8(X, Y, r);
        }
    }

    pbkdf2_hmac_sha256(password, password_len, (uint8_t *)B, B_len, 1, out, out_len);

    free(B);
    free(V);
    free(Y);
}
