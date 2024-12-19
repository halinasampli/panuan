#ifndef SCRYPT_H
#define SCRYPT_H

#include <stdint.h>
#include <stddef.h>

void scrypt(const uint8_t *password, size_t password_len, const uint8_t *salt, size_t salt_len, uint32_t N, uint32_t r, uint32_t p, uint8_t *out, size_t out_len);

#endif