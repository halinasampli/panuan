#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sha256.h"
#include <time.h>

// Simulasi pekerjaan mining dengan header blok
void mine_block(const char *previous_hash, const char *merkle_root, uint32_t difficulty) {
    uint32_t version = 1; // Versi blok
    uint32_t timestamp = (uint32_t)time(NULL); // Waktu saat ini
    uint32_t bits = difficulty; // Target kesulitan
    uint32_t nonce = 0; // Nilai nonce dimulai dari 0

    char block_header[256];
    uint8_t hash[32];
    char hash_string[65];

    printf("Starting mining simulation...\n");

    while (1) {
        // Format header blok: Version + Previous Hash + Merkle Root + Timestamp + Bits + Nonce
        snprintf(block_header, sizeof(block_header), "%08x%s%s%08x%08x%08x",
                 version, previous_hash, merkle_root, timestamp, bits, nonce);

        // Hash header blok
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (uint8_t *)block_header, strlen(block_header));
        sha256_final(&ctx, hash);

        // Konversi hash ke string hexadecimal
        for (int i = 0; i < 32; ++i) {
            sprintf(hash_string + i * 2, "%02x", hash[i]);
        }
        hash_string[64] = '\0';

        // Periksa apakah hash memenuhi target (jumlah nol di depan)
        if (strncmp(hash_string, "0000", difficulty / 4) == 0) {
            printf("Block mined successfully!\n");
            printf("Hash: %s\n", hash_string);
            printf("Nonce: %u\n", nonce);
            printf("Block header: %s\n", block_header);
            break;
        }

        // Increment nonce
        nonce++;

        // Jika nonce melebihi batas, reset nonce dan update timestamp
        if (nonce == 0) {
            timestamp = (uint32_t)time(NULL);
        }
    }

    printf("Mining completed!\n");
}

int main() {
    // Simulasi data blok
    const char *previous_hash = "0000000000000000000abcdef1234567890abcdef1234567890abcdef1234567";
    const char *merkle_root = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    uint32_t difficulty = 16; // Target kesulitan (4 hex nol di depan)

    mine_block(previous_hash, merkle_root, difficulty);

    return 0;
}
