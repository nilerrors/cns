// Brute force of double AES-128-ECB with two 20-bit keys.
//
// Uses OpenSSL's modern EVP interface instead of the deprecated AES_* calls.
//
// Build (Linux, and macOS with OpenSSL installed via brew):
//   g++ -O3 -fopenmp aes2_brute.cpp -o aes2_brute -lcrypto
// Run:
//   ./aes2_brute

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <array>
#include <string>
#include <openssl/evp.h>

static const int N = 1 << 20;              // 2^20 possible values per key

static std::vector<uint8_t> hex_to_bytes(const std::string &hex)
{
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); i++)
        sscanf(hex.c_str() + 2 * i, "%2hhx", &out[i]);
    return out;
}

// Turn a 20-bit integer into the 16-byte key format the challenge uses:
// 3 key bytes followed by 13 zero bytes.
static void make_key(uint32_t k, uint8_t key[16])
{
    std::memset(key, 0, 16);
    key[0] = (k >> 16) & 0xff;
    key[1] = (k >> 8) & 0xff;
    key[2] = k & 0xff;
}

// Set up an ECB decryption context for one key. The caller owns the
// returned context and must free it with EVP_CIPHER_CTX_free.
static EVP_CIPHER_CTX *make_ecb_ctx(const uint8_t key[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // raw fixed-size blocks, no PKCS7 padding
    return ctx;
}

// Decrypt `nblocks` 16-byte blocks in one call. ECB has no chaining between
// blocks, so this works for any number of blocks at once, not just one.
static void ecb_decrypt(EVP_CIPHER_CTX *ctx, const uint8_t *in, uint8_t *out, int nblocks)
{
    int outlen = 0;
    EVP_DecryptUpdate(ctx, out, &outlen, in, nblocks * 16);
}

int main()
{
    std::string promo_hex =
        "df7c7dfbd5e1ba2af108d658132d5f20d34de27da16375ceabd7a79cbfe738244"
        "027a4a0b26ec498a2c223a545b9567c20bf423bb38514e6cd6f043ab9e23a84ff"
        "a6745294c224068e1cffd9e8c9e294";
    std::vector<uint8_t> ct = hex_to_bytes(promo_hex);
    int nblocks = (int)ct.size() / 16;
    printf("ciphertext blocks: %d\n", nblocks);

    // Step 1: decrypt the FIRST block of the ciphertext with every possible
    // K2, and remember the result. This is the "backward" half of the
    // meet-in-the-middle search.
    printf("building table for all 2^20 values of k2...\n");
    std::vector<std::array<uint8_t, 16>> table(N);

    #pragma omp parallel for schedule(static)
    for (int k2 = 0; k2 < N; k2++) {
        uint8_t key[16];
        make_key((uint32_t)k2, key);
        EVP_CIPHER_CTX *ctx = make_ecb_ctx(key);
        ecb_decrypt(ctx, ct.data(), table[k2].data(), 1);
        EVP_CIPHER_CTX_free(ctx);
    }
    printf("table built, searching over k1...\n");

    volatile bool found = false;

    // Step 2: for every possible K1, decrypt every table entry a second
    // time and see if the result starts with "cns{". That is the forward
    // half of the search. The whole table is decrypted in one EVP call per
    // k1, which is much faster than calling it 2^20 times per k1.
    #pragma omp parallel for schedule(dynamic, 64)
    for (int k1 = 0; k1 < N; k1++) {
        if (found) continue;

        uint8_t key[16];
        make_key((uint32_t)k1, key);
        EVP_CIPHER_CTX *ctx = make_ecb_ctx(key);

        std::vector<uint8_t> mids(16 * N);
        ecb_decrypt(ctx, reinterpret_cast<const uint8_t *>(table.data()), mids.data(), N);

        for (int k2 = 0; k2 < N; k2++) {
            uint8_t *mid = &mids[16 * k2];
	    bool all_ascii = true;
	    for (int i = 0; i < 16; i++) {
		if (mid[i] < 32 || mid[i] >= 127) {
		    all_ascii = false;
		    break;
		}
	    }
            if (all_ascii && mid[0] == 'c' && mid[1] == 'n' && mid[2] == 's' && mid[3] == '{') {
                #pragma omp critical
                {
                    if (!found) {
                        found = true;
                        printf("\nfound k1 = %d, k2 = %d\n", k1, k2);

                        // Decrypt the WHOLE ciphertext with these two keys
                        // and print it.
                        uint8_t key2[16];
                        make_key((uint32_t)k2, key2);
                        EVP_CIPHER_CTX *ctx2 = make_ecb_ctx(key2);

                        std::vector<uint8_t> tmp(ct.size()), out(ct.size());
                        ecb_decrypt(ctx2, ct.data(), tmp.data(), nblocks);   // undo 2nd encryption
                        ecb_decrypt(ctx, tmp.data(), out.data(), nblocks);   // undo 1st encryption

                        printf("flag: %.*s\n", (int)out.size(), out.data());
                        EVP_CIPHER_CTX_free(ctx2);
                    }
                }
                break;
            }
        }

        EVP_CIPHER_CTX_free(ctx);

        if (k1 % 4096 == 0)
            printf("progress: k1 = %d / %d\n", k1, N);
    }

    if (!found)
        printf("no match found, double check the plaintext prefix and promo hex\n");

    return 0;
}

