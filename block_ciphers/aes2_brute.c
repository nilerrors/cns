/*
 * Brute force of double AES-128-ECB with two 20-bit keys, using the known
 * plaintext prefix "cns{" on the first promo-code block.
 *
 * Build (Linux / MinGW / macOS on x86):
 *   gcc -O3 -march=native -maes -fopenmp brute.c -o brute
 * Run:
 *   ./brute
 *
 * Requires an x86 CPU with AES-NI.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <omp.h>

#define N 1048576
#define NBLK 5

/* "cns{" as a little-endian 32-bit integer: 63 6e 73 7b */
#define PREFIX 0x7b736e63u

static const char *PROMO_HEX =
    "df7c7dfbd5e1ba2af108d658132d5f20d34de27da16375ceabd7a79cbfe73824"
    "4027a4a0b26ec498a2c223a545b9567c20bf423bb38514e6cd6f043ab9e23a84"
    "ffa6745294c224068e1cffd9e8c9e294";

static uint8_t ct[80];
static __m128i *M;
static volatile int found = 0;

static inline __m128i key_step(__m128i key, __m128i gen)
{
    gen = _mm_shuffle_epi32(gen, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, gen);
}

#define EXPAND(i, rc) \
    rk[i] = key_step(rk[(i) - 1], _mm_aeskeygenassist_si128(rk[(i) - 1], rc))

/* Build the decryption round keys for the key derived from the 20-bit value k */
static void dec_schedule(uint32_t k, __m128i dk[11])
{
    uint8_t key[16];
    __m128i rk[11];
    int i;

    memset(key, 0, 16);
    key[0] = (uint8_t)((k >> 16) & 0xff);
    key[1] = (uint8_t)((k >> 8) & 0xff);
    key[2] = (uint8_t)(k & 0xff);

    rk[0] = _mm_loadu_si128((const __m128i *)key);
    EXPAND(1, 0x01);
    EXPAND(2, 0x02);
    EXPAND(3, 0x04);
    EXPAND(4, 0x08);
    EXPAND(5, 0x10);
    EXPAND(6, 0x20);
    EXPAND(7, 0x40);
    EXPAND(8, 0x80);
    EXPAND(9, 0x1b);
    EXPAND(10, 0x36);

    dk[0] = rk[10];
    for (i = 1; i < 10; i++)
        dk[i] = _mm_aesimc_si128(rk[10 - i]);
    dk[10] = rk[0];
}

static inline __m128i dec_block(const __m128i dk[11], __m128i b)
{
    int r;
    b = _mm_xor_si128(b, dk[0]);
    for (r = 1; r < 10; r++)
        b = _mm_aesdec_si128(b, dk[r]);
    return _mm_aesdeclast_si128(b, dk[10]);
}

/* Full check of a candidate pair: decrypt all blocks and show the result */
static void check(int k1, int k2)
{
    __m128i d1[11], d2[11];
    uint8_t pt[80];
    int i, ok = 1;

    dec_schedule((uint32_t)k1, d1);
    dec_schedule((uint32_t)k2, d2);
    for (i = 0; i < NBLK; i++) {
        __m128i b = _mm_loadu_si128((const __m128i *)(ct + 16 * i));
        b = dec_block(d2, b); /* undo the second encryption first */
        b = dec_block(d1, b); /* then the first one */
        _mm_storeu_si128((__m128i *)(pt + 16 * i), b);
    }
    for (i = 0; i < 16; i++)
        if (pt[i] < 0x20 || pt[i] > 0x7e)
            ok = 0;
    if (!ok)
        return;

#pragma omp critical
    {
        if (!found) {
            printf("\nFOUND k1=%d k2=%d\n", k1, k2);
            for (i = 0; i < 80; i++)
                putchar((pt[i] >= 0x20 && pt[i] <= 0x7e) ? pt[i] : '.');
            printf("\n");
            fflush(stdout);
            found = 1;
        }
    }
}

int main(void)
{
    int i;
    long long done = 0;
    __m128i c0;

    if (strlen(PROMO_HEX) != 160) {
        fprintf(stderr, "bad hex length\n");
        return 1;
    }
    for (i = 0; i < 80; i++) {
        unsigned int v;
        sscanf(PROMO_HEX + 2 * i, "%2x", &v);
        ct[i] = (uint8_t)v;
    }

    printf("threads: %d\n", omp_get_max_threads());
    M = (__m128i *)_mm_malloc((size_t)N * sizeof(__m128i), 16);
    if (!M) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    c0 = _mm_loadu_si128((const __m128i *)ct);

    /* M[k2] = D_K2(first block) */
#pragma omp parallel for schedule(static)
    for (i = 0; i < N; i++) {
        __m128i dk[11];
        dec_schedule((uint32_t)i, dk);
        M[i] = dec_block(dk, c0);
    }
    printf("table built, searching...\n");
    fflush(stdout);

#pragma omp parallel for schedule(dynamic, 16)
    for (i = 0; i < N; i++) {
        __m128i dk[11];
        int k2, j, r;
        long long d;

        if (found)
            continue;
        dec_schedule((uint32_t)i, dk);

        for (k2 = 0; k2 < N; k2 += 8) {
            __m128i b[8];
            for (j = 0; j < 8; j++)
                b[j] = _mm_xor_si128(M[k2 + j], dk[0]);
            for (r = 1; r < 10; r++)
                for (j = 0; j < 8; j++)
                    b[j] = _mm_aesdec_si128(b[j], dk[r]);
            for (j = 0; j < 8; j++)
                b[j] = _mm_aesdeclast_si128(b[j], dk[10]);
            for (j = 0; j < 8; j++)
                if ((uint32_t)_mm_cvtsi128_si32(b[j]) == PREFIX)
                    check(i, k2 + j);
        }

#pragma omp atomic capture
        d = ++done;
        if (d % 8192 == 0) {
            printf("progress %lld / %d\n", d, N);
            fflush(stdout);
        }
    }

    if (!found)
        printf("done, nothing found\n");
    _mm_free(M);
    return 0;
}
