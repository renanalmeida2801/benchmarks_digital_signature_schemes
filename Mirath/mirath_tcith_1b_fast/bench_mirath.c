#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "clocks.h"
#include "rng.h"
#include "api.h"

/* ─────────────────────────────────────────────────────────────
 * CONFIGURAÇÃO DO BENCHMARK
 * Altere os dois defines abaixo e recompile.
 * ───────────────────────────────────────────────────────────── */

/* Escolha UMA das funções abaixo descomentando a linha desejada:
 *
 *   #define BENCH_FUNCTION KEYGEN
 *   #define BENCH_FUNCTION SIGN
 *   #define BENCH_FUNCTION VERIFY
 */
#define BENCH_FUNCTION VERIFY

/* Número de repetições — CLOCKS executa (BENCH * BENCH) vezes:
 *
 *   BENCH =   5 →     25 execuções  (rápido, menos preciso)
 *   BENCH =  10 →    100 execuções  (bom ponto de partida)
 *   BENCH =  50 →  2.500 execuções  (preciso)
 *   BENCH = 100 → 10.000 execuções  (muito preciso, mais lento)
 */
#define BENCH 200

/* ─────────────────────────────────────────────────────────────
 * Tokens internos — não altere.
 * Usados para comparação via #if abaixo.
 * ───────────────────────────────────────────────────────────── */
#define KEYGEN 1
#define SIGN   2
#define VERIFY 3

/* ─────────────────────────────────────────────────────────────
 * Buffers globais necessários para a macro CLOCKS.
 * CLOCKS expande o código inline em tempo de compilação,
 * portanto as variáveis precisam estar visíveis globalmente.
 * ───────────────────────────────────────────────────────────── */
static unsigned char pk[CRYPTO_PUBLICKEYBYTES];
static unsigned char sk[CRYPTO_SECRETKEYBYTES];
static unsigned char sm[CRYPTO_BYTES + 22];
static unsigned char m[22] = {
    0x52, 0x61, 0x6e, 0x6b, 0x20, 0x73, 0x59, 0x6e,
    0x64, 0x72, 0x6f, 0x6d, 0x65, 0x20, 0x44, 0x45,
    0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67
};
static unsigned long long mlen = 22;
static unsigned long long smlen = 0;

/* ─────────────────────────────────────────────────────────────
 * setup() — Inicializa RNG, gera par de chaves e assinatura
 * de referência. Necessário para SIGN e VERIFY funcionarem.
 * ───────────────────────────────────────────────────────────── */
static int setup(void) {
    unsigned char seed[48] = {0};
    randombytes_init(seed, NULL, 256);

    if (crypto_sign_keypair(pk, sk) != 0) {
        printf("[ERRO] crypto_sign_keypair falhou no setup.\n");
        return -1;
    }

    if (crypto_sign(sm, &smlen, m, mlen, sk) != 0) {
        printf("[ERRO] crypto_sign falhou no setup.\n");
        return -1;
    }

    return 0;
}

int main(void) {

    printf("===== BENCHMARK MIRATH =====\n");
    printf("BENCH                 : %d (%d execucoes)\n", BENCH, BENCH * BENCH);
    printf("CRYPTO_PUBLICKEYBYTES : %d bytes\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_SECRETKEYBYTES : %d bytes\n", CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_BYTES          : %d bytes\n\n", CRYPTO_BYTES);

    if (setup() != 0) return -1;

/* ─────────────────────────────────────────────────────────────
 * Seleção da função em tempo de compilação.
 * Apenas o bloco correspondente ao BENCH_FUNCTION definido
 * acima será compilado e executado.
 * ───────────────────────────────────────────────────────────── */
#if BENCH_FUNCTION == KEYGEN
    printf("Funcao: KeyGen (crypto_sign_keypair)\n\n");
    CLOCKS(crypto_sign_keypair(pk, sk));

#elif BENCH_FUNCTION == SIGN
    printf("Funcao: Sign (crypto_sign)\n\n");
    CLOCKS(crypto_sign(sm, &smlen, m, mlen, sk));

#elif BENCH_FUNCTION == VERIFY
    printf("Funcao: Verify (crypto_sign_open)\n\n");
    CLOCKS(crypto_sign_open(m, &mlen, sm, smlen, pk));

#else
    #error "BENCH_FUNCTION invalido. Use KEYGEN, SIGN ou VERIFY."
#endif

    return 0;
}
