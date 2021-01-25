#include <os.h>
#include "globals.h"
#include "printf.h"
#include "hedera.h"

void hedera_derive_keypair(
    uint32_t index,
    /* out */ cx_ecfp_private_key_t *secret,
    /* out */ cx_ecfp_public_key_t *public)
{
    static uint8_t seed[32];
    static uint32_t path[5];
    static cx_ecfp_private_key_t pk;

    path[0] = 44 | 0x80000000;
    path[1] = 3030 | 0x80000000;
    path[2] = 0x80000000;
    path[3] = 0x80000000;
    path[4] = index | 0x80000000;

    os_perso_derive_node_bip32_seed_key(
        HDW_ED25519_SLIP10,
        CX_CURVE_Ed25519,
        path,
        5,
        seed,
        NULL,
        NULL,
        0);

    cx_ecfp_init_private_key(
        CX_CURVE_Ed25519,
        seed,
        sizeof(seed),
        &pk);

    if (public)
    {
        cx_ecfp_init_public_key(
            CX_CURVE_Ed25519,
            NULL,
            0,
            public);
        cx_ecfp_generate_pair(
            CX_CURVE_Ed25519,
            public,
            &pk,
            1);
    }

    if (secret)
    {
        *secret = pk;
    }

    os_memset(seed, 0, sizeof(seed));
    os_memset(&pk, 0, sizeof(pk));
}

void hedera_sign(
    uint32_t index,
    const uint8_t *tx,
    uint8_t tx_len,
    /* out */ uint8_t *result)
{
    static cx_ecfp_private_key_t pk;

    // Get Keys
    hedera_derive_keypair(index, &pk, NULL);

    // Sign Transaction
    // <cx.h> 2283
    // Claims to want Hashes, but other apps use the message itself
    // and complain that the documentation is wrong
    cx_eddsa_sign(
        &pk,       // private key
        0,         // mode (UNSUPPORTED)
        CX_SHA512, // hashID
        tx,        // hash (really message)
        tx_len,    // hash length (really message length)
        NULL,      // context (UNUSED)
        0,         // context length (0)
        result,    // signature
        64,        // signature length
        NULL       // info
    );

    // Clear private key
    os_memset(&pk, 0, sizeof(pk));
}

int ipow(int base, int exp)
{
    int result = 1;
    while (exp)
    {
        if (exp % 2)
            result *= base;
        exp /= 2;
        base *= base;
    }
    return result;
}

char *hedera_format_tinybar(uint64_t tinybar)
{
    return hedera_format_amount(tinybar, 8);
}

char *hedera_format_amount(uint64_t amount, uint8_t decimals)
{
    static const int BUF_SIZE = 32;
    static const int FMT_SIZE = 10;
    static char buf[BUF_SIZE];
    static char fmt[FMT_SIZE];

    os_memset(buf, '\0', BUF_SIZE);
    os_memset(fmt, '\0', FMT_SIZE);

    int factor = ipow(10, decimals);
    uint64_t whole = amount / factor;
    uint64_t frac = amount % factor;

    int cnt = hedera_snprintf(buf, BUF_SIZE, "%llu", whole);

    if (frac != 0)
    {
        int fmt_cnt = hedera_snprintf(fmt, FMT_SIZE, ".%%.%dllu", decimals);
        fmt[fmt_cnt] = '\0';
        cnt += hedera_snprintf(buf + cnt, BUF_SIZE - cnt, fmt, frac);
    }

    buf[cnt] = '\0';
    return buf;
}