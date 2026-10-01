/* EdDSA key generation must return a key whose private part can be exported.
 *
 * For Ed25519 and Ed448:
 *  1. Known answer: import the RFC 8032 key pair (TEST 2 and "1 octet"), sign
 *     the RFC message; the signature must equal the RFC's and verify with the
 *     RFC public key.
 *  2. Generate a key pair, export its raw private and public values, import
 *     them into a second private key. Both keys must produce the same
 *     signature (EdDSA is deterministic) and it must verify with the exported
 *     public key.
 * With a FIPS wolfCrypt the private key is locked outside
 * PRIVATE_KEY_UNLOCK()/PRIVATE_KEY_LOCK(); a key generation that exports it
 * while locked fails with FIPS_PRIVATE_KEY_LOCKED_E.
 */
#include <stdio.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include "test_util.h"

struct eddsa_kat {
    const char *name;
    gnutls_ecc_curve_t curve;
    gnutls_pk_algorithm_t pk;
    gnutls_sign_algorithm_t sign;
    unsigned char priv[57];
    unsigned char pub[57];
    unsigned int key_len;
    unsigned char msg[1];
    unsigned char sig[114];
    unsigned int sig_len;
};

/* RFC 8032, section 7.1 TEST 2 and section 7.4 "1 octet". */
static const struct eddsa_kat kats[] = {
    {
        "Ed25519", GNUTLS_ECC_CURVE_ED25519, GNUTLS_PK_EDDSA_ED25519,
        GNUTLS_SIGN_EDDSA_ED25519,
        { 0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3,
          0x46, 0xec, 0x11, 0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab,
          0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb },
        { 0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a,
          0xa7, 0x4d, 0x1b, 0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4,
          0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c },
        32,
        { 0x72 },
        { 0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82,
          0x0b, 0x5f, 0x64, 0x25, 0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50,
          0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda, 0x08,
          0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f, 0x36, 0x13,
          0xd0, 0xf1, 0x1d, 0x8c, 0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a,
          0xee, 0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00 },
        64
    },
    {
        "Ed448", GNUTLS_ECC_CURVE_ED448, GNUTLS_PK_EDDSA_ED448,
        GNUTLS_SIGN_EDDSA_ED448,
        { 0xc4, 0xea, 0xb0, 0x5d, 0x35, 0x70, 0x07, 0xc6, 0x32, 0xf3, 0xdb,
          0xb4, 0x84, 0x89, 0x92, 0x4d, 0x55, 0x2b, 0x08, 0xfe, 0x0c, 0x35,
          0x3a, 0x0d, 0x4a, 0x1f, 0x00, 0xac, 0xda, 0x2c, 0x46, 0x3a, 0xfb,
          0xea, 0x67, 0xc5, 0xe8, 0xd2, 0x87, 0x7c, 0x5e, 0x3b, 0xc3, 0x97,
          0xa6, 0x59, 0x94, 0x9e, 0xf8, 0x02, 0x1e, 0x95, 0x4e, 0x0a, 0x12,
          0x27, 0x4e },
        { 0x43, 0xba, 0x28, 0xf4, 0x30, 0xcd, 0xff, 0x45, 0x6a, 0xe5, 0x31,
          0x54, 0x5f, 0x7e, 0xcd, 0x0a, 0xc8, 0x34, 0xa5, 0x5d, 0x93, 0x58,
          0xc0, 0x37, 0x2b, 0xfa, 0x0c, 0x6c, 0x67, 0x98, 0xc0, 0x86, 0x6a,
          0xea, 0x01, 0xeb, 0x00, 0x74, 0x28, 0x02, 0xb8, 0x43, 0x8e, 0xa4,
          0xcb, 0x82, 0x16, 0x9c, 0x23, 0x51, 0x60, 0x62, 0x7b, 0x4c, 0x3a,
          0x94, 0x80 },
        57,
        { 0x03 },
        { 0x26, 0xb8, 0xf9, 0x17, 0x27, 0xbd, 0x62, 0x89, 0x7a, 0xf1, 0x5e,
          0x41, 0xeb, 0x43, 0xc3, 0x77, 0xef, 0xb9, 0xc6, 0x10, 0xd4, 0x8f,
          0x23, 0x35, 0xcb, 0x0b, 0xd0, 0x08, 0x78, 0x10, 0xf4, 0x35, 0x25,
          0x41, 0xb1, 0x43, 0xc4, 0xb9, 0x81, 0xb7, 0xe1, 0x8f, 0x62, 0xde,
          0x8c, 0xcd, 0xf6, 0x33, 0xfc, 0x1b, 0xf0, 0x37, 0xab, 0x7c, 0xd7,
          0x79, 0x80, 0x5e, 0x0d, 0xbc, 0xc0, 0xaa, 0xe1, 0xcb, 0xce, 0xe1,
          0xaf, 0xb2, 0xe0, 0x27, 0xdf, 0x36, 0xbc, 0x04, 0xdc, 0xec, 0xbf,
          0x15, 0x43, 0x36, 0xc1, 0x9f, 0x0a, 0xf7, 0xe0, 0xa6, 0x47, 0x29,
          0x05, 0xe7, 0x99, 0xf1, 0x95, 0x3d, 0x2a, 0x0f, 0xf3, 0x34, 0x8a,
          0xb2, 0x1a, 0xa4, 0xad, 0xaf, 0xd1, 0xd2, 0x34, 0x44, 0x1c, 0xf8,
          0x07, 0xc0, 0x3a, 0x00 },
        114
    },
};

/* Sign msg with a private key built from raw values; verify with pub. */
static int sign_raw(const struct eddsa_kat *kat, const gnutls_datum_t *x,
    const gnutls_datum_t *k, gnutls_datum_t *sig)
{
    gnutls_privkey_t priv = NULL;
    gnutls_pubkey_t pub = NULL;
    gnutls_datum_t msg = { (unsigned char *)kat->msg, sizeof(kat->msg) };
    int ret;

    if ((ret = gnutls_privkey_init(&priv)) < 0 ||
        (ret = gnutls_privkey_import_ecc_raw(priv, kat->curve, x, NULL, k)) < 0 ||
        (ret = gnutls_privkey_sign_data2(priv, kat->sign, 0, &msg, sig)) < 0 ||
        (ret = gnutls_pubkey_init(&pub)) < 0 ||
        (ret = gnutls_pubkey_import_ecc_raw(pub, kat->curve, x, NULL)) < 0 ||
        (ret = gnutls_pubkey_verify_data2(pub, kat->sign, 0, &msg, sig)) < 0) {
        print_gnutls_error("importing, signing or verifying", ret);
        ret = 1;
    }
    else {
        ret = 0;
    }

    gnutls_pubkey_deinit(pub);
    gnutls_privkey_deinit(priv);
    return ret;
}

static int test_kat(const struct eddsa_kat *kat)
{
    gnutls_datum_t x = { (unsigned char *)kat->pub, kat->key_len };
    gnutls_datum_t k = { (unsigned char *)kat->priv, kat->key_len };
    gnutls_datum_t sig = { NULL, 0 };
    int ret;

    printf("\n=== %s: RFC 8032 known answer ===\n", kat->name);
    ret = sign_raw(kat, &x, &k, &sig);
    if (ret == 0) {
        ret = compare_sz("RFC 8032 signature", sig.data, sig.size, kat->sig,
            kat->sig_len);
    }
    gnutls_free(sig.data);
    return ret;
}

static int test_keygen_export(const struct eddsa_kat *kat)
{
    gnutls_privkey_t priv = NULL;
    gnutls_datum_t msg = { (unsigned char *)kat->msg, sizeof(kat->msg) };
    gnutls_datum_t x = { NULL, 0 }, k = { NULL, 0 };
    gnutls_datum_t sig = { NULL, 0 }, sig2 = { NULL, 0 };
    gnutls_ecc_curve_t curve;
    int ret;

    printf("\n=== %s: generate, export, re-import ===\n", kat->name);
    if ((ret = gnutls_privkey_init(&priv)) < 0 ||
        (ret = gnutls_privkey_generate2(priv, kat->pk, 0, 0, NULL, 0)) < 0 ||
        (ret = gnutls_privkey_export_ecc_raw2(priv, &curve, &x, NULL, &k,
            0)) < 0 ||
        (ret = gnutls_privkey_sign_data2(priv, kat->sign, 0, &msg,
            &sig)) < 0) {
        print_gnutls_error("generating, exporting or signing", ret);
        ret = 1;
    }
    else if (curve != kat->curve || x.size != kat->key_len ||
             k.size != kat->key_len) {
        printf("FAILURE - exported curve %d, public %u, private %u bytes\n",
            curve, x.size, k.size);
        ret = 1;
    }
    else {
        ret = sign_raw(kat, &x, &k, &sig2);
        if (ret == 0) {
            ret = compare_sz("signature by the re-imported key", sig2.data,
                sig2.size, sig.data, sig.size);
        }
    }

    gnutls_free(x.data);
    gnutls_free(k.data);
    gnutls_free(sig.data);
    gnutls_free(sig2.data);
    gnutls_privkey_deinit(priv);
    return ret;
}

int main(void)
{
    size_t i;
    int ret;

    printf("Testing EdDSA key generation and private key export...\n");

    ret = gnutls_global_init();
    if (ret != 0) {
        print_gnutls_error("initializing GnuTLS", ret);
        return 1;
    }

    if (gnutls_fips140_mode_enabled()) {
        printf("This test can be run only when FIPS140 mode is not enabled\n");
        gnutls_global_deinit();
        return 0;
    }

    for (i = 0; i < sizeof(kats) / sizeof(kats[0]); i++) {
        if (test_kat(&kats[i]) != 0 || test_keygen_export(&kats[i]) != 0) {
            gnutls_global_deinit();
            return 1;
        }
    }

    gnutls_global_deinit();
    printf("\nAll EdDSA key generation tests completed successfully!\n");
    return 0;
}
