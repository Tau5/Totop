#include "include/totop.h"

#include <stdio.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define check_err(obj) if (obj == NULL) return TOTOP_ERROR;

const char* BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
EVP_MD_CTX* evp_md_ctx = NULL;

unsigned char* Totop_decode_base32(const char* input, int len, int* new_len) {
    int non_equal_letters = 0;
    for (int i = 0; i < len; i++) {
        if (input[i] != '=') non_equal_letters++;
    }

    int size = floor((double)(len) * 5.0 / 8.0);
    unsigned char* output = calloc(size, 1);

    if (new_len != NULL) {
        *new_len = size;
    }

    for (int i = 0; i < non_equal_letters; i++) {
        int byte_start = 5 * i / 8;
        int byte_offset = 5 * i % 8;
        int exceeds = 5 - (8 - byte_offset);
        if (exceeds < 0) exceeds = 0;
        for (int c = 0; c < 32; c++) {
            if (BASE32_ALPHABET[c] == input[i]) {
                if (exceeds > 0) {
                    output[byte_start] |= c >> exceeds;
                    output[byte_start + 1] |= c << (8 - exceeds);
                } else {
                    output[byte_start] |= c << 3 - byte_offset;
                }

            }
        }
    }

    return output;
}

unsigned int Totop_topt_get_counter(int interval) {
    return floor(((double) time(NULL) - 0) / interval);
}

unsigned int Totop_get_code(enum TotopCrypt crypt, const unsigned char* key, int keylength, uint64_t counter, int code_digits) {
#ifdef __DEBUG__
    printf("key: %s\n", key);

    printf("key hex: ");
    for (int i = 0; i < keylength; i++) {
        printf("%x", key[i]);
    }
    printf("\n");
#endif

    unsigned char ctr_bytes[8];
    for (int i = 7; i >= 0; i--) {
        ctr_bytes[i] = counter & 0xFF;
        counter >>= 8;
    }

    const EVP_MD* evp_md = NULL;

    switch (crypt) {
    case TOTOP_SHA1:
            evp_md = EVP_sha1();
        break;
    case TOTOP_SHA256:
            evp_md = EVP_sha256();
        break;
    case TOTOP_SHA512:
            evp_md = EVP_sha512();
        break;
    }

    const uint8_t* hmac = HMAC(evp_md, key, keylength, ctr_bytes,
        sizeof(unsigned char) * 8, NULL, 0);

    const int offset = hmac[19] & 0xf;
    unsigned int Sbits = (hmac[offset+3]  & 0xff)
       | (hmac[offset+2] & 0xff) << 8
       | (hmac[offset+1] & 0xff) << 16
       | (hmac[offset] & 0x7f) << 24 ;

    unsigned int result = Sbits % (int) (pow(10,code_digits));

#ifdef __DEBUG__
    for (int i = 0; i < 20; i++) {
        printf("%x", hmac[i]);
    }
    printf("\n");
    printf("sbits: %x\n", Sbits);
    printf("%u\n", result);
#endif

    return result;
}

