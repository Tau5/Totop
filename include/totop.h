#ifndef TOTOP_LIBRARY_H
#define TOTOP_LIBRARY_H
#include <bits/stdint-uintn.h>

enum TotopCrypt {
    TOTOP_SHA1 = 0,
    TOTOP_SHA256 = 1,
    TOTOP_SHA512 = 2,
};

/** Generates OTP code for given key/counter pair
 *
 * @param crypt     Hash function to use (TOTOP_SHA1, _SHA256 or _SHA512)
 * @param key       Pointer to key
 * @param keylength length of pointer in bytes
 * @param counter   HOTP counter
 * @param code_digits     Digits in output code
 *
 * @returns HOTP code
 */
unsigned int Totop_get_code(enum TotopCrypt crypt, const unsigned char* key, int keylength, uint64_t counter, int code_digits);

/** Decodes input from base32
 *
 * @param input     String to decode
 * @param len       Length of input
 * @param new_len   Pointer to write length of output (can be NULL)
 *
 * @returns Pointer to decoded string (must be freed!)
 */
unsigned char* Totop_decode_base32(const char* input, int len, int* new_len);

/** Returns the TOTP counter for the given interval
 *
 * @param interval seconds between code regeneration
 *
 * @returns counter
 */
unsigned int Totop_topt_get_counter(int interval);

#endif //TOTOP_LIBRARY_H