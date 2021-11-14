#include <stdio.h>
#include <time.h>
#include <string.h>
#include <openssl/bn.h>

void modular_exponentiation(BIGNUM *result, const BIGNUM *const_base, const BIGNUM *const_exponent, const BIGNUM *const_modulus)
{
    BIGNUM *two, *temp;
    BIGNUM *base, *exponent, *modulus;
    BN_CTX *ctx;
    if (BN_is_one(const_modulus))
    {
        BN_dec2bn(&result, "0");
        return;
    }
    BN_dec2bn(&result, "1");
    ctx = BN_CTX_new();
    two = BN_new();
    temp = BN_new();
    base = BN_new();
    exponent = BN_new();
    modulus = BN_new();
    BN_dec2bn(&two, "2");
    BN_copy(base, const_base);
    BN_copy(exponent, const_exponent);
    BN_copy(modulus, const_modulus);
    while (!BN_is_zero(exponent))
    {
        BN_div(NULL, temp, exponent, two, ctx);
        if (BN_is_one(temp))
        {
            BN_mul(result, result, base, ctx);
            BN_div(NULL, result, result, modulus, ctx);
        }
        BN_rshift1(exponent, exponent);
        BN_mul(base, base, base, ctx);
        BN_div(NULL, base, base, modulus, ctx);
    }
    BN_free(two);
    BN_free(temp);
    BN_CTX_free(ctx);
    return;
}

void chinese_remainder(BIGNUM *result, BIGNUM *base, BIGNUM *dP, BIGNUM *dQ, BIGNUM *qInv, BIGNUM *p, BIGNUM *q)
{
    BIGNUM *m1, *m2, *h, *temp;
    BN_CTX *ctx;
    m1 = BN_new();
    m2 = BN_new();
    h = BN_new();
    temp = BN_new();
    ctx = BN_CTX_new();

    modular_exponentiation(m1, base, dP, p);
    modular_exponentiation(m2, base, dQ, q);

    BN_sub(temp, m1, m2);
    BN_add(temp, temp, p);
    BN_mul(temp, qInv, temp, ctx);
    BN_div(NULL, h, temp, p, ctx);

    BN_mul(temp, h, q, ctx);
    BN_add(result, temp, m2);

    BN_free(m1);
    BN_free(m2);
    BN_free(h);
    BN_free(temp);
    BN_CTX_free(ctx);
    return;
}
int main(int argc, char *argv[])
{
    BIGNUM *n, *e, *d, *numeric_message, *result;
    BIGNUM *p, *q, *dP, *dQ, *qInv, *temp, *one;
    BN_CTX *ctx;
    char message[1000], *encrypted_message, decrypted_message[1000];
    struct timespec initial_time, final_time;
    n = BN_new();
    e = BN_new();
    d = BN_new();
    p = BN_new();
    q = BN_new();
    dP = BN_new();
    dQ = BN_new();
    qInv = BN_new();
    temp = BN_new();
    one = BN_new();
    ctx = BN_CTX_new();
    BN_dec2bn(&one, "1");
    numeric_message = BN_new();
    result = BN_new();
    BN_hex2bn(&p, "E0DFD2C2A288ACEBC705EFAB30E4447541A8C5A47A37185C5A9"
                  "CB98389CE4DE19199AA3069B404FD98C801568CB9170EB712BF"
                  "10B4955CE9C9DC8CE6855C6123");
    BN_hex2bn(&q, "EBE0FCF21866FD9A9F0D72F7994875A8D92E67AEE4B515136B2"
                  "A778A8048B149828AEA30BD0BA34B977982A3D42168F594CA99"
                  "F3981DDABFAB2369F229640115h");
    BN_hex2bn(&n, "CF33188211FDF6052BDBB1A37235E0ABB5978A45C71FD381A91"
                  "AD12FC76DA0544C47568AC83D855D47CA8D8A779579AB72E635"
                  "D0B0AAAC22D28341E998E90F82122A2C06090F43A37E0203C2B"
                  "72E401FD06890EC8EAD4F07E686E906F01B2468AE7B30CBD670"
                  "255C1FEDE1A2762CF4392C0759499CC0ABECFF008728D9A11ADF");
    BN_hex2bn(&e, "40B028E1E4CCF07537643101FF72444A0BE1D7682F1EDB553E3"
                  "AB4F6DD8293CA1945DB12D796AE9244D60565C2EB692A89B888"
                  "1D58D278562ED60066DD8211E67315CF89857167206120405B0"
                  "8B54D10D4EC4ED4253C75FA74098FE3F7FB751FF5121353C554"
                  "391E114C85B56A9725E9BD5685D6C9C7EED8EE442366353DC39");
    BN_hex2bn(&d, "C21A93EE751A8D4FBFD77285D79D6768C58EBF283743D2889A3"
                  "95F266C78F4A28E86F545960C2CE01EB8AD5246905163B28D0B"
                  "8BAABB959CC03F4EC499186168AE9ED6D88058898907E61C7CC"
                  "CC584D65D801CFE32DFC983707F87F5AA6AE4B9E77B9CE630E2"
                  "C0DF05841B5E4984D059A35D7270D500514891F7B77B804BED81");

    BN_sub(temp, p, one);
    BN_div(NULL, dP, d, temp, ctx);
    BN_sub(temp, q, one);
    BN_div(NULL, dQ, d, temp, ctx);
    BN_mod_inverse(qInv, q, p, ctx);

    printf("Enter message upto 1000 characters\n");
    scanf("%99[^\n]s", &message);

    BN_bin2bn(message, strlen(message), numeric_message);
    modular_exponentiation(result, numeric_message, e, n);
    encrypted_message = BN_bn2dec(result);
    printf("\nEncrypted message is: %s\n", encrypted_message);

    BN_dec2bn(&numeric_message, encrypted_message);

    clock_gettime(CLOCK_MONOTONIC, &initial_time);
    modular_exponentiation(result, numeric_message, d, n);
    BN_bn2bin(result, decrypted_message);
    printf("\nDecrypted message using direct modular exponentiation: %s\n", decrypted_message);
    clock_gettime(CLOCK_MONOTONIC, &final_time);
    printf("\n%d seconds, %d nanoseconds\n", (final_time.tv_sec - initial_time.tv_sec), (final_time.tv_nsec - initial_time.tv_nsec));

    clock_gettime(CLOCK_MONOTONIC, &initial_time);
    chinese_remainder(result, numeric_message, dP, dQ, qInv, p, q);
    BN_bn2bin(result, decrypted_message);
    printf("\nDecrypted message using chinese remainder theorem: %s\n", decrypted_message);
    clock_gettime(CLOCK_MONOTONIC, &final_time);
    printf("\n%d seconds, %d nanoseconds\n", (final_time.tv_sec - initial_time.tv_sec), (final_time.tv_nsec - initial_time.tv_nsec));

    OPENSSL_free(encrypted_message);
    OPENSSL_free(decrypted_message);
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(dP);
    BN_free(dQ);
    BN_free(qInv);
    BN_free(temp);
    BN_free(one);
    BN_free(numeric_message);
    BN_free(result);
    BN_CTX_free(ctx);
}