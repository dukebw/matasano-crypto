#include "crypt_helper.h"

#define MESSAGE_SCRATCH_SIZE_BYTES 64

internal inline void
SimpleSrpGetHmacKSaltUnchecked(u8 *HmacKSalt, bignum *PremasterSecret, bignum *Salt)
{
    u8 K[SHA_1_HASH_LENGTH_BYTES];
    Sha1(K, (u8 *)PremasterSecret->Num, BigNumSizeBytesUnchecked(PremasterSecret));

    HmacSha1(HmacKSalt, K, sizeof(K), (u8 *)Salt->Num, BigNumSizeBytesUnchecked(Salt));
}

internal MIN_UNIT_TEST_FUNC(TestOfflineDictAttackSimplifiedSrp)
{
    /*
        S:      x = SHA256(salt|password)
                v = g**x % n

        C->S:   I, A = g**a % n

        S->C:   salt, B = g**b % n, u = 128 bit random number

        C:      x = SHA256(salt|password)
                S = B**(a + ux) % n
                K = SHA256(S)

        S:      S = (A * v ** u)**b % n
                K = SHA256(S)

        C->S:   Send HMAC-SHA256(K, salt)

        S->C:   Send "OK" if HMAC-SHA256(K, salt) validates
    */

    // LittleX calculated identically, so do it once
    u32 SaltSizeBytes = BigNumSizeBytesUnchecked((bignum *)&RFC_5054_TEST_SALT);
    u32 XMessageSizeBytes = SaltSizeBytes + STR_LEN(SRP_TEST_VEC_PASSWORD);

    u8 MessageScratch[MESSAGE_SCRATCH_SIZE_BYTES];
    Stopif(XMessageSizeBytes > sizeof(MessageScratch),
           "Buffer overflow in TestOfflineDictAttackSimplifiedSrp!\n");

    memcpy(MessageScratch, (u8 *)RFC_5054_TEST_SALT.Num, SaltSizeBytes);
    memcpy(MessageScratch + SaltSizeBytes, SRP_TEST_VEC_PASSWORD, STR_LEN(SRP_TEST_VEC_PASSWORD));

    bignum LittleX;
    u32 LittleXSizeDWords = SHA_1_HASH_LENGTH_BYTES/sizeof(u64) + 1;
    memset(LittleX.Num, 0, LittleXSizeDWords*sizeof(u64));

    Sha1((u8 *)LittleX.Num, MessageScratch, XMessageSizeBytes);
    LittleX.SizeWords = LittleXSizeDWords;

    bignum LittleU;
    u32 LittleUSize32BitWords = 128/BITS_IN_WORD;
    GenRandUnchecked((u32 *)LittleU.Num, LittleUSize32BitWords);
    LittleU.SizeWords = LittleUSize32BitWords/2;

    // Client
    // BigNumScratch := u*x
    bignum BigNumScratch;
    BigNumMultiplyOperandScanning(&BigNumScratch, &LittleU, &LittleX);

    // BigNumScratch := a + (u * x)
    BigNumAdd(&BigNumScratch, (bignum *)&RFC_5054_TEST_LITTLE_A, &BigNumScratch);

    // BigNumScratch := <premaster secret>
    MontModExpRBigNumMax(&BigNumScratch,
                         (bignum *)&RFC_5054_TEST_BIG_B,
                         &BigNumScratch,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

    u8 ClientHmacKSalt[SHA_1_HASH_LENGTH_BYTES];
    SimpleSrpGetHmacKSaltUnchecked(ClientHmacKSalt, &BigNumScratch, (bignum *)&RFC_5054_TEST_SALT);

    // Server
    bignum LittleV;
    MontModExpRBigNumMax(&LittleV,
                         (bignum *)&NIST_RFC_5054_GEN_BIGNUM,
                         &LittleX,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

    // BigNumScratch := v ** u
    MontModExpRBigNumMax(&BigNumScratch,
                         &LittleV,
                         &LittleU,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

    // BigNumScratch := A * v ** u % n
    BigNumMultiplyModP(&BigNumScratch,
                       (bignum *)&RFC_5054_TEST_BIG_A,
                       &BigNumScratch,
                       (bignum *)&RFC_5054_NIST_PRIME_1024);

    // BigNumScratch := <premaster secret>
    MontModExpRBigNumMax(&BigNumScratch,
                         &BigNumScratch,
                         (bignum *)&RFC_5054_TEST_LITTLE_B,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

    u8 ServerHmacKSalt[SHA_1_HASH_LENGTH_BYTES];
    SimpleSrpGetHmacKSaltUnchecked(ServerHmacKSalt, &BigNumScratch, (bignum *)&RFC_5054_TEST_SALT);

    MinUnitAssert(AreVectorsEqual(ServerHmacKSalt, ClientHmacKSalt, sizeof(ServerHmacKSalt)),
                  "Hmac mismatch in TestOfflineDictAttackSimplifiedSrp!\n");
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestOfflineDictAttackSimplifiedSrp);
}

int main()
{
	srand(time(0));
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
