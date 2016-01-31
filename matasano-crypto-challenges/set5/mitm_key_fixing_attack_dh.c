#include "crypt_helper.h"

// Simulated server
global_variable u8 GlobalExchangeBuffer[sizeof(bignum)];

const char DH_MITM_TEST_MSG_A[] = "This is a Diffie-Hellman MITM attack.\n";
const char DH_MITM_TEST_MSG_B[] = "Use the code you just worked out to "
                                  "build a protocol and an \"echo\" bot.\n";

internal MIN_UNIT_TEST_FUNC(TestMitmKeyFixingAttack)
{
    // A -> B
    bignum A;
    GenRandBigNumModNUnchecked(&A, (bignum *)&NIST_RFC_3526_PRIME_1536);

    MontModExpRBigNumMax((bignum *)GlobalExchangeBuffer, (bignum *)&NIST_RFC_3526_GEN_BIGNUM, &A,
                         (bignum *)&NIST_RFC_3526_PRIME_1536);

    // B gets session key
    bignum B;
    GenRandBigNumModNUnchecked(&B, (bignum *)&NIST_RFC_3526_PRIME_1536);

    bignum SessionKeyB;
    MontModExpRBigNumMax(&SessionKeyB, (bignum *)GlobalExchangeBuffer, &B, (bignum *)&NIST_RFC_3526_PRIME_1536);

    // B -> A
    MontModExpRBigNumMax((bignum *)GlobalExchangeBuffer, (bignum *)&NIST_RFC_3526_GEN_BIGNUM, &B,
                         (bignum *)&NIST_RFC_3526_PRIME_1536);

    // A gets session key
    bignum SessionKeyA;
    MontModExpRBigNumMax(&SessionKeyA, (bignum *)GlobalExchangeBuffer, &A, (bignum *)&NIST_RFC_3526_PRIME_1536);

    MinUnitAssert(AreVectorsEqual(SessionKeyA.Num, SessionKeyB.Num,
                               sizeof(u64)*NIST_RFC_3526_PRIME_1536.SizeWords),
                  "SessionKey mismatch in TestMitmKeyFixingAttack!");

    // Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    u8 Message[sizeof(DH_MITM_TEST_MSG_A) + AES_128_BLOCK_LENGTH_BYTES];
    memcpy(Message, DH_MITM_TEST_MSG_A, sizeof(DH_MITM_TEST_MSG_A));

    u8 IvA[AES_128_BLOCK_LENGTH_BYTES];
    u8 SessionSymmetricKey[SHA_1_HASH_LENGTH_BYTES];
    HashSessionKeyGenIvAndEncrypt(GlobalExchangeBuffer, IvA, (u8 *)SessionKeyA.Num, sizeof(u64)*SessionKeyA.SizeWords,
                                  Message, STR_LEN(DH_MITM_TEST_MSG_A), SessionSymmetricKey);

    AesCbcDecrypt(Message, GlobalExchangeBuffer, STR_LEN(DH_MITM_TEST_MSG_A), SessionSymmetricKey, IvA);

    MinUnitAssert(AreVectorsEqual(Message, (u8 *)DH_MITM_TEST_MSG_A, STR_LEN(DH_MITM_TEST_MSG_A)),
                  "Message mismatch in TestMitmKeyFixingAttack!");

    // M -> B/A (sends fake p)
    BigNumCopyUnchecked((bignum *)GlobalExchangeBuffer, (bignum *)&NIST_RFC_3526_PRIME_1536);

    // B/A get fake session key
    MontModExpRBigNumMax(&SessionKeyA, (bignum *)GlobalExchangeBuffer, &A, (bignum *)&NIST_RFC_3526_PRIME_1536);

    Sha1(SessionSymmetricKey, (u8 *)SessionKeyA.Num, sizeof(u64)*SessionKeyA.SizeWords);

    u8 EveGuessedSymmetricKey[SHA_1_HASH_LENGTH_BYTES];
    Sha1(EveGuessedSymmetricKey, (u8 *)"", 0);

    MinUnitAssert(AreVectorsEqual(EveGuessedSymmetricKey, SessionSymmetricKey, SHA_1_HASH_LENGTH_BYTES),
                  "Guessed symmetric-key mismatch in TestMitmKeyFixingAttack!");
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestMitmKeyFixingAttack);
}

int main()
{
	srand(time(0));
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
