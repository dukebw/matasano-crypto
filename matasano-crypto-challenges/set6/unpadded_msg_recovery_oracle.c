#include "crypt_helper.h"

internal MIN_UNIT_TEST_FUNC(TestUnpaddedMsgRecoveryOracle)
{
    // C' = ((S**E mod N) C) mod N
    //          P'
    // => P = -----  mod N
    //          S
    bignum PublicExponentE;
    InitTinyBigNumUnchecked(&PublicExponentE, 3, false);

    bignum ModulusN;
    bignum PrivateKeyD;
    GenerateRsaKeyPair(&PrivateKeyD, &ModulusN, &PublicExponentE, MAX_BIGNUM_SIZE_BITS/8);

    bignum Plaintext;
    GenRandBigNumModNUnchecked(&Plaintext, &ModulusN);

    bignum S;
    GenRandBigNumModNUnchecked(&S, &ModulusN);

    // TempBigNum := S**E mod N
    bignum TempBigNum;
    MontModExpRBigNumMax(&TempBigNum, &S, &PublicExponentE, &ModulusN);

    // Ciphertext := C
    bignum Ciphertext;
    MontModExpRBigNumMax(&Ciphertext, &Plaintext, &PublicExponentE, &ModulusN);

    // TempBigNum := ((S**E mod N) C) mod N
    BigNumMultiplyModP(&TempBigNum, &TempBigNum, &Ciphertext, &ModulusN);

    // TempBigNum := P'
    MontModExpRBigNumMax(&TempBigNum, &TempBigNum, &PrivateKeyD, &ModulusN);

    // S := S^-1 mod N
    Stopif(!GetInverseModN(&S, &S, &ModulusN), "No inverse mod N in TestUnpaddedMsgRecoveryOracle!\n");

    // TempBigNum := P'*S^-1 mod N
    BigNumMultiplyModP(&TempBigNum, &TempBigNum, &S, &ModulusN);

    MinUnitAssert(AreBigNumsEqualUnchecked(&TempBigNum, &Plaintext),
                  "Plaintext not recovered in TestUnpaddedMsgRecoveryOracle!\n");
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
    MinUnitRunTest(TestUnpaddedMsgRecoveryOracle);
}

int main()
{
    srand(time(0));
    AllTests();
    printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
