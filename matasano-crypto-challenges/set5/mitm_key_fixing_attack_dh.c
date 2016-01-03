#include "crypt_helper.h"

// Simulated server
global_variable bignum ExchangeBuffer;

internal MIN_UNIT_TEST_FUNC(TestMitmKeyFixingAttack)
{
    // TODO(bwd): - compress MontModExpBigNumMaxR
    //            - MITM
    // A -> B
    bignum A;
    GenRandBigNumModNUnchecked(&A, (bignum *)&NIST_RFC_3526_PRIME_1536);

    MontModExp(&ExchangeBuffer, (bignum *)&NIST_RFC_3526_GEN_BIGNUM, &A, (bignum *)&NIST_RFC_3526_PRIME_1536,
               MAX_BIGNUM_SIZE_BITS);

    // B gets session key
    bignum B;
    GenRandBigNumModNUnchecked(&B, (bignum *)&NIST_RFC_3526_PRIME_1536);

    bignum SessionKeyB;
    MontModExp(&SessionKeyB, &ExchangeBuffer, &B, (bignum *)&NIST_RFC_3526_PRIME_1536, MAX_BIGNUM_SIZE_BITS);

    // B -> A
    MontModExp(&ExchangeBuffer, (bignum *)&NIST_RFC_3526_GEN_BIGNUM, &B, (bignum *)&NIST_RFC_3526_PRIME_1536,
               MAX_BIGNUM_SIZE_BITS);

    // A gets session key
    bignum SessionKeyA;
    MontModExp(&SessionKeyA, &ExchangeBuffer, &A, (bignum *)&NIST_RFC_3526_PRIME_1536, MAX_BIGNUM_SIZE_BITS);

    MinUnitAssert(VectorsEqual(SessionKeyA.Num, SessionKeyB.Num,
                               sizeof(u64)*NIST_RFC_3526_PRIME_1536.SizeWords),
                  "Mismatch in TestMitmKeyFixingAttack!");
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
