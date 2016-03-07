#include "crypt_helper.h"

#define RSA_BROADCAST_PRIME_SIZE_BITS (MAX_BIGNUM_SIZE_BITS/8)

internal bignum *
BigNumMinTwoUnchecked(bignum *A, bignum *B)
{
    bignum *Result;
    if (IsALessThanOrEqualToB(A, B))
    {
        Result = A;
    }
    else
    {
        Result = B;
    }

    return Result;
}

internal bignum *
BigNumMinThreeUnchecked(bignum *A, bignum *B, bignum *C)
{
    bignum *Result = BigNumMinTwoUnchecked(A, BigNumMinTwoUnchecked(B, C));

    return Result;
}

/*
    Source: HAC, Section 14.2.5

    INPUT: positive integers x = (x_n ... x_1 x_0)_b , y = (y_t ... y_1 y_0)_b with n ≥ t ≥ 1, y_t != 0.
    OUTPUT: the quotient q = (q_n−t ... q_1 q_0)_b and remainder r = (r_t ... r_1 r_0)_b such that
    x = q*y + r, 0 ≤ r < y.

    1. For j from 0 to (n − t) do: q_j ←0.
    2. While (x ≥ y*b^n−t) do the following: q_n−t ← q_n−t + 1, x ← x − y*b^n−t.
    3. For i from n down to (t + 1) do the following:
        3.1 If x_i = y_t then set q_i−t−1 ← b − 1; otherwise set q_i−t−1 ← floor[(x_i*b + x_i−1)/y_t)].
        3.2 While (q_i−t−1*(y_t*b + y_t−1) > x_i*b^2 + x_i−1*b + x_i−2) do: q_i−t−1 ← q_i−t−1 − 1.
        3.3 x ← x − q_i−t−1*y*b^i−t−1 .
        3.4 If x < 0 then set x ← x + y*b^i−t−1 and q_i−t−1 ← q_i−t−1 − 1.
    4. r ← x.
    5. Return(q, r).
*/
internal void
BigNumDivide(bignum *Quotient, bignum *Remainder, bignum *Dividend, bignum *Divisor)
{
    Stopif((Quotient == 0) || (Remainder == 0) || (Dividend == 0) || (Divisor == 0),
           "Null input to BigNumDivide!\n");

    Stopif(IsEqualToZeroUnchecked(Divisor), "Divide by zero in BigNumDivide!\n");

    if (IsALessThan(Dividend, Divisor))
    {
        BigNumSetToZeroUnchecked(Quotient);

        BigNumCopyUnchecked(Remainder, Dividend);
    }
    else
    {
        u32 DivisorSizeBits = BigNumBitCountUnchecked(Divisor);
        u32 QuotientSizeBits = BigNumBitCountUnchecked(Dividend) - DivisorSizeBits;

        bignum LocalQuotient;
        LocalQuotient.Negative = false;
        memset(LocalQuotient.Num, 0, IntegerDivideCeiling(QuotientSizeBits, BITS_IN_BIGNUM_WORD)*BYTES_IN_BIGNUM_WORD);

        bignum DivisorUpshifted;
        DivisorUpshifted.Negative = false;
        u32 FloorQSizeDWords = QuotientSizeBits / BITS_IN_BIGNUM_WORD;
        u32 QSizeBitsModDWord = QuotientSizeBits % BITS_IN_BIGNUM_WORD;
        for (u32 DivisorIndex = 0;
             DivisorIndex < Divisor->SizeWords;
             ++DivisorIndex)
        {
            DivisorUpshifted.Num[FloorQSizeDWords + DivisorIndex] = Divisor->Num[DivisorIndex] << QSizeBitsModDWord;
            DivisorUpshifted.Num[FloorQSizeDWords + DivisorIndex + 1] = (Divisor->Num[DivisorIndex] >>
                                                                         (BITS_IN_BIGNUM_WORD - QSizeBitsModDWord));
        }
        DivisorUpshifted.SizeWords = FloorQSizeDWords + Divisor->SizeWords + 1;
        AdjustSizeWordsDownUnchecked(&DivisorUpshifted);

        bignum LocalDividend;
        BigNumCopyUnchecked(&LocalDividend, Dividend);

        if (IsAGreaterThanOrEqualToB(&LocalDividend, &DivisorUpshifted))
        {
            LocalQuotient.Num[FloorQSizeDWords - 1] = 1 << QSizeBitsModDWord;

            BigNumSubtract(&LocalDividend, &LocalDividend, &DivisorUpshifted);
        }

        for (u32 QuotientBitIndex = QuotientSizeBits;
             QuotientBitIndex > DivisorSizeBits;
             --QuotientBitIndex)
        {
            if (!(Dividend->Num[QuotientBitIndex/BITS_IN_BIGNUM_WORD] & (1 << (QuotientBitIndex % BITS_IN_BIGNUM_WORD))))
            {
#if 0
                LocalQuotient.Num[] |= 1 << ;
#endif
            }
        }

        BigNumCopyUnchecked(Quotient, &LocalQuotient);
    }
}

internal MIN_UNIT_TEST_FUNC(TestRsaBroadcastAttack)
{
    bignum PrimeN1;
    bignum PrimeN2;
    bignum PrimeN3;
    bignum *PrimeArray[] =
    {
        &PrimeN1,
        &PrimeN2,
        &PrimeN3,
    };

    GetRandPrime(&PrimeN1, RSA_BROADCAST_PRIME_SIZE_BITS);
    GetRandPrime(&PrimeN2, RSA_BROADCAST_PRIME_SIZE_BITS);
    GetRandPrime(&PrimeN3, RSA_BROADCAST_PRIME_SIZE_BITS);

    bignum N1N2N3;
    BigNumMultiplyOperandScanning(&N1N2N3, &PrimeN1, &PrimeN2);
    BigNumMultiplyOperandScanning(&N1N2N3, &N1N2N3, &PrimeN3);
    Stopif(N1N2N3.SizeWords >= MAX_BIGNUM_SIZE_WORDS, "N1N2N3 overflowed in TestRsaBroadcastAttack!\n");

    bignum Message;
    GenRandBigNumModNUnchecked(&Message, BigNumMinThreeUnchecked(&PrimeN1, &PrimeN2, &PrimeN3));

    bignum CrtResult;
    BigNumSetToZeroUnchecked(&CrtResult);

    bignum Three;
    InitTinyBigNumUnchecked(&Three, 3, false);

    // M1 := N1N2N3/N1
    u32 NumPrimes = ARRAY_LENGTH(PrimeArray);
    for (u32 PrimeIndex = 0;
         PrimeIndex < NumPrimes;
         ++PrimeIndex)
    {
        // 0 -> {1, 2}
        // 1 -> {0, 2}
        // 2 -> {0, 1}
        bignum Mi;
        BigNumMultiplyOperandScanning(&Mi,
                                      PrimeArray[(PrimeIndex + 1) % NumPrimes],
                                      PrimeArray[(PrimeIndex + 2) % NumPrimes]);

        Stopif(IsAGreaterThanOrEqualToB(&Mi, &N1N2N3), "Invalid NiNj >= N1N2N3 condition\n");

        bignum MiModNi;
        ReduceModP(&MiModNi, &Mi, PrimeArray[PrimeIndex]);

        bignum MiInverseModPrimeNi;
        Stopif(!GetInverseModN(&MiInverseModPrimeNi, &MiModNi, PrimeArray[PrimeIndex]),
               "Mi not inverted mod PrimeNi in TestRsaBroadcastAttack!");

        bignum Residue_i;
        MontModExpRBigNumMax(&Residue_i, &Message, &Three, PrimeArray[PrimeIndex]);

        bignum ProductMResidueMInv;
        BigNumMultiplyOperandScanning(&ProductMResidueMInv, &Mi, &Residue_i);

        Stopif(IsAGreaterThanOrEqualToB(&ProductMResidueMInv, &N1N2N3), "Invalid NiNj*c_k >= N1N2N3 condition\n");

        BigNumMultiplyModP(&ProductMResidueMInv, &ProductMResidueMInv, &MiInverseModPrimeNi, &N1N2N3);

        BigNumAddModN(&CrtResult, &CrtResult, &ProductMResidueMInv, &N1N2N3);
    }

    bignum ExpectedCubedResult;
    MontModExpRBigNumMax(&ExpectedCubedResult, &Message, &Three, &N1N2N3);

    MinUnitAssert(AreBigNumsEqualUnchecked(&ExpectedCubedResult, &CrtResult), "X^3 mismatch in TestRsaBroadcastAttack!\n");

    // Newton's method to get cubed root:
    // f(x) == 0, where f(x) == x^3 - A
    // x_k+1 == x_k - f(x_k)/f'(x_k)
    // => x_k+1 == x_k - (x_k^3 - A)/(3*x_k^2) == x_k - x_k/3 - A/3*x_k^2 == 1/3*(2*x_k - A/x_k^2)
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
    MinUnitRunTest(TestRsaBroadcastAttack);
}

int main()
{
    srand(time(0));
    AllTests();
    printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
