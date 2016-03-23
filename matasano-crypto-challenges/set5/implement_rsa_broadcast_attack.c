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

internal u64
ShiftLeftUnchecked(bignum *BigNum, u32 ShiftAmountBits)
{
    u64 PrevWord = 0;
    u64 NextWord;
    for (u32 BigNumIndex = 0;
         BigNumIndex < BigNum->SizeWords;
         ++BigNumIndex)
    {
        NextWord = BigNum->Num[BigNumIndex] >> ShiftAmountBits;
        BigNum->Num[BigNumIndex] = (BigNum->Num[BigNumIndex] << ShiftAmountBits) | PrevWord;
        PrevWord = NextWord;
    }

    return PrevWord;
}

/*
    Source: TAOCP 4.3.1 Algorithm D

    D1. [Normalize.] Set d <- floor[(b - l)/v_n-1]. Then set (u_m+n u_m+n-i ... u_1 u_0)_b
        equal to (u_m+n-1 ... u_1 u_0)_b times d; similarly, set (v_n-1 ... v_1 v_0)_b equal to
        (v_n-1 ... v_1 v_0)_b times d.

    D2. [Initialize j] Set j <- m. (The loop on j, steps D2 through D7, will be
        essentially a division of (u_j+n ... u_j+1 u_j)_b by (v_n-1 ... v_1 v_0)_b to get a single
        quotient digit q_j.

    D3. [Calculate q.] Set q <- floor[((u_j+n)*b + u_j+n-1)/v_n-1] and let r' be the remainder,
        ((u_j+n)*b + u_j+n-1) mod v_n-1. Now test if q' = b or q'*v_n-2 > b*r' + u_j+n-2; if
        so, decrease q' by 1, increase r' by v_n-1, and repeat this test if r' < b.

    D4. [Multiply and subtract.] Replace (u_j+n u_j+n-1 ... u_j)_b by

            (u_j+n u_j+n-1 ... u_j)_b - q'*(v_n-1 ... v_1 v_0)_b

        This computation (analogous to steps M3, M4, and M5 of Algorithm M)
        consists of a simple multiplication by a one-place number, combined with
        a subtraction. The digits (u_j+n, u_j+n-1, ..., u_j) should be kept positive; if
        the result of this step is actually negative, (u_n+j u_j+n-1 ... u_j)_b should be
        left as the true value plus b^n+1, namely as the b's complement of the true
        value, and a "borrow" to the left should be remembered.

    D5. [Test remainder.] Set q_j <- q'. If the result of step D4 was negative, go to
        step D6; otherwise go on to step D7.

    D6. [Add back.] (The probability that this step is necessary is very small, on
        the order of only 2/b, as shown in exercise 21; test data to activate this
        step should therefore be specifically contrived when debugging.) Decrease
        q_j by 1, and add (0 v_n-1 ... v_1 v_0)_b to (u_n+j u_j+n-1 ... u_j+1 u_j)_b. (A carry
        will occur to the left of u_j+n, and it should be ignored since it cancels with
        the borrow that occurred in D4.)

    D7. [Loop on j] Decrease j by one. Now if j >= 0, go back to D3.

    D8. [Unnormalize.] Now (q_m ... q_1 q_0)_b is the desired quotient, and the desired
        remainder may be obtained by dividing (u_n-1 ... u_1 u_0)_b by d.
*/
internal void
BigNumDivide(bignum *Quotient, bignum *Remainder, bignum *DividendX, bignum *DivisorY)
{
    Stopif((Quotient == 0) || (Remainder == 0) || (DividendX == 0) || (DivisorY == 0),
           "Null input to BigNumDivide!\n");

    Stopif(IsEqualToZeroUnchecked(DivisorY), "Divide by zero in BigNumDivide!\n");

    if (IsALessThan(DividendX, DivisorY))
    {
        BigNumSetToZeroUnchecked(Quotient);

        BigNumCopyUnchecked(Remainder, DividendX);
    }
    else
    {
        Stopif((DivisorY->Num[DivisorY->SizeWords - 1] == 0) || (DividendX->Num[DividendX->SizeWords - 1] == 0),
               "Invalid SizeWords input to BigNumDivide!\n");

        bignum LocalDividendX;
        BigNumCopyUnchecked(&LocalDividendX, DividendX);

        bignum LocalDivisorY;
        BigNumCopyUnchecked(&LocalDivisorY, DivisorY);

        u32 DivisorLeadingZeros = __builtin_clzl(DivisorY->Num[DivisorY->SizeWords - 1]);

        u64 DividendShiftCarry = ShiftLeftUnchecked(&LocalDividendX, DivisorLeadingZeros);
        LocalDividendX.Num[LocalDividendX.SizeWords] = DividendShiftCarry;
        ++LocalDividendX.SizeWords;
        // NOTE(brendan): LocalDividendX.Num[LocalDividendX.SizeWords - 1] == u_m+n may be zero at this point

        u64 DivisorShiftCarry = ShiftLeftUnchecked(&LocalDivisorY, DivisorLeadingZeros);
        Stopif(DivisorShiftCarry, "DivisorY must shift to 0 in !\n");
        Stopif(!(LocalDivisorY.Num[LocalDivisorY.SizeWords - 1] & (1ull << 63)),
               "v_n-1 not >= b/2 in BigNumDivide!\n");

        bignum LocalQuotient;
        u32 DividendDivisorSizeDiffWords = (DividendX->SizeWords - DivisorY->SizeWords);
        u64 DivisorY_NMinusOne = LocalDivisorY.Num[LocalDivisorY.SizeWords - 1];
        /* u64 DivisorY_NMinusTwo = LocalDivisorY.Num[LocalDivisorY.SizeWords - 2]; */
        for (i32 QuotientIndex = DividendDivisorSizeDiffWords;
             QuotientIndex >= 0;
             --QuotientIndex)
        {
            u32 JPlusN = DividendX->SizeWords + QuotientIndex;
            u64 DividendX_JPlusN = LocalDividendX.Num[JPlusN];
            if (DividendX_JPlusN < DivisorY_NMinusOne)
            {
                u128 QuotientDigitCandidate = (((u128)DividendX_JPlusN << 64) +
                                               (u128)LocalDividendX.Num[JPlusN - 1])/(u128)DivisorY_NMinusOne;
            }
            else
            {
                // q_hat == b
            }
        }

        LocalQuotient.SizeWords = DividendDivisorSizeDiffWords;
        AdjustSizeWordsDownUnchecked(&LocalQuotient);

        BigNumCopyUnchecked(Quotient, &LocalQuotient);
    }
}

internal MIN_UNIT_TEST_FUNC(TestBigNumDivide)
{
    bignum Dividend;
    InitTinyBigNumUnchecked(&Dividend, 721948327, false);

    bignum Divisor;
    InitTinyBigNumUnchecked(&Divisor, 84461, false);

    bignum Quotient;
    bignum Remainder;
    BigNumDivide(&Quotient, &Remainder, &Dividend, &Divisor);

    MinUnitAssert((IsEqualTinyBigNumUnchecked(&Quotient, 8547) &&
                   IsEqualTinyBigNumUnchecked(&Quotient, 60160)),
                  "Test 1 failed in TestBigNumDivide!\n");
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

    MinUnitAssert(AreBigNumsEqualUnchecked(&ExpectedCubedResult, &CrtResult),
                  "X^3 mismatch in TestRsaBroadcastAttack!\n");

    // Newton's method to get cubed root:
    // f(x) == 0, where f(x) == x^3 - A
    // x_k+1 == x_k - f(x_k)/f'(x_k)
    // => x_k+1 == x_k - (x_k^3 - A)/(3*x_k^2) == x_k - x_k/3 - A/3*x_k^2 == 1/3*(2*x_k - A/x_k^2)
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
    MinUnitRunTest(TestRsaBroadcastAttack);
    MinUnitRunTest(TestBigNumDivide);
}

int main()
{
    srand(time(0));
    AllTests();
    printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
