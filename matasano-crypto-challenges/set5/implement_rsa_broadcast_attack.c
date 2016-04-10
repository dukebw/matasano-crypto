#include "crypt_helper.h"

#define RSA_BROADCAST_PRIME_SIZE_BITS (MAX_BIGNUM_SIZE_BITS/8)
#define DWORDS_IN_WORD (sizeof(u64)/sizeof(u32))
#define RARE_U_LENGTH_DWORDS 4
#define RARE_V_LENGTH_DWORDS 3

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

    Stopif(ShiftAmountBits > BITS_IN_BIGNUM_WORD, "Invalid ShiftAmountBits input to ShiftLeftUnchecked!\n");

    if (ShiftAmountBits > 0)
    {
        for (u32 BigNumIndex = 0;
             BigNumIndex < BigNum->SizeWords;
             ++BigNumIndex)
        {
            NextWord = BigNum->Num[BigNumIndex] >> (BITS_IN_BIGNUM_WORD - ShiftAmountBits);
            BigNum->Num[BigNumIndex] = (BigNum->Num[BigNumIndex] << ShiftAmountBits) | PrevWord;
            PrevWord = NextWord;
        }
    }

    return PrevWord;
}

internal b32
IsD3ConditionMet(u128 QHat, u64 RHat, u64 V_NMinusTwo, bignum *DividendU, u32 JPlusN)
{
    b32 Result;

    u128 QHatTimesV_NMinusTwo = QHat*V_NMinusTwo;
    u64 QHatTimesV_N2Upper64 = GET_UPPER_64(QHatTimesV_NMinusTwo);
    if (QHatTimesV_N2Upper64 > RHat)
    {
        Result = true;
    }
    else if (QHatTimesV_N2Upper64 < RHat)
    {
        Result = false;
    }
    else if (GET_LOWER_64(QHatTimesV_NMinusTwo) > DividendU->Num[JPlusN - 2])
    {
        Result = true;
    }
    else
    {
        Result = false;
    }

    return Result;
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
BigNumDivide(bignum *QuotientQ, bignum *Remainder, bignum *DividendU, bignum *DivisorV)
{
    Stopif((QuotientQ == 0) || (DividendU == 0) || (DivisorV == 0),
           "Null input to BigNumDivide!\n");

    Stopif(IsEqualToZeroUnchecked(DivisorV), "Divide by zero in BigNumDivide!\n");

    Stopif(DivisorV->SizeWords == 1, "Need different routine to divide by one word!\n");

    // TODO(bwd): can be allowed if we store ujn in a temporary variable
    Stopif(DividendU->SizeWords >= (MAX_BIGNUM_SIZE_WORDS - 1), "Overflow in BigNumDivide!\n");

    if (IsALessThan(DividendU, DivisorV))
    {
        BigNumSetToZeroUnchecked(QuotientQ);

        if (Remainder)
        {
            BigNumCopyUnchecked(Remainder, DividendU);
        }
    }
    else
    {
        Stopif((DivisorV->Num[DivisorV->SizeWords - 1] == 0) || (DividendU->Num[DividendU->SizeWords - 1] == 0),
               "Invalid SizeWords input to BigNumDivide!\n");

        bignum LocalDividendU;
        BigNumCopyUnchecked(&LocalDividendU, DividendU);

        bignum LocalDivisorV;
        BigNumCopyUnchecked(&LocalDivisorV, DivisorV);

        u32 NMinusOne = LocalDivisorV.SizeWords - 1;
        u32 DivisorLeadingZeros = __builtin_clzl(LocalDivisorV.Num[NMinusOne]);

        u64 Carry = ShiftLeftUnchecked(&LocalDividendU, DivisorLeadingZeros);
        LocalDividendU.Num[LocalDividendU.SizeWords] = Carry;
        ++LocalDividendU.SizeWords;
        // NOTE(brendan): LocalDividendU.Num[LocalDividendU.SizeWords - 1] == u_m+n may be zero at this point

        Carry = ShiftLeftUnchecked(&LocalDivisorV, DivisorLeadingZeros);
        Stopif(Carry, "LocalDivisorV must shift to 0 in BigNumDivide!\n");
        Stopif(!(LocalDivisorV.Num[NMinusOne] & (1ull << 63)), "v_n-1 not >= b/2 in BigNumDivide!\n");

        // NOTE(brendan): set LocalDivisorV[N] = 0 for convenience of D6 "add-back" step
        LocalDivisorV.Num[LocalDivisorV.SizeWords] = 0;

        bignum LocalQuotientQ;
        u64 DivisorV_NMinusOne = LocalDivisorV.Num[NMinusOne];
        u64 DivisorV_NMinusTwo = LocalDivisorV.Num[LocalDivisorV.SizeWords - 2];
        i32 SizeDiffWords_M = (DividendU->SizeWords - LocalDivisorV.SizeWords);
        for (i32 QuotientIndex = SizeDiffWords_M;
             QuotientIndex >= 0;
             --QuotientIndex)
        {
            u32 JPlusN = LocalDivisorV.SizeWords + QuotientIndex;
            u64 DividendU_JPlusN = LocalDividendU.Num[JPlusN];
            u64 NextRemainderRHat;
            u128 QuotientDigitCandidateQHat;
            b32 ShouldDecrementQHat;
            if (DividendU_JPlusN < DivisorV_NMinusOne)
            {
                u128 NextDoubleWordDividend = (((u128)DividendU_JPlusN << 64) +
                                               (u128)LocalDividendU.Num[JPlusN - 1]);
                QuotientDigitCandidateQHat = NextDoubleWordDividend/(u128)DivisorV_NMinusOne;

                NextRemainderRHat = NextDoubleWordDividend % DivisorV_NMinusOne;

                ShouldDecrementQHat = IsD3ConditionMet(QuotientDigitCandidateQHat,
                                                       NextRemainderRHat,
                                                       DivisorV_NMinusTwo,
                                                       &LocalDividendU,
                                                       JPlusN);
            }
            else
            {
                QuotientDigitCandidateQHat = (u128)1 << BITS_IN_DWORD;
                NextRemainderRHat = DivisorV_NMinusOne;

                ShouldDecrementQHat = true;
            }

            while (ShouldDecrementQHat)
            {
                --QuotientDigitCandidateQHat;
                NextRemainderRHat += DivisorV_NMinusOne;

                if (!CheckForCarry(NextRemainderRHat, DivisorV_NMinusOne))
                {
                    ShouldDecrementQHat = IsD3ConditionMet(QuotientDigitCandidateQHat,
                                                           NextRemainderRHat,
                                                           DivisorV_NMinusTwo,
                                                           &LocalDividendU,
                                                           JPlusN);
                }
                else
                {
                    ShouldDecrementQHat = false;
                }
            }

            Carry = 0;
            for (u32 DivisorVIndex = 0;
                 DivisorVIndex < LocalDivisorV.SizeWords;
                 ++DivisorVIndex)
            {
                u128 V_iTimesQHat = LocalDivisorV.Num[DivisorVIndex]*QuotientDigitCandidateQHat + Carry;
                Stopif(V_iTimesQHat < Carry, "Overflow during D4 in BigNumDivide!\n");

                u64 V_iTimesQHatLower64 = GET_LOWER_64(V_iTimesQHat);
                Carry = ZeroOrSetIfLessThan(LocalDividendU.Num[QuotientIndex + DivisorVIndex],
                                            V_iTimesQHatLower64);

                LocalDividendU.Num[QuotientIndex + DivisorVIndex] -= V_iTimesQHatLower64;

                Carry += GET_UPPER_64(V_iTimesQHat);
            }

            u64 PrevU_JPlusN = LocalDividendU.Num[QuotientIndex + LocalDivisorV.SizeWords];
            LocalDividendU.Num[QuotientIndex + LocalDivisorV.SizeWords] = PrevU_JPlusN - Carry;

            Carry = ZeroOrSetIfLessThan(PrevU_JPlusN, Carry);

            // D6
            if (Carry)
            {
                --QuotientDigitCandidateQHat;

                u32 AddBackSizeWords = LocalDivisorV.SizeWords + 1;
                Carry = MultiPrecisionAdd(LocalDividendU.Num + QuotientIndex,
                                          &AddBackSizeWords,
                                          LocalDividendU.Num + QuotientIndex,
                                          AddBackSizeWords,
                                          LocalDivisorV.Num,
                                          LocalDivisorV.SizeWords);
                Stopif(Carry != 1, "No carry in add-back step D6 in BigNumDivide!\n");
            }

            LocalQuotientQ.Num[QuotientIndex] = QuotientDigitCandidateQHat;
        }

        // D7
        AdjustSizeWordsDownUnchecked(&LocalDividendU);
        if (Remainder)
        {
            if (DivisorLeadingZeros > 0)
            {
                u64 PrevWord = 0;
                u64 NextWord;
                for (i32 RemainderIndex = (LocalDividendU.SizeWords - 1);
                     RemainderIndex >= 0;
                     --RemainderIndex)
                {
                    NextWord = (LocalDividendU.Num[RemainderIndex] << (BITS_IN_BIGNUM_WORD -
                                                                       DivisorLeadingZeros));
                    Remainder->Num[RemainderIndex] =
                        (LocalDividendU.Num[RemainderIndex] >> DivisorLeadingZeros) | PrevWord;
                    PrevWord = NextWord;
                }

                Remainder->SizeWords = LocalDividendU.SizeWords;
                Remainder->Negative = false;
            }
            else
            {
                BigNumCopyUnchecked(Remainder, &LocalDividendU);
            }
        }

        LocalQuotientQ.Negative = false;
        LocalQuotientQ.SizeWords = SizeDiffWords_M + 1;
        AdjustSizeWordsDownUnchecked(&LocalQuotientQ);

        BigNumCopyUnchecked(QuotientQ, &LocalQuotientQ);
    }
}

// returns Remainder
internal u64
BigNumDivideByOneWord(bignum *Quotient, bignum *Dividend, u64 Divisor)
{
    Stopif((Quotient == 0) || (Dividend == 0), "Null input to BigNumDivideByOneWord!\n");
    Stopif(Divisor == 0, "Divide by zero in BigNumDivideByOneWord!\n");

    u64 PrevWord = 0;
    for (i64 DividendIndex = (Dividend->SizeWords - 1);
         DividendIndex >= 0;
         --DividendIndex)
    {
        u128 NextDividendWord128 = (((u128)PrevWord << BITS_IN_BIGNUM_WORD) | Dividend->Num[DividendIndex]);
        Quotient->Num[DividendIndex] = NextDividendWord128/Divisor;
        PrevWord = NextDividendWord128 % Divisor;
    }

    Quotient->Negative = Dividend->Negative;
    Quotient->SizeWords = Dividend->SizeWords;
    AdjustSizeWordsDownUnchecked(Quotient);

    return PrevWord;
}

internal void
OsslLeftShiftUnchecked(BIGNUM *OsslBigNum, u32 BitsToShift)
{
    i32 Status = BN_lshift(OsslBigNum, OsslBigNum, BitsToShift);
    if (Status == 0)
    {
        OsslPrintErrors();
        Stopif(true, "BN_lshift failed in OsslLeftShiftUnchecked!\n");
    }
}

internal void
OsslDivide(BIGNUM *Quotient, BIGNUM *Remainder, BIGNUM *Dividend, BIGNUM *Divisor, BN_CTX *Context)
{
    i32 Status = BN_div(Quotient, Remainder, Dividend, Divisor, Context);
    if (Status == 0)
    {
        OsslPrintErrors();
        Stopif(true, "BN div failed in OsslDivide!\n");
    }
}

internal inline b32
IsRareCaseSecondRequirementMet(u128 QHat, u64 V_NMinusTwo, u64 RHat, u64 U_NMinusTwo)
{
    b32 Result = ((QHat*(u128)V_NMinusTwo) <= (((u128)RHat << 64) | U_NMinusTwo));

    return Result;
}

internal inline void
InitBignumFromOsslBnUnchecked(bignum *BigNum, BIGNUM *OsslBigNum)
{
    memcpy(BigNum->Num, OsslBigNum->d, OsslBigNum->top*BYTES_IN_BIGNUM_WORD);
    BigNum->SizeWords = OsslBigNum->top;
    BigNum->Negative = !!OsslBigNum->neg;
}

internal inline b32
DoesBigNumDivResultEqualOsslResult(bignum *Quotient,
                                   bignum *Remainder,
                                   BIGNUM *OsslUDivV,
                                   BIGNUM *OsslUDivVRemainder)
{
    b32 Result = (DoesBigNumEqualOsslBigNum(Quotient, OsslUDivV) &&
                  DoesBigNumEqualOsslBigNum(Remainder, OsslUDivVRemainder));

    return Result;
}

internal MIN_UNIT_TEST_FUNC(TestBigNumDivide)
{
    BIGNUM OsslU;
    BIGNUM OsslV;
    BIGNUM OsslUDivV;
    BIGNUM OsslUDivVRemainder;

    bignum Dividend;
    bignum Divisor;
    bignum Quotient;
    bignum Remainder;

    u64 UArray[MAX_BIGNUM_SIZE_WORDS/2];
    InitOsslBnUnchecked(&OsslU, UArray, 0, ARRAY_LENGTH(UArray));

    u64 VArray[ARRAY_LENGTH(UArray)];
    InitOsslBnUnchecked(&OsslV, VArray, 0, ARRAY_LENGTH(VArray));

    u64 UDivVArray[ARRAY_LENGTH(UArray)];
    InitOsslBnUnchecked(&OsslUDivV, UDivVArray, 0, ARRAY_LENGTH(UDivVArray));

    u64 UDivVRemainderArray[ARRAY_LENGTH(UArray)];
    InitOsslBnUnchecked(&OsslUDivVRemainder, UDivVRemainderArray, 0, ARRAY_LENGTH(UDivVRemainderArray));

    BN_CTX *OsslContext = BN_CTX_new();

    for (u32 TestIteration = 0;
         TestIteration < 1000;
         ++TestIteration)
    {
        GenOsslPseudoRandBn(&OsslU, BITS_IN_DWORD*ARRAY_LENGTH(UArray));
        GenOsslPseudoRandBn(&OsslV, BITS_IN_DWORD*ARRAY_LENGTH(VArray)/2);

        OsslDivide(&OsslUDivV, &OsslUDivVRemainder, &OsslU, &OsslV, OsslContext);

        InitBignumFromOsslBnUnchecked(&Dividend, &OsslU);
        InitBignumFromOsslBnUnchecked(&Divisor, &OsslV);

        BigNumDivide(&Quotient, &Remainder, &Dividend, &Divisor);

        MinUnitAssert(DoesBigNumDivResultEqualOsslResult(&Quotient, &Remainder, &OsslUDivV, &OsslUDivVRemainder),
                      "Test 1 failed in TestBigNumDivide!\n");
    }

    // Find an example four digit number u (base 2^64) and three digit number v such that:
    // 1. v_n-1 >= floor(b/2)
    // 2. q_hat*v_n-2 <= b*r_hat + u_n-2
    // 3. q_hat != q
    // Then should have (u mod v ) >= (1 - 2/b)*v

    b32 WereRareInputsFound = false;
    do
    {
        GenOsslPseudoRandBn(&OsslU, BITS_IN_DWORD*RARE_U_LENGTH_DWORDS);
        GenOsslPseudoRandBn(&OsslV, BITS_IN_DWORD*RARE_V_LENGTH_DWORDS);
        u32 OsslVLeadingZeros = __builtin_clzl(OsslV.d[OsslV.top - 1]);
        OsslLeftShiftUnchecked(&OsslV, OsslVLeadingZeros);
        OsslLeftShiftUnchecked(&OsslU, OsslVLeadingZeros);

        OsslDivide(&OsslUDivV, &OsslUDivVRemainder, &OsslU, &OsslV, OsslContext);

        // q < b requirement
        if (OsslUDivV.top == 1)
        {
            u64 V_NMinusOne = OsslV.d[OsslV.top - 1];
            u128 TempDividend = (((u128)OsslU.d[OsslU.top - 1] << 64) + (u128)OsslU.d[OsslU.top - 2]);
            u128 QHat = TempDividend/(u128)V_NMinusOne;
            // One in 2^64 likelihood?
            u64 QHatUpper64 = QHat >> 64;
            u64 QHatLower64 = (u64)QHat;
            if (QHatUpper64)
            {
                printf("QHat = b found!\n");
                Stopif((QHatUpper64 != 1) || QHatLower64,
                       "QHat <= b -- invariant broken in TestBigNumDivide!\n");
            }

            // q != q_hat requirement
            if ((u64)QHat != OsslUDivV.d[0])
            {
                Stopif((u64)QHat > (OsslUDivV.d[0] + 2), "QHat > (q + 2) in TestBigNumDivide!\n");

                // q_hat*v_n-2 <= (b*r_hat + u_n-2) requirement
                u64 RHat = TempDividend % V_NMinusOne;
                
                while (!IsRareCaseSecondRequirementMet(QHat,
                                                       OsslV.d[OsslV.top - 2],
                                                       RHat,
                                                       OsslU.d[OsslU.top - 2]) &&
                       (OsslV.d[OsslV.top - 2] != 0))
                {
                    OsslV.d[OsslV.top - 2] >>= 1;
                }

                // binary search for a matching candidate
                if (OsslV.d[OsslV.top - 2] > 0)
                {
                    b32 IsRareCaseSecondReqStillMet = IsRareCaseSecondRequirementMet(QHat,
                                                                                     OsslV.d[OsslV.top - 2],
                                                                                     RHat,
                                                                                     OsslU.d[OsslU.top - 2]);
                    OsslDivide(&OsslUDivV, &OsslUDivVRemainder, &OsslU, &OsslV, OsslContext);
                    u64 V_NMinusTwoUpperBound = OsslV.d[OsslV.top - 2] << 1;
                    u64 V_NMinusTwoLowerBound = OsslV.d[OsslV.top - 2];
                    while ((((u64)QHat == OsslUDivV.d[0]) || !IsRareCaseSecondReqStillMet) &&
                           (V_NMinusTwoUpperBound > V_NMinusTwoLowerBound) &&
                           ((V_NMinusTwoUpperBound - V_NMinusTwoLowerBound) > 1))
                    {
                        OsslV.d[OsslV.top - 2] = (u64)(((u128)V_NMinusTwoUpperBound +
                                                        (u128)V_NMinusTwoLowerBound)/2);

                        OsslDivide(&OsslUDivV, &OsslUDivVRemainder, &OsslU, &OsslV, OsslContext);
                        IsRareCaseSecondReqStillMet = IsRareCaseSecondRequirementMet(QHat,
                                                                                     OsslV.d[OsslV.top - 2],
                                                                                     RHat,
                                                                                     OsslU.d[OsslU.top - 2]);

                        if (IsRareCaseSecondReqStillMet)
                        {
                            V_NMinusTwoLowerBound = OsslV.d[OsslV.top - 2];
                        }
                        else
                        {
                            V_NMinusTwoUpperBound = OsslV.d[OsslV.top - 2];
                        }
                    }
                    Stopif((V_NMinusTwoUpperBound <= V_NMinusTwoLowerBound),
                           "No rare case candidate found!\n");
                    Stopif(OsslV.d[OsslV.top - 2] == 0, "Overflow in TestBigNumDivide!\n");

                    // Test assertion that now (u mod v) >= (1 - 2/b)*v
                    // -> b*(u mod v) >= (b - 2)*v
                    u64 TwoTimesVArray[2*RARE_U_LENGTH_DWORDS];
                    BIGNUM OsslTwoTimesV;
                    InitOsslBnUnchecked(&OsslTwoTimesV, TwoTimesVArray, 0, ARRAY_LENGTH(TwoTimesVArray));

                    Stopif(!BN_lshift(&OsslTwoTimesV, &OsslV, 1), "BN_lshift failed in TestBigNumDivide!\n");

                    OsslLeftShiftUnchecked(&OsslUDivVRemainder, BITS_IN_DWORD);
                    OsslLeftShiftUnchecked(&OsslV, BITS_IN_DWORD);

                    Stopif(!BN_sub(&OsslV, &OsslV, &OsslTwoTimesV), "BN_sub failed in TestBigNumDivide!\n");

                    if (BN_cmp(&OsslUDivVRemainder, &OsslV) >= 0)
                    {
                        WereRareInputsFound = true;
                        printf("Rare Inputs found!\n");

                        // Restore OsslV for input to test case
                        Stopif(!BN_add(&OsslV, &OsslV, &OsslTwoTimesV),
                               "BN_add failed in TestBigNumDivide!\n");
                        Stopif(!BN_rshift(&OsslV, &OsslV, BITS_IN_DWORD),
                               "BN_rshift failed in TestBigNumDivide!\n");
                    }
                }
            }
        }
    } while (!WereRareInputsFound);

    OsslDivide(&OsslUDivV, &OsslUDivVRemainder, &OsslU, &OsslV, OsslContext);

    InitBignumFromOsslBnUnchecked(&Dividend, &OsslU);
    InitBignumFromOsslBnUnchecked(&Divisor, &OsslV);

    BigNumDivide(&Quotient, &Remainder, &Dividend, &Divisor);

    MinUnitAssert(DoesBigNumDivResultEqualOsslResult(&Quotient, &Remainder, &OsslUDivV, &OsslUDivVRemainder),
                  "Test 2 failed in TestBigNumDivide!\n");

    // Divide by single-word test case
    OsslV.top = 1;
    OsslDivide(&OsslUDivV, &OsslUDivVRemainder, &OsslU, &OsslV, OsslContext);

    Remainder.Num[0] = BigNumDivideByOneWord(&Quotient, &Dividend, OsslV.d[0]);
    Remainder.SizeWords = 1;

    MinUnitAssert(DoesBigNumDivResultEqualOsslResult(&Quotient, &Remainder, &OsslUDivV, &OsslUDivVRemainder),
                  "Test 3 failed in TestBigNumDivide!\n");
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

        Stopif(IsAGreaterThanOrEqualToB(&ProductMResidueMInv, &N1N2N3),
               "Invalid NiNj*c_k >= N1N2N3 condition\n");

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

    // Initial guess: x^3 >> (2*(bit count)/3)
    u32 InitialValueBits = BigNumBitCountUnchecked(&CrtResult)/3;
    u32 InitialValueWordCount = (InitialValueBits + (BITS_IN_BIGNUM_WORD - 1))/BITS_IN_BIGNUM_WORD;
    u32 InitialValueFirstWord = CrtResult.SizeWords - InitialValueWordCount;
    u32 InitialValueMod64Bits = InitialValueBits % BITS_IN_BIGNUM_WORD;
    u32 ShiftAmountBitsMod64 = BITS_IN_BIGNUM_WORD - InitialValueMod64Bits;
    if (InitialValueMod64Bits > 0)
    {
        u64 NextWord;
        u64 PrevWord = 0;
        for (u32 CrtResultIndex = (CrtResult.SizeWords - 1);
             CrtResultIndex >= InitialValueFirstWord;
             --CrtResultIndex)
        {
            NextWord = CrtResult.Num[CrtResultIndex] << InitialValueMod64Bits;
            CrtResult.Num[CrtResultIndex - InitialValueFirstWord] =
                (CrtResult.Num[CrtResultIndex] >> ShiftAmountBitsMod64) | PrevWord;
            PrevWord = NextWord;
        }
    }
    else
    {
        memmove(CrtResult.Num,
                CrtResult.Num + InitialValueFirstWord,
                BYTES_IN_BIGNUM_WORD*InitialValueWordCount);
    }
    CrtResult.SizeWords = InitialValueWordCount;
    CrtResult.Negative = false;

    bignum TempBigNum;
    u32 NewtonMethodIterations = 0;
    while (!AreBigNumsEqualUnchecked(&CrtResult, &Message))
    {
        // TempBigNum := x_k^2
        // TODO(brendan): Fast bignum-squaring function
        // re-use Three as Two
        Three.Num[0] = 2;
        MontModExpRBigNumMax(&TempBigNum, &CrtResult, &Three, &N1N2N3);
        Three.Num[0] = 3;

        // TempBigNum := A/x_k^2
        BigNumDivide(&TempBigNum, 0, &ExpectedCubedResult, &TempBigNum);

        // CrtResult := 2*x_k
        ShiftLeftUnchecked(&CrtResult, 1);

        // CrtResult := (2*x_k + A/x_k^2)
        BigNumAdd(&CrtResult, &CrtResult, &TempBigNum);

        // CrtResult := 1/3*(2*x_k + A/x_k^2)
        BigNumDivideByOneWord(&CrtResult, &CrtResult, 3);

        ++NewtonMethodIterations;
    }
    printf("Newton's method iterations: %u\n", NewtonMethodIterations);
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
    MinUnitRunTest(TestBigNumDivide);
    MinUnitRunTest(TestRsaBroadcastAttack);
}

int main()
{
    srand(time(0));
    AllTests();
    printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
