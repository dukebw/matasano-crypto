#include "crypt_helper.h"
#include <openssl/bn.h>

#define P_Q_SIZE_BITS (MAX_BIGNUM_SIZE_BITS/4)

internal inline b32
IsEqualToOneUnchecked(bignum *BigNum)
{
    b32 Result = (BigNum->SizeWords == 1) && (BigNum->Num[0] == 1);

    return Result;
}

internal inline b32
IsEvenUnchecked(bignum *BigNum)
{
    b32 Result = (BigNum->Num[0] % 2) == 0;

    return Result;
}

const bignum TEST_INV_MOD_INPUT =
{
    .Num =
    {
        0x4C9D17C8302E6940, 0x60D60BC8FCF393B3, 0x53088F73490FFC0D, 0x58D51C58FEB2A5C, 0x45EF4949ACFC69B9,
        0x389B219D73EA60DF, 0x4F17CA07EB39E48E, 0x61454904A15BDB30, 0x9A8080721F648A6C, 0x726B39EAC030507A,
        0x4F08B89C1B0E1376, 0xD0D7FCDCE1D48EBC, 0x4978146DCF7D776, 0x15F05C3D48B72D25, 0xF8D3686409A10E6B,
        0xF8F664620CE0DC0D, 0x65B05CEB1365EE53, 0x30C120AA3428B821, 0xAF5E14E2DB2BA56D, 0x2353A9239A79D767,
        0x5BACA26E1DF1AF7, 0x5376178274370F47, 0x5D8A4C274F375711, 0xA8552818B46970A7, 0x5658BB74F5D59CB8,
        0xC5CFE04A4D575ED8, 0x3F05740BE6152C0E, 0xA5CB515FFBC79724, 0x1113BC5F04D0A64B, 0x1170423501F693B4,
        0xC2AEA87CFA4F1ED4, 0x2652C93C6C15F13D, 
    },
    .SizeWords = 32,
};

const bignum RFC_5054_NIST_PRIME_2048 =
{
    .Num =
    {
        0x0FA7111F9E4AFF73, 0x9B65E372FCD68EF2, 0x35DE236D525F5475, 0x94B5C803D89F7AE4, 0x71AE35F8E9DBFBB6,
        0x2A5698F3A8D0C382, 0x9CCC041C7BC308D8, 0xAF874E7303CE5329, 0x6160279004E57AE6, 0x032CFBDBF52FB378,
        0x5EA77A2775D2ECFA, 0x544523B524B0D57D, 0x5B9D32E688F87748, 0xF1D2B9078717461A, 0x76BD207A436C6481,
        0xCA97B43A23FB8016, 0x1D281E446B14773B, 0x7359D041D5C33EA7, 0xA80D740ADBF4FF74, 0x55F97993EC975EEA,
        0x2918A9962F0B93B8, 0x661A05FBD5FAAAE8, 0xCF6095179A163AB3, 0xE8083969EDB767B0, 0xCD7F48A9DA04FD50,
        0xD52312AB4B03310D, 0x8193E0757767A13D, 0xA37329CBB4A099ED, 0xFC3192943DB56050, 0xAF72B6651987EE07,
        0xF166DE5E1389582F, 0xAC6BDB41324A9A9B, 
    },
    .SizeWords = 32,
};

internal void
GetRandPrime(bignum *RandPrimeModP)
{
    Stopif(RandPrimeModP == 0, "Null input to GetRandPrime!\n");

    BIGNUM *BN_RandPrime = BN_new();
    i32 PrimeFound = BN_generate_prime_ex(BN_RandPrime, P_Q_SIZE_BITS, 0, 0, 0, 0);

    RandPrimeModP->SizeWords = P_Q_SIZE_BITS/BITS_IN_DWORD;

    Stopif(!PrimeFound, "No prime found in TestImplementRsa!\n");

    Stopif(!BN_is_prime_ex(BN_RandPrime, 64, 0, 0), "Prime check failed in TestImplementRsa!\n");

    Stopif(BN_RandPrime->top != (i32)RandPrimeModP->SizeWords,
           "Invalid size returned from BN_generate_prime_ex!\n");

    memcpy(RandPrimeModP->Num, BN_RandPrime->d, P_Q_SIZE_BITS/BITS_IN_BYTE);

    BN_free(BN_RandPrime);
}

internal void
DivideNonZeroBignumBy2Unchecked(bignum *BigNum)
{
    u32 BigNumLastWordIndex = (BigNum->SizeWords - 1);
    for (u32 BigNumIndex = 0;
         BigNumIndex < BigNumLastWordIndex;
         ++BigNumIndex)
    {
        BigNum->Num[BigNumIndex] = ((BigNum->Num[BigNumIndex + 1] << (BITS_IN_DWORD - 1)) |
                                    (BigNum->Num[BigNumIndex] >> 1));
    }

    BigNum->Num[BigNumLastWordIndex] >>= 1;
    AdjustSizeWordsDownUnchecked(BigNum);
}

internal void
BinaryInverseInnerLoop(bignum *UOrV, bignum *X1OrX2, bignum *PrimeP)
{
    while (IsEvenUnchecked(UOrV))
    {
        DivideNonZeroBignumBy2Unchecked(UOrV);

        if (IsEvenUnchecked(X1OrX2))
        {
            DivideNonZeroBignumBy2Unchecked(X1OrX2);
        }
        else
        {
            BigNumAdd(X1OrX2, X1OrX2, PrimeP);

            DivideNonZeroBignumBy2Unchecked(X1OrX2);
        }
    }
}

/*
   Algorithm 2.22, "Guide to Elliptic Curve Cryptography", Menezes

   INPUT : Prime p and a ∈ [1, p − 1].
   OUTPUT : a − 1 mod p.

   1. u ← a, v ← p.
   2. x1 ← 1, x2 ← 0.
   3. While (u != 1 and v != 1) do
       3.1 While u is even do
               u ← u/2.
               If x1 is even then x1 ← x1/2; else x1 ← (x1 + p)/2.
       3.2 While v is even do
               v ← v/2.
               If x2 is even then x2 ← x2/2; else x2 ← (x2 + p)/2.
       3.3 If u ≥ v then: u ← u − v, x1 ← x1 − x2 ;
           Else: v ← v − u, x2 ← x2 − x1 .
   4. If u = 1 then return(x1 mod p); else return(x2 mod p).
*/
internal void
GetInverseModN(bignum *EInverseModN, bignum *InputA, bignum *PrimeP)
{
    Stopif((EInverseModN == 0) || (InputA == 0) || (PrimeP == 0), "Null input to GetInverseModN!\n");

    Stopif((InputA->SizeWords == 0), "InputA must be in [1, p - 1] in GetInverseModN!\n");

    bignum U;
    BigNumCopyUnchecked(&U, InputA);

    bignum V;
    BigNumCopyUnchecked(&V, PrimeP);

    bignum X1;
    X1.SizeWords = 1;
    X1.Num[0] = 1;

    bignum X2;
    X2.SizeWords = 0;

    while (!IsEqualToOneUnchecked(&U) && !IsEqualToOneUnchecked(&V))
    {
        BinaryInverseInnerLoop(&U, &X1, PrimeP);
        BinaryInverseInnerLoop(&V, &X2, PrimeP);

        if (IsAGreaterThanOrEqualToB(&U, &V))
        {
            BigNumSubtract(&U, &U, &V);
            BigNumSubtract(&X1, &X1, &X2);
        }
        else
        {
            BigNumSubtract(&V, &V, &U);
            BigNumSubtract(&X2, &X2, &X1);
        }
    }

    if (IsEqualToOneUnchecked(&U))
    {
        BigNumCopyUnchecked(EInverseModN, &X1);
    }
    else
    {
        BigNumCopyUnchecked(EInverseModN, &X2);
    }

    Stopif(IsAGreaterThanOrEqualToB(EInverseModN, PrimeP), "InvModResult not mod P in GetInverseModN!\n");
}

internal void
InitOsslBnUnchecked(BIGNUM *OsslBignum, u64 *Array, u32 SizeDWords, u32 ArrayMaxSizeDWords)
{
    OsslBignum->d = Array;
    OsslBignum->top = SizeDWords;
    OsslBignum->dmax = ArrayMaxSizeDWords;
    OsslBignum->neg = 0;
}

internal MIN_UNIT_TEST_FUNC(TestBigNumNegative)
{
}

internal MIN_UNIT_TEST_FUNC(TestBinaryInverse)
{
    BIGNUM BN_Prime2048;
    InitOsslBnUnchecked(&BN_Prime2048,
                        (u64 *)RFC_5054_NIST_PRIME_2048.Num,
                        RFC_5054_NIST_PRIME_2048.SizeWords,
                        ARRAY_LENGTH(RFC_5054_NIST_PRIME_2048.Num));

    Stopif(!BN_is_prime_ex(&BN_Prime2048, 64, 0, 0), "Test prime not prime in TestBinaryInverse!\n");

    bignum InvModResult;
    GetInverseModN(&InvModResult, (bignum *)&TEST_INV_MOD_INPUT, (bignum *)&RFC_5054_NIST_PRIME_2048);

    BN_CTX *Context = BN_CTX_new();

    BIGNUM Input;
    InitOsslBnUnchecked(&Input,
                        (u64 *)TEST_INV_MOD_INPUT.Num,
                        TEST_INV_MOD_INPUT.SizeWords,
                        ARRAY_LENGTH(TEST_INV_MOD_INPUT.Num));

    u64 ExpectedModInvBuffer[ARRAY_LENGTH(TEST_INV_MOD_INPUT.Num)];
    BIGNUM ExpectedModInv;
    InitOsslBnUnchecked(&ExpectedModInv, ExpectedModInvBuffer, 0, ARRAY_LENGTH(ExpectedModInvBuffer));

    BN_mod_inverse(&ExpectedModInv, &Input, &BN_Prime2048, Context);

    BN_CTX_free(Context);

    MinUnitAssert(!memcmp(InvModResult.Num, ExpectedModInv.d, BYTES_IN_BIGNUM_WORD*ExpectedModInv.top) &&
                  ((i32)InvModResult.SizeWords == ExpectedModInv.top),
                  "InvModResult mismatch in TestBinaryInverse!\n");
}

internal MIN_UNIT_TEST_FUNC(TestImplementRsa)
{
    /*
       "Handbook of Applied Cryptography", Menezes
       8.1 Algorithm Key generation for RSA public-key encryption

       SUMMARY: Each entity creates an RSA public key and a corresponding private key.
                Each entity A should do the following:

       1. Generate two large random (and distinct) primes p and q, each roughly the same size.
       2. Compute n = pq and φ = (p − 1)(q − 1). (See Note 8.5.)
       3. Select a random integer e, 1 < e < φ, such that gcd(e, φ) = 1.
       4. Use the extended Euclidean algorithm (Algorithm 2.107) to compute the unique
          integer d, 1 < d < φ, such that ed ≡ 1 (mod φ).
       5. A’s public key is (n, e); A’s private key is d.
    */
    bignum PrimeQ;
    bignum PrimeP;
    GetRandPrime(&PrimeQ);
    GetRandPrime(&PrimeP);

    // n := pq
    bignum ModulusN;
    BigNumMultiplyOperandScanning(&ModulusN, &PrimeP, &PrimeQ);

    // totient := (p - 1)(q - 1)
    PrimeQ.Num[0] -= 1;
    PrimeP.Num[0] -= 1;

    bignum Totient;
    BigNumMultiplyOperandScanning(&Totient, &PrimeP, &PrimeQ);

    bignum PrivateKeyD;
    bignum PublicExponentE;
    PublicExponentE.SizeWords = 1;
    PublicExponentE.Num[0] = 3;
    GetInverseModN(&PrivateKeyD, &PublicExponentE, &Totient);

    bignum BigNumScratch;
    BigNumMultiplyModP(&BigNumScratch, &PrivateKeyD, &PublicExponentE, &Totient);

    MinUnitAssert(IsEqualToOneUnchecked(&BigNumScratch), "de not equal to 1 mod phi in TestImplementRsa!\n");

    char Message[] = "When we are born, we cry that we are come to this great stage of fools.";

    u32 CeilingMessageSizeDWords = (STR_LEN(Message) + (BYTES_IN_BIGNUM_WORD - 1))/BYTES_IN_BIGNUM_WORD;
    BigNumScratch.SizeWords = CeilingMessageSizeDWords;
    BigNumScratch.Num[BigNumScratch.SizeWords - 1] = 0;
    memcpy(BigNumScratch.Num, Message, STR_LEN(Message));

    // To encrypt: c = m**e % n.
    MontModExpRBigNumMax(&BigNumScratch, &BigNumScratch, &PublicExponentE, &ModulusN);

    // To decrypt: m = c**d % n 
    MontModExpRBigNumMax(&BigNumScratch, &BigNumScratch, &PrivateKeyD, &ModulusN);

    MinUnitAssert(!memcmp(BigNumScratch.Num, Message, CeilingMessageSizeDWords),
                  "Decrypt/Encrypt mismatch in TestImplementRsa!\n");
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
    MinUnitRunTest(TestBigNumNegative);
    MinUnitRunTest(TestBinaryInverse);
    MinUnitRunTest(TestImplementRsa);
}

int main()
{
    srand(time(0));
    AllTests();
    printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
