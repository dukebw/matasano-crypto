#include "crypt_helper.h"

#define P_Q_SIZE_BITS (MAX_BIGNUM_SIZE_BITS/4)

#define BIGNUM_BINARY_OP_FN(Name) u32 Name(bignum *SumAB, bignum *A, bignum *B)
typedef BIGNUM_BINARY_OP_FN(bignum_binary_op_fn);

#define OSSL_BN_BINARY_OP_FN(Name) void Name(BIGNUM *SumAB, BIGNUM *A, BIGNUM *B)
typedef OSSL_BN_BINARY_OP_FN(ossl_bn_binary_op_fn);

typedef struct
{
    BIGNUM LeftOp;
    BIGNUM RightOp;
    BIGNUM Result;
} ossl_binary_operands;

typedef struct
{
    bignum LeftOp;
    bignum RightOp;
    bignum Result;
} bignum_binary_operands;

internal const bignum TEST_INV_MOD_INPUT =
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
    .Negative = false,
};

internal const bignum RFC_5054_NIST_PRIME_2048 =
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
    .Negative = false,
};

internal const bignum TEST_NEG_A =
{
    .Num =
    {
        0x8D0A700515C96F17, 0x4B9463979042A579, 0xB8D9E77DE551F863, 0x99D8EE8C615E5A05, 0xA84C3E177E817A7F,
        0xED6A29BF485A4923, 0x5E0BFB8682FF8290, 0xEA8AD311A8235EBE, 0x2F0700CAE4A7060F, 0x900C204EB9AA363C,
        0x89FB2330A171AF9F, 0xCE9035AAB43537DA, 0x680DB7D2D3EAB7D7, 0x5C3D4A926DB537C5, 0xA551A8F7B65277D5,
        0x6543568B24D36905, 0x9B11F69F8698ECE9, 0x18DD81F0CD55EF50, 0x5E2C37CF09ED9601, 0x178BD5309D98061D,
        0xEDAD4CA90675A804, 0x9B4FCA1C62AECE97, 0x3BF9B4BD0939FB77, 0x9E5216D4AD41575C, 0xFE27502D9B145F0,
        0x3F0A52D36576B411, 0xC9A0C504BB2BEC02, 0xA69AB46C6B21A9BB, 0x49D53FF4E7862D48, 0xAF5FD57E3014F61B,
        0x22728428C4D0CEB1, 0xE8481E2062B48FFC,
    },
    .SizeWords = 32,
    .Negative = false,
};

internal const bignum TEST_NEG_B =
{
    .Num =
    {
        0xBA052C29D26AF995, 0x2F0A18C4C544485C, 0x25D7E62DBF8E5865, 0x6209765851BFFD81, 0xD51562001ED28C26,
        0x444BBA15A2C07C2B, 0xF69B97AF05877B8E, 0x6FB34F3DA58EE94, 0x619EEB77F82B977B, 0x3096C17417983D99,
        0xB9EB920D8556C7BA, 0x746247430B7535DD, 0x3A62C25478D9B8DD, 0x7EE8BF625B69ED08, 0xD00A5A37F540C8BF,
        0x41FF2C9C9B49E174, 0x31D7FC86FAFB60E7, 0xC3C0C91ACDBF14B6, 0x98369FF0996B72E9, 0xD8D1D8125DF8B511,
        0xD65B4C0CC4F7691A, 0x7425FD815614DA68, 0xD02D2E37A91B58DE, 0xCAD3244E431303BB, 0xB59A28CBE68D9BBA,
        0xE4B5982200BB3DDC, 0xF9D599EB1F583FA0, 0x4E360E547D4A5E6F, 0xD4A4C0BB6686B9A1, 0x412E168DADEE98B2,
        0xBF4890439951D1E1, 0x4D98AB3365D537F7, 
    },
    .SizeWords = 32,
    .Negative = false,
};

internal const bignum TEST_NEG_B_MINUS_A =
{
    .Num =
    {
        0xD30543DB435E7582, 0x1C8A4AD2CAFE5D1C, 0x9302015025C39FFE, 0x37CF78340F9E5C84, 0xD336DC175FAEEE59,
        0xA91E6FA9A599CCF7, 0x677063D77D780702, 0xE38F9E1DCDCA7029, 0xCD681552EC7B6E94, 0x5F755EDAA211F8A2,
        0xD00F91231C1AE7E5, 0x5A2DEE67A8C001FC, 0x2DAAF57E5B10FEFA, 0xDD548B30124B4ABD, 0xD5474EBFC111AF15,
        0x234429EE89898790, 0x6939FA188B9D8C02, 0x551CB8D5FF96DA9A, 0xC5F597DE70822317, 0x3EB9FD1E3F9F510B,
        0x1752009C417E3EE9, 0x2729CC9B0C99F42F, 0x6BCC8685601EA299, 0xD37EF2866A2E53A0, 0x5A484C36F323AA35,
        0x5A54BAB164BB7634, 0xCFCB2B199BD3AC61, 0x5864A617EDD74B4B, 0x75307F3980FF73A7, 0x6E31BEF082265D68,
        0x6329F3E52B7EFCD0, 0x9AAF72ECFCDF5804, 
    },
    .SizeWords = 32,
    .Negative = true,
};

// C := A - B
internal const bignum TEST_NEG_C_PLUS_C =
{
    .Num =
    {
        0xA60A87B686BCEB04, 0x391495A595FCBA39, 0x260402A04B873FFC, 0x6F9EF0681F3CB909, 0xA66DB82EBF5DDCB2,
        0x523CDF534B3399EF, 0xCEE0C7AEFAF00E05, 0xC71F3C3B9B94E052, 0x9AD02AA5D8F6DD29, 0xBEEABDB54423F145,
        0xA01F22463835CFCA, 0xB45BDCCF518003F9, 0x5B55EAFCB621FDF4, 0xBAA916602496957A, 0xAA8E9D7F82235E2B,
        0x468853DD13130F21, 0xD273F431173B1804, 0xAA3971ABFF2DB534, 0x8BEB2FBCE104462E, 0x7D73FA3C7F3EA217,
        0x2EA4013882FC7DD2, 0x4E5399361933E85E, 0xD7990D0AC03D4532, 0xA6FDE50CD45CA740, 0xB490986DE647546B,
        0xB4A97562C976EC68, 0x9F96563337A758C2, 0xB0C94C2FDBAE9697, 0xEA60FE7301FEE74E, 0xDC637DE1044CBAD0,
        0xC653E7CA56FDF9A0, 0x355EE5D9F9BEB008, 0x1, 
    },
    .SizeWords = 33,
    .Negative = true,
};

internal void
BinaryInverseInnerLoop(bignum *UOrV, bignum *X1OrX2, bignum *PrimeP)
{
    while (IsEvenUnchecked(UOrV))
    {
        DivideBignumBy2Unchecked(UOrV);

        if (IsEvenUnchecked(X1OrX2))
        {
            DivideBignumBy2Unchecked(X1OrX2);
        }
        else
        {
            BigNumAdd(X1OrX2, X1OrX2, PrimeP);

            DivideBignumBy2Unchecked(X1OrX2);
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
// NOTE(brendan): Unused for now. Unchecked input requirement: PrimeP is prime.
internal void
GetInverseModPPrime(bignum *EInverseModN, bignum *InputA, bignum *PrimeP)
{
    Stopif((EInverseModN == 0) || (InputA == 0) || (PrimeP == 0), "Null input to GetInverseModN!\n");

    Stopif((InputA->SizeWords == 0), "InputA must be in [1, p - 1] in GetInverseModN!\n");

    bignum U;
    BigNumCopyUnchecked(&U, InputA);

    bignum V;
    BigNumCopyUnchecked(&V, PrimeP);

    bignum X1;
    BigNumSetToOneUnchecked(&X1);

    bignum X2;
    BigNumSetToZeroUnchecked(&X2);

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

internal inline void
OsslAddBn(BIGNUM *SumAB, BIGNUM *A, BIGNUM *B)
{
    i32 Status = BN_add(SumAB, A, B);
    Stopif(Status != 1, "BN_add failed in OsslAddBn!\nERR_get_error(): 0x%lx\n", ERR_get_error());
}

internal inline void
OsslSubtractBn(BIGNUM *AMinusB, BIGNUM *A, BIGNUM *B)
{
    i32 Status = BN_sub(AMinusB, A, B);
    Stopif(Status != 1, "BN_add failed in OsslSubtractBn!\nERR_get_error(): 0x%lx\n", ERR_get_error());
}

internal inline void
OsslMultiplyBn(BIGNUM *ATimesB, BIGNUM *A, BIGNUM *B)
{
    BN_CTX *Context = BN_CTX_new();

    i32 Status = BN_mul(ATimesB, A, B, Context);
    Stopif(Status != 1, "BN_mul failed in OsslMultiplyBn!\nERR_get_error(): 0x%lx\n", ERR_get_error());

    BN_CTX_free(Context);
}

internal void
BinaryOpAndAssertEqual(bignum_binary_operands *Ops,
                       ossl_binary_operands *OsslOps,
                       b32 LeftOpNegative,
                       b32 RightOpNegative,
                       bignum_binary_op_fn *BigNumBinaryOpFn,
                       ossl_bn_binary_op_fn *OsslBnBinaryOpFn)
{
    Stopif((Ops == 0) || (OsslOps == 0), "Null input to BinaryOpAndAssertEqual!");

    Ops->LeftOp.Negative = LeftOpNegative;
    Ops->RightOp.Negative = RightOpNegative;
    OsslOps->LeftOp.neg = LeftOpNegative;
    OsslOps->RightOp.neg = RightOpNegative;

    OsslBnBinaryOpFn(&OsslOps->Result, &OsslOps->LeftOp, &OsslOps->RightOp);
    BigNumBinaryOpFn(&Ops->Result, &Ops->LeftOp, &Ops->RightOp);

    MinUnitAssert(DoesBigNumEqualOsslBigNum(&Ops->Result, &OsslOps->Result),
                  "BigNum/OsslBignum mismatch in TestBigNumNegative!\n");
}

internal void
GenerateLeftRightOpSetSize(ossl_binary_operands *OsslOps, bignum_binary_operands *Ops, u32 Bits)
{
    GenOsslPseudoRandBn(&OsslOps->LeftOp, Bits);
    GenOsslPseudoRandBn(&OsslOps->RightOp, Bits);

    Ops->LeftOp.SizeWords = OsslOps->LeftOp.top;
    Ops->RightOp.SizeWords = OsslOps->RightOp.top;
}

internal MIN_UNIT_TEST_FUNC(TestBigNumNegative)
{
    ossl_binary_operands OsslOps;
    bignum_binary_operands Ops;
    u64 BN_ResultBuffer[MAX_BIGNUM_SIZE_WORDS];

    bignum Zero;
    BigNumSetToZeroUnchecked(&Zero);

    InitOsslBnUnchecked(&OsslOps.LeftOp, Ops.LeftOp.Num, 0, ARRAY_LENGTH(Ops.LeftOp.Num));
    InitOsslBnUnchecked(&OsslOps.RightOp, Ops.RightOp.Num, 0, ARRAY_LENGTH(Ops.RightOp.Num));
    InitOsslBnUnchecked(&OsslOps.Result, BN_ResultBuffer, 0, ARRAY_LENGTH(BN_ResultBuffer));

    for (u32 TestCount = 0;
         TestCount < 2048;
         ++TestCount)
    {
        GenerateLeftRightOpSetSize(&OsslOps, &Ops, MAX_BIGNUM_SIZE_BITS - BITS_IN_BIGNUM_WORD);

        BigNumAdd(&Ops.Result, &Ops.LeftOp, &Zero);
        MinUnitAssert(AreBigNumsEqualUnchecked(&Ops.Result, &Ops.LeftOp),
                      "Zero case failed in TestBigNumNegative!\n");

        BigNumAdd(&Ops.Result, &Zero, &Ops.LeftOp);
        MinUnitAssert(AreBigNumsEqualUnchecked(&Ops.Result, &Ops.LeftOp),
                      "Zero case failed in TestBigNumNegative!\n");

        BigNumSubtract(&Ops.Result, &Ops.LeftOp, &Zero);
        MinUnitAssert(AreBigNumsEqualUnchecked(&Ops.Result, &Ops.LeftOp),
                      "Zero case failed in TestBigNumNegative!\n");

        BigNumSubtract(&Ops.Result, &Zero, &Ops.LeftOp);
        MinUnitAssert(((Ops.Result.SizeWords == Ops.LeftOp.SizeWords) &&
                       (Ops.Result.Negative != Ops.LeftOp.Negative) &&
                       !memcmp(Ops.Result.Num, Ops.LeftOp.Num, BigNumSizeBytesUnchecked(&Ops.LeftOp))),
                      "Zero case failed in TestBigNumNegative!\n");

        BinaryOpAndAssertEqual(&Ops, &OsslOps, false, false, BigNumAdd, OsslAddBn);
        BinaryOpAndAssertEqual(&Ops, &OsslOps, false, true, BigNumAdd, OsslAddBn);
        BinaryOpAndAssertEqual(&Ops, &OsslOps, true, false, BigNumAdd, OsslAddBn);
        BinaryOpAndAssertEqual(&Ops, &OsslOps, true, true, BigNumAdd, OsslAddBn);

        BinaryOpAndAssertEqual(&Ops, &OsslOps, false, false, BigNumSubtract, OsslSubtractBn);
        BinaryOpAndAssertEqual(&Ops, &OsslOps, false, true, BigNumSubtract, OsslSubtractBn);
        BinaryOpAndAssertEqual(&Ops, &OsslOps, true, false, BigNumSubtract, OsslSubtractBn);
        BinaryOpAndAssertEqual(&Ops, &OsslOps, true, true, BigNumSubtract, OsslSubtractBn);

        GenerateLeftRightOpSetSize(&OsslOps, &Ops, MAX_BIGNUM_SIZE_BITS/4);

        BinaryOpAndAssertEqual(&Ops, &OsslOps, false, false, BigNumMultiplyOperandScanning, OsslMultiplyBn);
        BinaryOpAndAssertEqual(&Ops, &OsslOps, true, false, BigNumMultiplyOperandScanning, OsslMultiplyBn);
        BinaryOpAndAssertEqual(&Ops, &OsslOps, false, true, BigNumMultiplyOperandScanning, OsslMultiplyBn);
        BinaryOpAndAssertEqual(&Ops, &OsslOps, true, true, BigNumMultiplyOperandScanning, OsslMultiplyBn);
    }
}

internal MIN_UNIT_TEST_FUNC(TestBinaryInverse)
{
    // TODO(bwd): gcd + gcd tests (Simple, average and corner/extreme degenerate)
    bignum SimpleInput;
    InitTinyBigNumUnchecked(&SimpleInput, 17, false);

    bignum SimplePrime;
    InitTinyBigNumUnchecked(&SimplePrime, 3120, false);

    bignum InvModResult;
    GetInverseModN(&InvModResult, &SimpleInput, &SimplePrime);

    MinUnitAssert((InvModResult.Num[0] == 2753) &&
                  (InvModResult.SizeWords == 1) &&
                  (InvModResult.Negative == false),
                  "Simple inv mod case failed in TestBinaryInverse!\n");

    BIGNUM BN_Prime2048;
    InitOsslBnUnchecked(&BN_Prime2048,
                        (u64 *)RFC_5054_NIST_PRIME_2048.Num,
                        RFC_5054_NIST_PRIME_2048.SizeWords,
                        ARRAY_LENGTH(RFC_5054_NIST_PRIME_2048.Num));

    Stopif(!BN_is_prime_ex(&BN_Prime2048, 64, 0, 0), "Test prime not prime in TestBinaryInverse!\n");

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

    GetInverseModN(&InvModResult, (bignum *)&TEST_INV_MOD_INPUT, (bignum *)&RFC_5054_NIST_PRIME_2048);

    MinUnitAssert(DoesBigNumEqualOsslBigNum(&InvModResult, &ExpectedModInv),
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
    bignum PrivateKeyD;
    bignum PublicExponentE;
    InitTinyBigNumUnchecked(&PublicExponentE, 3, false);

    bignum PrimeQ;
    bignum PrimeP;
    bignum Totient;
    do
    {
        GetRandPrime(&PrimeQ, P_Q_SIZE_BITS);
        GetRandPrime(&PrimeP, P_Q_SIZE_BITS);

        // totient := (p - 1)(q - 1) == pq - p - q + 1
        BigNumMultiplyOperandScanning(&Totient, &PrimeP, &PrimeQ);
        BigNumSubtract(&Totient, &Totient, &PrimeP);
        BigNumSubtract(&Totient, &Totient, &PrimeQ);

        bignum One;
        BigNumSetToOneUnchecked(&One);
        BigNumAdd(&Totient, &Totient, &One);
    } while (!GetInverseModN(&PrivateKeyD, &PublicExponentE, &Totient));

    char Message[] = "When we are born, we cry that we are come to this great stage of fools.";

    bignum BigNumScratch;
    u32 CeilingMessageSizeDWords = (STR_LEN(Message) + (BYTES_IN_BIGNUM_WORD - 1))/BYTES_IN_BIGNUM_WORD;
    BigNumScratch.SizeWords = CeilingMessageSizeDWords;
    BigNumScratch.Num[BigNumScratch.SizeWords - 1] = 0;
    BigNumScratch.Negative = false;
    memcpy(BigNumScratch.Num, Message, STR_LEN(Message));

    // n := pq
    bignum ModulusN;
    BigNumMultiplyOperandScanning(&ModulusN, &PrimeP, &PrimeQ);

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
