#include "crypt_helper.h"

#define NIST_RFC_5054_GEN 2

const bignum NIST_RFC_5054_GEN_BIGNUM =
{
    .Num =
    {
        NIST_RFC_5054_GEN
    },
    .SizeWords = 1
};

const bignum RFC_5054_NIST_PRIME_1536 =
{
    .Num =
    {
        0xCF76E3FED135F9BB, 0x15180F93499A234D, 0x8CE7A28C2442C6F3, 0x5A021FFF5E91479E, 0x7F8A2FE9B8B5292E,
        0x837C264AE3A9BEB8, 0xE442734AF7CCB7AE, 0x65772E437D6C7F8C, 0xDB2FD53D24B7C486, 0x6EDF019539349627,
        0x158BFD3E2B9C8CF5, 0x764E3F4B53DD9DA1, 0x47548381DBC5B1FC, 0x9B609E0BE3BAB63D, 0x8134B1C8B9798914,
        0xDF028A7CEC67F0D0, 0x80B655BB9A22E8DC, 0x1558903BA0D0F843, 0x51C6A94BE4607A29, 0x5F4F5F556E27CBDE,
        0xBEEEA9614B19CC4D, 0xDBA51DF499AC4C80, 0xB1F12A8617A47BBB, 0x9DEF3CAFB939277A,
    },
    .SizeWords = 24
};

const bignum RFC_5054_NIST_PRIME_1024 =
{
    .Num =
    {
        0x9FC61D2FC0EB06E3, 0xFD5138FE8376435B, 0x2FD4CBF4976EAA9A, 0x68EDBC3C05726CC0, 0xC529F566660E57EC,
        0x82559B297BCF1885, 0xCE8EF4AD69B15D49, 0x5DC7D7B46154D6B6, 0x8E495C1D6089DAD1, 0xE0D5D8E250B98BE4,
        0x383B4813D692C6E0, 0xD674DF7496EA81D3, 0x9EA2314C9C256576, 0x6072618775FF3C0B, 0x9C33F80AFA8FC5E8,
        0xEEAF0AB9ADB38DD6, 
    },
    .SizeWords = 16
};

const bignum RFC_5054_TEST_SALT =
{
    .Num =
    {
        0xB5A727673A2441EE, 0xBEB25379D1A8581E, 
    },
    .SizeWords = 2
};

const bignum RFC_5054_TEST_K =
{
    .Num =
    {
        0x665C3E818913186F, 0x5AEF2CDD07ABAF0F, 0x7556AA04, 
    },
    .SizeWords = 3
};

const bignum RFC_5054_TEST_X =
{
    .Num =
    {
        0x93DB6CF84D16C124, 0xABE9127CC58CCF49, 0x94B7555A, 
    },
    .SizeWords = 3
};

const bignum RFC_5054_TEST_V =
{
    .Num =
    {
        0xDB2BE315E2099AFB, 0xE955A5E29E7AB245, 0x33B564E26480D78, 0xE058AD51CC72BFC9, 0x1AFF87B2B9DA6E04,
        0x52E08AB5EA53D15C, 0xBBF4CEBFBB1681, 0x48CF1970B4FB6F84, 0xC671085A1447B52A, 0xF105B4787E5186F5,
        0xE379BA4729FDC59, 0x822223CA1A605B53, 0x9886D8129BADA1F1, 0xB0DDE1569E8FA00A, 0x4E337D05B4B375BE,
        0x7E273DE8696FFC4F, 
    },
    .SizeWords = 16
};

const bignum RFC_5054_TEST_LITTLE_A =
{
    .Num =
    {
        0xAFD529DDDA2D4393, 0xC81EDC04E2762A56, 0x1989806F0407210B, 0x60975527035CF2AD, 
    },
    .SizeWords = 4
};

const bignum RFC_5054_TEST_LITTLE_B =
{
    .Num =
    {
        0x9E61F5D105284D20, 0x1DDA08E974A004F4, 0x471E81F00F6928E0, 0xE487CB59D31AC550, 
    },
    .SizeWords = 4
};

const bignum RFC_5054_TEST_BIG_A =
{
    .Num =
    {
        0x72FAC47B0769447B, 0xB349EF5D76988A36, 0x58F0EDFDFE15EFEA, 0xEEF54073CA11CF58, 0x6530E69F66615261,
        0xE1327F44BE087EF0, 0x71E1E8B9AF6D9C03, 0x42BA92AEACED8251, 0x8E39356179EAE45E, 0xBFCF99F921530EC,
        0x2D1A5358A2CF1B6E, 0x3211C04692272D8B, 0x72557EC44352E890, 0xD0E560F0C64115BB, 0x47B0704C436F523D,
        0x61D5E490F6F1B795, 
    },
    .SizeWords = 16
};

const bignum RFC_5054_TEST_BIG_B =
{
    .Num =
    {
        0xA8E3FB004B117B58, 0xEB4012B7D7665238, 0x910440B1B27AAEAE, 0x30B331EB76840, 0x9C6059F388838E7A,
        0x7BD4FBAA37089E6F, 0xD7D82C7F8DEB75CE, 0xD0C6DDB58B318885, 0x6C6DA04453728610, 0xB681CBF87837EC99,
        0x5A981652236F99D9, 0xDC46A0670DD125B9, 0x5393011BAF38964, 0x4916A1E77AF46AE1, 0xB6D041FA01BB152D,
        0xBD0C61512C692C0C, 
    },
    .SizeWords = 16
};

const bignum RFC_5054_TEST_U =
{
    .Num =
    {
        0x70A7AE5F462EF019, 0x3487DA98554ED47D, 0xCE38B959, 
    },
    .SizeWords = 3
};

const bignum RFC_5054_TEST_PREMASTER_SECRET =
{
    .Num =
    {
        0x8A469FFECA686E5A, 0xC346D7E474B29EDE, 0xBE5BEC4EC0A3212D, 0x3CD67FC88A2F39A4, 0x210DCC1F10EB3394,
        0x2AFAFA8F3499B200, 0xBDCAF8A709585EB, 0xA172B4A2A5903A, 0x41BB59B6D5979B5C, 0x876E2D013800D6C,
        0x9AE12B0A6F67809F, 0x59B48220F7C4693C, 0xF271A10D233861E3, 0x90A3381F63B387AA, 0xAE450C0287745E79,
        0xB0DC82BABCF30674,
    },
    .SizeWords = 16
};

const char SRP_TEST_VEC_EMAIL[] = "alice";
const char SRP_TEST_VEC_PASSWORD[] = "password123";

// TODO(bwd): generate salt as random integer (second test)

internal inline void
CopyByteSwappedUnchecked(u8 *Dest, u8 *Source, u32 LengthBytes)
{
    for (u32 SourceIndex = 0;
         SourceIndex < LengthBytes;
         ++SourceIndex)
    {
        Dest[LengthBytes - SourceIndex - 1] = Source[SourceIndex];
    }
}

internal b32
AreVectorsEqualByteSwapped(u8 *A, u8 *B, u32 LengthBytes)
{
    Stopif((A == 0) || (B == 0), "Null input to AreVectorsEqualByteSwapped!\n");

    b32 Result = true;

    for (u32 BIndex = 0;
         BIndex < LengthBytes;
         ++BIndex)
    {
        if (A[LengthBytes - BIndex - 1] != B[BIndex])
        {
            Result = false;
            break;
        }
    }

    return Result;
}

internal inline void
HashOutputToBigNumUnchecked(bignum *OutBigNum, u8 *Hash)
{
    OutBigNum->SizeWords = SHA_1_HASH_LENGTH_BYTES/sizeof(u64) + 1;

    memset(OutBigNum->Num, 0, sizeof(u64)*OutBigNum->SizeWords);

    CopyByteSwappedUnchecked((u8 *)OutBigNum->Num, Hash, SHA_1_HASH_LENGTH_BYTES);
}

internal MIN_UNIT_TEST_FUNC(TestImplementSrpTestVec)
{
    /*
       The premaster secret is calculated by the client as follows:

       I, P = <read from user>
       N, g, s, B = <read from server>
       a = random()
       A = g^a % N
       u = SHA1(PAD(A) | PAD(B))
       k = SHA1(N | PAD(g))
       x = SHA1(s | SHA1(I | ":" | P))
       <premaster secret> = (B - (k * g^x)) ^ (a + (u * x)) % N

       The premaster secret is calculated by the server as follows:

       N, g, s, v = <read from password file>
       b = random()
       k = SHA1(N | PAD(g))
       B = k*v + g^b % N
       A = <read from client>
       u = SHA1(PAD(A) | PAD(B))
       <premaster secret> = (A * v^u) ^ b % N
    */

    // Client
    // A := g^a mod N
    bignum BigA;
    MontModExpRBigNumMax(&BigA,
                         (bignum *)&NIST_RFC_5054_GEN_BIGNUM,
                         (bignum *)&RFC_5054_TEST_LITTLE_A,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

    MinUnitAssert(AreVectorsEqual(BigA.Num, (void *)RFC_5054_TEST_BIG_A.Num, RFC_5054_TEST_BIG_A.SizeWords) &&
                  (BigA.SizeWords == RFC_5054_TEST_BIG_A.SizeWords),
                  "Big A mismatch (Client) in TestImplementSrpTestVec!\n");

    // TODO(bwd): If A doesn't fill out 16*8 bytes?
    u32 TestModulusSizeBytes = sizeof(RFC_5054_TEST_BIG_B.Num[0])*RFC_5054_TEST_BIG_B.SizeWords;
    u8 MessageScratch[2*TestModulusSizeBytes];
    CopyByteSwappedUnchecked(MessageScratch, (u8 *)BigA.Num, TestModulusSizeBytes);
    CopyByteSwappedUnchecked(MessageScratch + TestModulusSizeBytes, (u8 *)RFC_5054_TEST_BIG_B.Num, TestModulusSizeBytes);

    // u := SHA1(PAD(A) | PAD(B))
    u8 LittleU[SHA_1_HASH_LENGTH_BYTES];
    Sha1(LittleU, MessageScratch, sizeof(MessageScratch));

    MinUnitAssert(AreVectorsEqualByteSwapped(LittleU, (u8 *)RFC_5054_TEST_U.Num, sizeof(LittleU)),
                  "Little u mismatch (Client) in TestImplementSrpTestVec!\n");

    // k := SHA1(N | PAD(g))
    CopyByteSwappedUnchecked(MessageScratch, (u8 *)RFC_5054_NIST_PRIME_1024.Num, TestModulusSizeBytes);

    u32 GPaddingBytes = sizeof(u64)*(RFC_5054_NIST_PRIME_1024.SizeWords - NIST_RFC_5054_GEN_BIGNUM.SizeWords);
    memset(MessageScratch + TestModulusSizeBytes, 0, GPaddingBytes);

    CopyByteSwappedUnchecked(MessageScratch + TestModulusSizeBytes + GPaddingBytes,
                             (u8 *)NIST_RFC_5054_GEN_BIGNUM.Num,
                             sizeof(u64)*NIST_RFC_5054_GEN_BIGNUM.SizeWords);

    u8 LittleK[SHA_1_HASH_LENGTH_BYTES];
    Sha1(LittleK, MessageScratch, sizeof(MessageScratch));

    MinUnitAssert(AreVectorsEqualByteSwapped(LittleK, (u8 *)RFC_5054_TEST_K.Num, sizeof(LittleK)),
                  "Little k mismatch (Client) in TestImplementSrpTestVec!\n");


    // MessageScratch := SHA1(I | ":" | P)
    u32 SaltLengthBytes = sizeof(u64)*RFC_5054_TEST_SALT.SizeWords;
    u32 EmailPasswordMsgLengthBytes = STR_LEN(SRP_TEST_VEC_EMAIL) + 1 + STR_LEN(SRP_TEST_VEC_PASSWORD);
    u32 SaltConcatHashEmailPwdLengthBytes = SaltLengthBytes + SHA_1_HASH_LENGTH_BYTES;
    Stopif((SaltConcatHashEmailPwdLengthBytes > sizeof(MessageScratch)) ||
           (EmailPasswordMsgLengthBytes > sizeof(MessageScratch)),
           "MessageScratch buffer overflow in TestImplementSrpTestVec!\n");

    memcpy(MessageScratch, SRP_TEST_VEC_EMAIL, STR_LEN(SRP_TEST_VEC_EMAIL));

    MessageScratch[STR_LEN(SRP_TEST_VEC_EMAIL)] = ':';

    memcpy(MessageScratch + STR_LEN(SRP_TEST_VEC_EMAIL) + 1, SRP_TEST_VEC_PASSWORD, STR_LEN(SRP_TEST_VEC_PASSWORD));

    Sha1(MessageScratch, MessageScratch, EmailPasswordMsgLengthBytes);

    memmove(MessageScratch + SaltLengthBytes, MessageScratch, SHA_1_HASH_LENGTH_BYTES);

    CopyByteSwappedUnchecked(MessageScratch, (u8 *)RFC_5054_TEST_SALT.Num, SaltLengthBytes);

    // x := SHA1(s | SHA1(I | ":" | P))
    u8 LittleX[SHA_1_HASH_LENGTH_BYTES];
    Sha1(LittleX, MessageScratch, SaltConcatHashEmailPwdLengthBytes);

    MinUnitAssert(AreVectorsEqualByteSwapped(LittleX, (u8 *)RFC_5054_TEST_X.Num, sizeof(LittleX)),
                  "Little x mismatch (Client) in TestImplementSrpTestVec!\n");

    // <premaster secret> = (B - (k * g^x)) ^ (a + (u * x)) % N
    bignum LittleXBigNum;
    HashOutputToBigNumUnchecked(&LittleXBigNum, LittleX);

    // BigNumScratch := g^x
    bignum BigNumScratch;
    MontModExpRBigNumMax(&BigNumScratch,
                         (bignum *)&NIST_RFC_5054_GEN_BIGNUM,
                         &LittleXBigNum,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

    bignum LittleKBigNum;
    HashOutputToBigNumUnchecked(&LittleKBigNum, LittleK);

    Stopif((LittleKBigNum.SizeWords + BigNumScratch.SizeWords + 1) > MAX_BIGNUM_SIZE_WORDS,
           "Potential overflow on multiplying k*g^x in TestImplementSrpTestVec!\n");

    // BigNumScratch := k * g^x
    BigNumMultiplyOperandScanning(&BigNumScratch, &LittleKBigNum, &BigNumScratch);

    // Reduce k*g^x mod P to satisfy BigNumSubtract function
    bignum MinusPInverseModR;
    FindMinusNInverseModR(&MinusPInverseModR, (bignum *)&RFC_5054_NIST_PRIME_1024, MAX_BIGNUM_SIZE_BITS);

    GetZRInverseModP(&BigNumScratch, BigNumScratch.Num, BigNumScratch.SizeWords,
                     (bignum *)&RFC_5054_NIST_PRIME_1024, &MinusPInverseModR, MAX_BIGNUM_SIZE_BITS);

    MultiplyByRModP(&BigNumScratch, &BigNumScratch, (bignum *)&RFC_5054_NIST_PRIME_1024, MAX_BIGNUM_SIZE_BITS);

    // TODO(bwd): Write Subtract Mod P to deal with case where X < Y in X - Y (X, Y in [0, P))
    // BigNumScratch := (B - (k * g^x))
    BigNumSubtract(&BigNumScratch, (bignum *)&RFC_5054_TEST_BIG_B, &BigNumScratch);

    // BigNumScratchExponent := u * x
    bignum LittleUBigNum;
    HashOutputToBigNumUnchecked(&LittleUBigNum, LittleU);

    bignum BigNumScratchExponent;
    BigNumMultiplyOperandScanning(&BigNumScratchExponent, &LittleUBigNum, &LittleXBigNum);

    // BigNumScratchExponent := a + (u * x)
    BigNumAdd(&BigNumScratchExponent, (bignum *)&RFC_5054_TEST_LITTLE_A, &BigNumScratchExponent);

    // BigNumScratch := <premaster secret>
    MontModExpRBigNumMax(&BigNumScratch,
                         &BigNumScratch,
                         &BigNumScratchExponent,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

    MinUnitAssert(AreVectorsEqual(BigNumScratch.Num,
                                  (void *)RFC_5054_TEST_PREMASTER_SECRET.Num,
                                  RFC_5054_TEST_PREMASTER_SECRET.SizeWords) &&
                  (BigNumScratch.SizeWords == RFC_5054_TEST_PREMASTER_SECRET.SizeWords),
                  "Premaster secret mismatch (Client) in TestImplementSrpTestVec!\n");
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestImplementSrpTestVec);
}

int main()
{
	srand(time(0));
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
