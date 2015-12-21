#include "crypt_helper.h"

#define DH_PRIME 37
#define DH_GENERATOR 5

// TODO(bwd): implementation with allocator
// Little-endian
const bignum NIST_RFC_3526_PRIME_1536 =
{
    .Num =
    {
        0xFFFFFFFFFFFFFFFF, 0xF1746C08CA237327, 0x670C354E4ABC9804, 0x9ED529077096966D, 0x1C62F356208552BB,
        0x83655D23DCA3AD96, 0x69163FA8FD24CF5F, 0x98DA48361C55D39A, 0xC2007CB8A163BF05, 0x49286651ECE45B3D,
        0xAE9F24117C4B1FE6, 0xEE386BFB5A899FA5, 0xBFF5CB6F406B7ED, 0xF44C42E9A637ED6B, 0xE485B576625E7EC6,
        0x4FE1356D6D51C245, 0x302B0A6DF25F1437, 0xEF9519B3CD3A431B, 0x514A08798E3404DD, 0x20BBEA63B139B22,
        0x29024E088A67CC74, 0xC4C6628B80DC1CD1, 0xC90FDAA22168C234, 0xFFFFFFFFFFFFFFFF,
    },
    .SizeWords = 24
};
const u32 NIST_RFC_3526_GEN = 2;

global_variable bignum GlobalScratchBigNumA;
#if 0
global_variable bignum GlobalScratchBigNumB;
#endif

const bignum TEST_BIGNUM_0_LEFT =
{
    .Num =
    {
        0x16B7818A267C927A, 0x317F555A9C4465DD, 0xECDAE61F0890E23D, 0xFE71C6A3E5915B0F, 0xC0C852C0324F8A15,
        0x9FBA65C63A2C2626, 0x4EB894857262A0B7, 0xF820D443C1D30AD5, 0x45F6C1AFA2B95062, 0xD1D9A84A1AA0D21F,
        0xB74C4C276DCA9219, 0x14CB93200174DECC, 0x16028B73B765222B, 0x5EDB94CE051E8587, 0xB37D92E17FDF785F,
        0x897BC982E3A892E6, 0x84ACAD97C2CFC554, 0xACE67AF703942DCE, 0x719480C9876D86F7, 0xF888F14504218F33,
        0x596DB399B0C7FDC8, 0xFDF090C90BD4A0E3, 0x74C4E83EB23BC2D9, 0xAB039DF5FF4826AD,
    },
    .SizeWords = 24
};
const bignum TEST_BIGNUM_0_RIGHT =
{
    .Num =
    {
        0xBF483A67D2D0EF9A, 0xB55A095F7A19A639, 0x1A7DCE69844F8315, 0x7F889E9E725FC3B6, 0xAB430068BA2174EC,
        0x1FC1F5EBA4A10C4B, 0x6CE8DC26245B96E0, 0x94575D62EF300B52, 0xF8AFFCAE86D71BE7, 0xE69FBB1B3F2A0412,
        0xEEBC754A78F95B1D, 0x69783B202FA1F3C7, 0x1A895AD6E40BE103, 0x46044C510DE029F9, 0xB3828CFD2525EC69,
        0x1E9E1341F3EE19E5, 0x3A05C33435B22714, 0xDF8442844B2A777F, 0x3F85AC87ED1FCEEF, 0x3028C80699092214,
        0x49E95E818474DDD0, 0xF0CA159FF7F96E51, 0xEA1A31EFE2CB850F, 0x89187C302364AA10,
    },
    .SizeWords = 24
};
const bignum TEST_BIGNUM_0_SUM =
{
    .Num =
    {
        0xD5FFBBF1F94D8214, 0xE6D95EBA165E0C16, 0x758B4888CE06552, 0x7DFA654257F11EC6, 0x6C0B5328EC70FF02,
        0xBF7C5BB1DECD3272, 0xBBA170AB96BE3797, 0x8C7831A6B1031627, 0x3EA6BE5E29906C4A, 0xB879636559CAD632,
        0xA608C171E6C3ED37, 0x7E43CE403116D294, 0x308BE64A9B71032E, 0xA4DFE11F12FEAF80, 0x67001FDEA50564C8,
        0xA819DCC4D796ACCC, 0xBEB270CBF881EC68, 0x8C6ABD7B4EBEA54D, 0xB11A2D51748D55E7, 0x28B1B94B9D2AB147,
        0xA357121B353CDB99, 0xEEBAA66903CE0F34, 0x5EDF1A2E950747E9, 0x341C1A2622ACD0BE, 0x1,
    },
    .SizeWords = 25
};

const bignum TEST_BIGNUM_1_A =
{
    .Num =
    {
        0xFFFFFFFE
    },
    .SizeWords = 1234
};
const bignum TEST_BIGNUM_1_B =
{
    .Num =
    {
        0xFFFFFFFF
    },
    .SizeWords = 1
};

const bignum TEST_BIGNUM_2_LEFT =
{
    .Num =
    {
        0xC5232011939B3F18, 0x19A577AF3CF91A36, 0xEDCF9A1B00D3BC32, 0x55D0CC4D2373AACF, 0xDA1A3B3D31B537FD,
        0x8526477EF5E3D8D8, 0x85CCF73261F34F78, 0xD26056B9918CBC37, 0x1D71050FE460DAFD, 0x885C1F2BA3455042,
        0xF2F825F4037C7B8C, 0xDC76F3899CD8C7D4, 0x92E2CB6C74A5AF1E, 0x58C568A0F92A7E28, 0x3DF2F28AD45719DC,
        0xB0E387907C062D3, 0x2A10373CACCE9AE3, 0x51B1D36575388CF5, 0xE7B20336DAD1D933, 0x80E764F05F7B6D17,
        0xBF966B49D1890C09, 0xF8149A628692F429, 0x698E26D12E2C6BCC, 0xF2CC08C42F28C163,
    },
    .SizeWords = 24
};
const bignum TEST_BIGNUM_2_RIGHT =
{
    .Num =
    {
        0x59B2E77BD36D02DC, 0xA482909B8FB5CC8F, 0xA8486211074E0432, 0xB4BB1E8AF7B14CA8, 0x3B8161DA6B8C9ADB,
        0xBB74D096499F311A, 0xC992855A3601AD42, 0x8895ED221B3E20D1, 0x64917AA27E0A45CF, 0x8F42DAC7FDBCC1AE,
        0xAA07712465E45116, 0xB44DB728DD1BC925, 0x84F002D675A744E9, 0xFADC494A6FA20124, 0xF952CF1CA1664739,
        0x6C54B73234E8BBA0, 0x167177BCB17DAA40, 0x28CB2A013211329, 0x86A9B5C70300D475, 0x84EEF461E56754CA,
        0x22C286559E06C860, 0x8CBB52DBE9CAACD8, 0x6925AFAF84B7E8CB, 0x6D479F3EECB8331D,
    },
    .SizeWords = 24
};
const bignum TEST_BIGNUM_2_SUM_MOD_P =
{
    .Num =
    {
        0x1ED6078D670841F5, 0xCCB39C42028B739E, 0x2F0BC6DDBD65285F, 0x6BB6C1D0AA8E610B, 0xF938A9C17CBC801D,
        0xBD35BAF162DF5C5C, 0xE6493CE39AD02D5B, 0xC21BFBA59075096E, 0xC00202F9C10761C7, 0xCE7693A1B41DB6B2,
        0xEE607306ED15ACBC, 0xA28C3EB71F6AF154, 0xBD3718BF6463C1A, 0x5F556F01C29491E2, 0x52C00C31135EE24F,
        0x2781BA3DCF575C2E, 0x1056A48B6BED30EC, 0x64A96C51BB1F5D03, 0x1D11B0844F9EA8CA, 0x3CA9AAC09CF26C0,
        0xB956A396E52807F6, 0xC0098AB2EF818430, 0x9A3FBDE917B9263, 0x6013A8031BE0F481,
    },
    .SizeWords = 24
};


const bignum TEST_BIGNUM_2_DIFFERENCE =
{
    .Num =
    {
        0x6B703895C02E3C3C, 0x7522E713AD434DA7, 0x45873809F985B7FF, 0xA115ADC22BC25E27, 0x9E98D962C6289D21,
        0xC9B176E8AC44A7BE, 0xBC3A71D82BF1A235, 0x49CA6997764E9B65, 0xB8DF8A6D6656952E, 0xF9194463A5888E93,
        0x48F0B4CF9D982A75, 0x28293C60BFBCFEAF, 0xDF2C895FEFE6A35, 0x5DE91F5689887D04, 0x44A0236E32F0D2A2,
        0x9EB98146D2D7A732, 0x139EBF7FFB50F0A2, 0x4F2520C5621779CC, 0x61084D6FD7D104BE, 0xFBF8708E7A14184D,
        0x9CD3E4F4338243A8, 0x6B5947869CC84751, 0x687721A9748301, 0x8584698542708E46,
    },
    .SizeWords = 24
};

const bignum TEST_BIGNUM_2_PRODUCT =
{
    .Num =
    {
        0xCCA78E4B52068A0, 0xC7B0807EA66615EB, 0xBF7DAE630CBBC0EF, 0x37A9136098745A21, 0x5798E028B0810DD4,
        0xC5C5E1F3CCD96BBB, 0x26278F265B8A3413, 0xA76C25D2A9D624C, 0x84A32738B9F5AD91, 0xE94132A37106C54D,
        0x518DAD6D9D0CA900, 0xEE7564CAD07E930, 0x42A5395DFCA56228, 0xEF1423FC95DA214F, 0xE874584AD76F75D2,
        0x6FAF4254F3F452E1, 0x3D0703FBEBC23119, 0xEDF68AB4EE213EFF, 0x5B0B89DFACF27484, 0x57F0BBC4F6AC5490,
        0x44F8EC9417985BFF, 0x3CE7327A55851A8, 0x84CD19591D3D46E5, 0x93C7D6AA22746645, 0xE8A9EFE928A25617,
        0x3A8DBB701EF00C8, 0xD68A185F14FF00F5, 0x399FC8C02C30CE60, 0x839610978A50E1E8, 0xB55F8EFF0FFEC7F5,
        0x5D68C84B05F7A700, 0xDAEB39F375B24671,
    },
    .SizeWords = 32
};

internal u32
NthPowerModP(u32 Value, u32 Power, u32 Prime)
{
    u32 Result = 1;

    for (u32 PowerIndex = 0;
         PowerIndex < Power;
         ++PowerIndex)
    {
        Result = (Value*Result) % Prime;
    }

    return Result;
}

internal MIN_UNIT_TEST_FUNC(TestDiffieHellmanWord)
{
    u32 A = rand() % DH_PRIME;
    u32 GPowerAModP = NthPowerModP(DH_GENERATOR, A, DH_PRIME);

    u32 B = rand() % DH_PRIME;
    u32 GPowerBModP = NthPowerModP(DH_GENERATOR, B, DH_PRIME);

    u32 SessionKeyA = NthPowerModP(GPowerBModP, A, DH_PRIME);
    u32 SessionKeyB = NthPowerModP(GPowerAModP, B, DH_PRIME);

    MinUnitAssert(SessionKeyA == SessionKeyB, "Session-key mismatch in TestDiffieHellmanWord!");
}

internal MIN_UNIT_TEST_FUNC(TestIsAGreaterThanB)
{
    MinUnitAssert(IsAGreaterThanB((bignum *)&TEST_BIGNUM_0_SUM, (bignum *)&TEST_BIGNUM_0_RIGHT) &&
                  (!IsAGreaterThanB((bignum *)&TEST_BIGNUM_0_LEFT, (bignum *)&TEST_BIGNUM_0_SUM)) &&
                  (!IsAGreaterThanB((bignum *)&TEST_BIGNUM_1_A, (bignum *)&TEST_BIGNUM_1_B)),
                  "Bad response in TestIsAGreaterThanB!");
}

internal MIN_UNIT_TEST_FUNC(TestBigNumAdd)
{
    BigNumAdd(&GlobalScratchBigNumA, (bignum *)&TEST_BIGNUM_0_LEFT, (bignum *)&TEST_BIGNUM_0_RIGHT);

    MinUnitAssert(GlobalScratchBigNumA.SizeWords == TEST_BIGNUM_0_SUM.SizeWords,
                  "SizeWords incorrect in TestBigNumAdd!");
    MinUnitAssert(VectorsEqual(GlobalScratchBigNumA.Num, (void *)TEST_BIGNUM_0_SUM.Num,
                               sizeof(u64)*TEST_BIGNUM_0_SUM.SizeWords),
                  "Expected/actual mismatch in TestBigNumAdd!");
}

internal MIN_UNIT_TEST_FUNC(TestBigNumSubtract)
{
    BigNumSubtract(&GlobalScratchBigNumA, (bignum *)&TEST_BIGNUM_2_LEFT, (bignum *)&TEST_BIGNUM_2_RIGHT);

    MinUnitAssert(GlobalScratchBigNumA.SizeWords == TEST_BIGNUM_2_DIFFERENCE.SizeWords,
                  "SizeWords incorrect in TestBigNumAdd!");
    MinUnitAssert(VectorsEqual(GlobalScratchBigNumA.Num, (void *)TEST_BIGNUM_2_DIFFERENCE.Num,
                               sizeof(u64)*TEST_BIGNUM_2_DIFFERENCE.SizeWords),
                  "Expected/actual mismatch in TestBigNumAdd!");

    BigNumSubtract(&GlobalScratchBigNumA, &GlobalScratchBigNumA, &GlobalScratchBigNumA);

    MinUnitAssert(GlobalScratchBigNumA.SizeWords == 0, "Expected (X - X) == 0 in TestBigNumSubtract!");
}

// TODO(bwd): Test case where A + B overflow 2^(W*t)
internal MIN_UNIT_TEST_FUNC(TestBigNumAddModN)
{
    BigNumAddModN(&GlobalScratchBigNumA, (bignum *)&TEST_BIGNUM_2_LEFT, (bignum *)&TEST_BIGNUM_2_RIGHT,
                  (bignum *)&NIST_RFC_3526_PRIME_1536);

    MinUnitAssert(GlobalScratchBigNumA.SizeWords == TEST_BIGNUM_2_SUM_MOD_P.SizeWords,
                  "SizeWords incorrect in TestBigNumAddModN!");
    MinUnitAssert(VectorsEqual(GlobalScratchBigNumA.Num, (void *)TEST_BIGNUM_2_SUM_MOD_P.Num,
                               sizeof(u64)*TEST_BIGNUM_2_SUM_MOD_P.SizeWords),
                  "Expected/actual mismatch in TestBigNumAddModN!");
}

internal MIN_UNIT_TEST_FUNC(TestBigNumMultiply)
{
    BigNumMultiplyOperandScanning(&GlobalScratchBigNumA,
                                  (bignum *)&TEST_BIGNUM_2_LEFT, (bignum *)&TEST_BIGNUM_2_RIGHT);

    MinUnitAssert(VectorsEqual(GlobalScratchBigNumA.Num, (void *)TEST_BIGNUM_2_PRODUCT.Num,
                               sizeof(u64)*TEST_BIGNUM_2_PRODUCT.SizeWords),
                  "Expected/actual mismatch in TestBigNumMultiply!");
}

internal inline void
GenRandBigNumModNUnchecked(bignum *A, bignum *N)
{
    GenRandUnchecked((u32 *)A->Num, 2*N->SizeWords);

    // TODO(bwd): hangs; more efficient algorithm
    while (!IsAGreaterThanB(N, A))
    {
        BigNumSubtract(A, A, N);
    }

    A->SizeWords = N->SizeWords;

    AdjustSizeWordsDownUnchecked(A);
}

internal MIN_UNIT_TEST_FUNC(TestFindNInverseModR)
{
    bignum TwoPower1792;
    memset(&TwoPower1792, 0, sizeof(TwoPower1792));

    TwoPower1792.SizeWords = (1792/BITS_IN_DWORD) + 1;
    TwoPower1792.Num[TwoPower1792.SizeWords - 1] = 1;

    bignum NInverseModR;
    FindNInverseModR(&NInverseModR, (bignum *)&NIST_RFC_3526_PRIME_1536, &TwoPower1792);
    MinUnitAssert(IsInverseOfNMod2PowerKUnchecked((bignum *)&NIST_RFC_3526_PRIME_1536, &NInverseModR, 1792),
                  "No NInverse found mod R in TestFindNInverseModR!");
}

internal MIN_UNIT_TEST_FUNC(TestDiffieHellmanBigNum)
{
#if 0
    GenRandBigNumModNUnchecked((bignum *)&GlobalScratchBigNumA, (bignum *)&NIST_RFC_3526_PRIME_1536);
    GenRandBigNumModNUnchecked((bignum *)&GlobalScratchBigNumB, (bignum *)&NIST_RFC_3526_PRIME_1536);
#endif
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestDiffieHellmanWord);
	MinUnitRunTest(TestBigNumAdd);
	MinUnitRunTest(TestBigNumSubtract);
	MinUnitRunTest(TestBigNumAddModN);
	MinUnitRunTest(TestBigNumMultiply);
	MinUnitRunTest(TestFindNInverseModR);
	MinUnitRunTest(TestDiffieHellmanBigNum);
}

int main()
{
	srand(time(0));
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
