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

global_variable bignum GlobalScratchBigNum;

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

internal MIN_UNIT_TEST_FUNC(TestBigNumAddModN)
{
}

internal MIN_UNIT_TEST_FUNC(TestBigNumAdd)
{
    BigNumAdd(&GlobalScratchBigNum, (bignum *)&TEST_BIGNUM_0_LEFT, (bignum *)&TEST_BIGNUM_0_RIGHT);

    MinUnitAssert(VectorsEqual(GlobalScratchBigNum.Num, (void *)TEST_BIGNUM_0_SUM.Num,
                               sizeof(u64)*TEST_BIGNUM_0_SUM.SizeWords),
                  "Expected/actual mismatch in TestBigNumAdd!");
}

internal MIN_UNIT_TEST_FUNC(TestDiffieHellmanBigNum)
{
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestDiffieHellmanWord);
	MinUnitRunTest(TestBigNumAdd);
	MinUnitRunTest(TestBigNumAddModN);
	MinUnitRunTest(TestDiffieHellmanBigNum);
}

int main()
{
	srand(time(0));
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
