#include "crypt_helper.h"
#include <openssl/rsa.h>

internal u32 TEST_OAEP_MODULUS[] =
{
    0xDE458BC0,	0xB9244EDC,	0x961558C4,	0xF728D633,	0x54ED485E,	0x04201371,
    0xF6CCF1E8,	0xFE492B64,	0x705DECD3,	0x6AE854C5,	0xD9B4A0FF,	0xD0A98EA7,
    0x5B279B71,	0x8C3ED86F,	0x744E93C4,	0x56AEA310,	0xAC981782,	0x0582B03A,
    0xFA1B2963,	0x60C7F0A3,	0x57CDE8EB,	0x7B92AAA6,	0xA5C73817,	0x56A71570,
    0xD23A4FE2,	0x6851E4EF,	0xDC19430E,	0x9A66C941,	0x9490DB5A,	0xB394A8E6,
    0xF7E1D48A,	0xF2AFD20C,	0xB969619C,	0x7EC18CD3,	0xAEB74C97,	0x517120C7,
    0x10744CDD,	0xA88D36A2,	0x7E0CC348,	0x597ADD01,	0x3E272533,	0xDD653A4A,
    0x27D6FA7A,	0x04ED1F7B,	0x9B64EB69,	0x6A1771FD,	0x9C8E5625,	0x3569B2FB,
    0x52C17FF5,	0xD8A53EE3,	0xC910F8AE,	0x1CA2E524,	0x66F87FAB,	0xBE9FA492,
    0xEE733DA4,	0x9056B50F,	0x0B99A3CC,	0x4CE448A0,	0x80389F63,	0xF9AFD5AC,
    0x2189043F,	0x7C5015AA,	0x318BFEC7,	0xDBC8F7FF
};

internal u32 TEST_OAEP_PRIVATE_KEY_D[] =
{
    0x5A054E79,	0xA1E7BF0F,	0xDEFCD265,	0x45D68FA1,	0x7D55906A,	0xE3D2B372,
    0xD7190365,	0x767C6A4D,	0xAF347BE0,	0xCE4E935C,	0x17B47842,	0x20C059C0,
    0x3C35C2C3,	0xD25E2D85,	0x66B3F1FE,	0x280529AA,	0x6BD65319,	0x7FBA9A03,
    0xEB6466BC,	0x64F6A736,	0xEAD59BD8,	0xDEF4E4D7,	0xE91AD639,	0xA9B5C0DE,
    0x25B670A6,	0x6E46DFB8,	0x30E33561,	0xF669FE01,	0x581331EB,	0x6AFF2CCC,
    0xB8261852,	0xF080CAA7,	0x4972C427,	0xAA16ACC4,	0x551AF2C2,	0xA6B48DB0,
    0x470698D2,	0x308E743C,	0x96E0D06A,	0x21F4EA7C,	0x5AF0BEA4,	0x57E76945,
    0x17FBEEFD,	0x486B87BB,	0xB428D6D8,	0xD8FE2402,	0xCA55C548,	0x33E725C7,
    0xD061F85B,	0x9D1D37F8,	0x4FF20697,	0x00DEF75F,	0xB4E43426,	0xFA8739BE,
    0x0493517D,	0x5E4803C6,	0x3A334EE6,	0xA0CA3951,	0x67610417,	0xF1BAD10C,
    0x82D6A4A8,	0xFB199B06,	0xC14E84CB,	0xE1148139
};

internal u32 TEST_OAEP_CIPHERTEXT[] =
{
    0xE993ECAD, 0xFD0A87CE, 0xC1DCD5E8, 0x99595699, 0xADC18333, 0x8762C5A6,
    0xBA142A8B, 0x58C8C1ED, 0xFAF9BB21, 0xB147DACA, 0x6E6F9CC1, 0x13A48387,
    0xD6CA3C65, 0x367131CB, 0xFA906ACC, 0xF528DE10, 0xDE6E5117, 0x02952089,
    0x303C7D24, 0xCF37C531, 0x42A49383, 0xABCBA46F, 0x58B377A1, 0xF8D33F8A,
    0x6E98BE66, 0x56F06836, 0x064C707D, 0xF4C87739, 0x6DB0CC03, 0xB89C02CB,
    0xB14D7D54, 0x0F777F14, 0x150D0F41, 0xF7387BB9, 0xEB8A36E2, 0x032C0166,
    0x8B8F0BF5, 0xBBD6724E, 0x97E5E37B, 0x9C10A8E7, 0x9D01F7CF, 0x9B1BDD7A,
    0x61417C44, 0x13535C89, 0xF91C048E, 0xF26D5391, 0x27E9C7D8, 0xC8939CD3,
    0x4FF847A5, 0x5D2D8182, 0x1636213E, 0x3A5C942C, 0x2A812247, 0xA46A1552,
    0x0735EADD, 0x37A99583, 0x22978A92, 0x19258B0E, 0x421BE8C6, 0x05DB0A3A,
    0x0CC9B9BD, 0xC8F25A49, 0x8B28C57D, 0xB4DE94E7
};

internal u32 TEST_OAEP_EXPECTED_PT[] =
{
    0x7121C500, 0x22FD81F0, 0xEF120DB2, 0xBECD89DA, 0xB3D1663C, 0x95EA7D0B,
    0xBC2E8D4D, 0x06F0D372, 0x7EC078F0, 0xD5795DF3, 0x5CFD0960, 0xB8536CA2,
    0xDBC7BA9F, 0xF9C3A9AB, 0xCF472631, 0xF51FCD95, 0xC30EEB82, 0x518D2FB9,
    0xC422F8C0, 0xEB1741D0, 0x22077D0D, 0xE7221F3F, 0x5E6E31FD, 0x04189412,
    0x88E2AD37, 0x1684E36C, 0xAB19D664, 0xAB9D6EA4, 0x588C3301, 0x3C520ECF,
    0x59778B12, 0x81EC85CE, 0xCA80D0DB, 0xFB94E6C0, 0x7356C8A6, 0x287696E0,
    0x820FBE2F, 0x075D0E29, 0x24EE81E5, 0x2633C963, 0x44CFAC79, 0x2635E037,
    0xA3C50062, 0x58794987, 0x5E3EC9F8, 0x387F7939, 0x069A2707, 0x037AF987,
    0x58010FD1, 0x9026CBAA, 0x2C45247D, 0xB54A2C8D, 0x3536A3DB, 0xC0A8E7A3,
    0x7C546375, 0xBFBC6045, 0x251638D7, 0xBEB4325C, 0x56C0D86D, 0x43F6CCEC,
    0x1245FFBB,	0x23E46012,	0xB4FE0B59,	0xA3D174EA,
};

internal u8 TEST_OAEP_PRIME_P[] =
{
    0xf2, 0x13, 0x74, 0x76, 0x7c, 0xfd, 0x4e, 0x98,
    0x07, 0xc3, 0xf3, 0xbd, 0x28, 0x51, 0x9a, 0x7c,  0x50, 0xab, 0x59, 0xbe, 0x66, 0xae, 0x81, 0x52,
    0x24, 0x94, 0x38, 0x99, 0xe5, 0x48, 0xbe, 0xc8,  0x14, 0x52, 0x36, 0x76, 0xde, 0x5b, 0x7a, 0x65,
    0xfd, 0xa0, 0xc0, 0x5f, 0xab, 0xde, 0xc5, 0xde,  0x89, 0x63, 0x23, 0x0d, 0xc9, 0xd0, 0xdb, 0xad,
    0x6f, 0x2a, 0x30, 0xf5, 0x7f, 0x77, 0x33, 0xa0,  0x35, 0x85, 0x35, 0x0c, 0x49, 0x5f, 0xa8, 0xc4,
    0x66, 0xa4, 0x50, 0x9a, 0x4d, 0xbf, 0x45, 0x99,  0xf1, 0x86, 0x3b, 0x2c, 0x09, 0xf6, 0x42, 0x47,
    0xc2, 0x61, 0x1f, 0x13, 0xc0, 0xf5, 0xeb, 0x47,  0x2d, 0x21, 0xd0, 0x8c, 0x24, 0x6e, 0xce, 0x8d,
    0x43, 0x94, 0x15, 0x72, 0xf6, 0x87, 0x55, 0x6e,  0xba, 0xc0, 0x68, 0xd0, 0x59, 0x4f, 0x23, 0x47,
    0xa6, 0xbf, 0x5e, 0x75, 0x30, 0xfc, 0x41, 0xa3,
};

internal MIN_UNIT_TEST_FUNC(TestOaep)
{
    bignum Ciphertext;
    BigNumFromBigEndianArrayUnchecked(&Ciphertext, TEST_OAEP_CIPHERTEXT, sizeof(TEST_OAEP_CIPHERTEXT));

    bignum PrivateKey;
    BigNumFromBigEndianArrayUnchecked(&PrivateKey, TEST_OAEP_PRIVATE_KEY_D, sizeof(TEST_OAEP_PRIVATE_KEY_D));

    bignum Modulus;
    BigNumFromBigEndianArrayUnchecked(&Modulus, TEST_OAEP_MODULUS, sizeof(TEST_OAEP_MODULUS));

    bignum RecoveredPt;
    MontModExpRBigNumMax(&RecoveredPt, &Ciphertext, &PrivateKey, &Modulus);

    ByteSwap((u8 *)TEST_OAEP_EXPECTED_PT, sizeof(TEST_OAEP_EXPECTED_PT));
    Stopif((BigNumSizeBytesUnchecked(&RecoveredPt) != sizeof(TEST_OAEP_EXPECTED_PT)) ||
           memcmp(TEST_OAEP_EXPECTED_PT, RecoveredPt.Num, sizeof(TEST_OAEP_EXPECTED_PT)),
           "Expected/unexpected mismatch in TestOaep!\n");

    Stopif(sizeof(TEST_OAEP_PRIME_P) % sizeof(u64), "Prime length not divisible by word size!\n");

    BIGNUM SensitiveTpmPrime;
    u32 TestOaepPrimePSizeDWords = sizeof(TEST_OAEP_PRIME_P)/sizeof(u64);
    InitOsslBnUnchecked(&SensitiveTpmPrime,
                        (u64 *)TEST_OAEP_PRIME_P,
                        TestOaepPrimePSizeDWords,
                        TestOaepPrimePSizeDWords);

    ByteSwap((u8 *)TEST_OAEP_PRIME_P, sizeof(TEST_OAEP_PRIME_P));
    i32 Status = BN_is_prime_ex(&SensitiveTpmPrime, 2048, 0, 0);
    if (Status == -1)
    {
        OsslPrintErrors();
        Stopif(true, "BN_is_prime_ex failed in TestOaep!\n");
    }
    Stopif(Status == 0, "Test \"prime\" is composite in TestOaep!\n");
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
    MinUnitRunTest(TestOaep);
}

int main()
{
    srand(time(0));
    AllTests();
    printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
