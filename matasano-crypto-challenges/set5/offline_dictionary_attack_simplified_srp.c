#include "crypt_helper.h"

#define MESSAGE_SCRATCH_SIZE_BYTES 64

internal inline void
SimpleSrpGetHmacKSaltUnchecked(u8 *HmacKSalt, bignum *PremasterSecret, bignum *Salt)
{
    u8 K[SHA_1_HASH_LENGTH_BYTES];
    Sha1(K, (u8 *)PremasterSecret->Num, BigNumSizeBytesUnchecked(PremasterSecret));

    HmacSha1(HmacKSalt, K, sizeof(K), (u8 *)Salt->Num, BigNumSizeBytesUnchecked(Salt));
}

const u64 TEST_LITTLE_U[] =
{
    0x308e51fd2291bb37, 0x6d8bb86f06266075
};

const u8 DICTIONARY[] =
{
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
    'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
    'V', 'W', 'X', 'Y', 'Z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
};
const u32 DICT_ENTRY_COUNT = ARRAY_LENGTH(DICTIONARY);

const char TEST_PASSWORD[] = "alice1";

global_variable char GlobalGuessPasswords[30*SIZE_1MB];

internal void
ClientSimpleGetHmacPremasterSecret(u8 *ClientHmacKSalt, bignum *LittleU, bignum *LittleX, bignum *BigB)
{
    Stopif((ClientHmacKSalt == 0) || (LittleU == 0) || (LittleX == 0) || (BigB == 0),
           "Null input to ClientSimpleGetHmacPremasterSecret!");

    // BigNumScratch := u*x
    bignum BigNumScratch;
    BigNumMultiplyOperandScanning(&BigNumScratch, LittleU, LittleX);

    // BigNumScratch := a + (u * x)
    BigNumAdd(&BigNumScratch, (bignum *)&RFC_5054_TEST_LITTLE_A, &BigNumScratch);

    // BigNumScratch := <premaster secret>
    MontModExpRBigNumMax(&BigNumScratch,
                         BigB,
                         &BigNumScratch,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

    SimpleSrpGetHmacKSaltUnchecked(ClientHmacKSalt, &BigNumScratch, (bignum *)&RFC_5054_TEST_SALT);
}

internal void
ServerSimpleGetHmacPremasterSecret(u8 *ServerHmacKSalt, bignum *LittleU, bignum *LittleX, bignum *LittleB)
{
    Stopif((ServerHmacKSalt == 0) || (LittleU == 0) || (LittleX == 0) || (LittleB == 0),
           "Null input to ServerSimpleGetHmacPremasterSecret!");

    bignum BigNumScratch;
    bignum LittleV;
    MontModExpRBigNumMax(&LittleV,
                         (bignum *)&NIST_RFC_5054_GEN_BIGNUM,
                         LittleX,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

    // BigNumScratch := v ** u
    MontModExpRBigNumMax(&BigNumScratch,
                         &LittleV,
                         LittleU,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

    // BigNumScratch := A * v ** u % n
    BigNumMultiplyModP(&BigNumScratch,
                       (bignum *)&RFC_5054_TEST_BIG_A,
                       &BigNumScratch,
                       (bignum *)&RFC_5054_NIST_PRIME_1024);

    // BigNumScratch := <premaster secret>
    MontModExpRBigNumMax(&BigNumScratch,
                         &BigNumScratch,
                         LittleB,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

    SimpleSrpGetHmacKSaltUnchecked(ServerHmacKSalt, &BigNumScratch, (bignum *)&RFC_5054_TEST_SALT);
}

internal void
GetLittleX(bignum *LittleX, char *Password, u32 PasswordSizeBytes)
{
    Stopif((LittleX == 0) || (Password == 0), "Null input to GetLittleX!");

    u32 SaltSizeBytes = BigNumSizeBytesUnchecked((bignum *)&RFC_5054_TEST_SALT);
    u32 XMessageSizeBytes = SaltSizeBytes + PasswordSizeBytes;

    u8 MessageScratch[MESSAGE_SCRATCH_SIZE_BYTES];
    Stopif(XMessageSizeBytes > sizeof(MessageScratch),
           "Buffer overflow in TestOfflineDictAttackSimplifiedSrp!\n");

    memcpy(MessageScratch, (u8 *)RFC_5054_TEST_SALT.Num, SaltSizeBytes);
    memcpy(MessageScratch + SaltSizeBytes, Password, PasswordSizeBytes);

    u32 LittleXSizeDWords = SHA_1_HASH_LENGTH_BYTES/sizeof(u64) + 1;
    memset(LittleX->Num, 0, LittleXSizeDWords*sizeof(u64));

    Sha1((u8 *)LittleX->Num, MessageScratch, XMessageSizeBytes);
    LittleX->SizeWords = LittleXSizeDWords;
    LittleX->Negative = false;
}

internal MIN_UNIT_TEST_FUNC(TestOfflineDictAttackSimplifiedSrp)
{
    /*
        S:      x = SHA256(salt|password)
                v = g**x % n

        C->S:   I, A = g**a % n

        S->C:   salt, B = g**b % n, u = 128 bit random number

        C:      x = SHA256(salt|password)
                S = B**(a + ux) % n
                K = SHA256(S)

        S:      S = (A * v ** u)**b % n
                K = SHA256(S)

        C->S:   Send HMAC-SHA256(K, salt)

        S->C:   Send "OK" if HMAC-SHA256(K, salt) validates
    */

    // LittleX calculated identically, so do it once
    bignum LittleX;
    GetLittleX(&LittleX, (char *)TEST_PASSWORD, STR_LEN(TEST_PASSWORD));

    bignum LittleU;
    u32 LittleUSize32BitWords = 128/BITS_IN_WORD;
    GenRandUnchecked((u32 *)LittleU.Num, LittleUSize32BitWords);
    LittleU.SizeWords = LittleUSize32BitWords/2;
    LittleU.Negative = false;

    // BigB := g**b (calculated by Server)
    bignum BigB;
    MontModExpRBigNumMax(&BigB,
                         (bignum *)&NIST_RFC_5054_GEN_BIGNUM,
                         (bignum *)&RFC_5054_TEST_LITTLE_B,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

    // Client
    u8 ClientHmacKSalt[SHA_1_HASH_LENGTH_BYTES];
    ClientSimpleGetHmacPremasterSecret(ClientHmacKSalt, &LittleU, &LittleX, &BigB);

    // Server
    u8 ServerHmacKSalt[SHA_1_HASH_LENGTH_BYTES];
    ServerSimpleGetHmacPremasterSecret(ServerHmacKSalt, &LittleU, &LittleX, (bignum *)&RFC_5054_TEST_LITTLE_B);

    MinUnitAssert(AreVectorsEqual(ServerHmacKSalt, ClientHmacKSalt, sizeof(ServerHmacKSalt)),
                  "Hmac mismatch in TestOfflineDictAttackSimplifiedSrp!\n");

    // Server chooses fake b, B, u and salt and cracks password from Client's HMAC-SHA256(K, salt)
    BigB.SizeWords = 1;
    BigB.Num[0] = 2;

    LittleU.SizeWords = 1;
    LittleU.Num[0] = 1;

    // Client
    ClientSimpleGetHmacPremasterSecret(ClientHmacKSalt, &LittleU, &LittleX, &BigB);

    // Server offline attack
    const char PWD_GUESS_FILENAME[] = "password_guesses_20";
    FILE *GuessPasswords = fopen(PWD_GUESS_FILENAME, "r");
    Stopif(GuessPasswords == 0,
           "fopen failed on %s in TestOfflineDictAttackSimplifiedSrp!",
           PWD_GUESS_FILENAME);

    u32 ReadBytes = fread(GlobalGuessPasswords, 1, sizeof(GlobalGuessPasswords), GuessPasswords);
    Stopif(ReadBytes >= (sizeof(GlobalGuessPasswords) - 1),
           "File not completely read in TestOfflineDictAttackSimplifiedSrp!");

    GlobalGuessPasswords[ReadBytes] = 0;

    b32 FoundPassword = false;
    char *NextPwdGuess;
    char *EndOfNextPwdGuess;
    u32 NextPwdGuessSizeBytes;
    bignum ServerPremasterSecret;
    bignum LittleV;
    for (NextPwdGuess = GlobalGuessPasswords, EndOfNextPwdGuess = strchr(GlobalGuessPasswords, '\n');
         EndOfNextPwdGuess;
         EndOfNextPwdGuess = strchr(EndOfNextPwdGuess, '\n'))
    {
        *EndOfNextPwdGuess++ = 0;

        NextPwdGuessSizeBytes = EndOfNextPwdGuess - NextPwdGuess - 1;

        GetLittleX(&LittleX, NextPwdGuess, NextPwdGuessSizeBytes);

        // S = (A * v ** u)**b % n == A * v % n (since u == 1 and b == 1)
        // v := g ** x
        MontModExpRBigNumMax(&LittleV,
                             (bignum *)&NIST_RFC_5054_GEN_BIGNUM,
                             &LittleX,
                             (bignum *)&RFC_5054_NIST_PRIME_1024);

        // ServerPremasterSecret := A * v % n
        BigNumMultiplyModP(&ServerPremasterSecret,
                           (bignum *)&RFC_5054_TEST_BIG_A,
                           &LittleV,
                           (bignum *)&RFC_5054_NIST_PRIME_1024);

        SimpleSrpGetHmacKSaltUnchecked(ServerHmacKSalt,
                                       &ServerPremasterSecret,
                                       (bignum *)&RFC_5054_TEST_SALT);

        if (!memcmp(ServerHmacKSalt, ClientHmacKSalt, sizeof(ClientHmacKSalt)))
        {
            FoundPassword = true;
            break;
        }

        NextPwdGuess = EndOfNextPwdGuess;
    }

    MinUnitAssert(FoundPassword &&
                  !memcmp(NextPwdGuess, TEST_PASSWORD, STR_LEN(TEST_PASSWORD)) &&
                  (NextPwdGuessSizeBytes == STR_LEN(TEST_PASSWORD)),
                  "Password not guessed in TestOfflineDictAttackSimplifiedSrp!\n");
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestOfflineDictAttackSimplifiedSrp);
}

int main()
{
	srand(time(0));
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
