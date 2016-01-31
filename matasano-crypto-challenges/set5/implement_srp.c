#include "crypt_helper.h"

// Source for RFC 5054: https://tools.ietf.org/html/rfc5054

#define GLOBAL_COMMAND_MAX_SIZE 128

char GlobalCommand[GLOBAL_COMMAND_MAX_SIZE] = "srp?";

CASSERT(sizeof(GlobalCommand) >= TEST_USER_CMD_LENGTH, implement_srp_c);

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

// TODO(bwd): generate salt as random integer (second test)

internal void
ClientGetPremasterSecret(bignum *OutputSecret,
                         bignum *BigB,
                         u8 *LittleK,
                         bignum *Gen,
                         u8 *LittleX,
                         bignum *LittleA,
                         u8 *LittleU,
                         bignum *PrimeModulusN)
{
    Stopif((OutputSecret == 0) ||
           (BigB == 0) ||
           (LittleK == 0) ||
           (Gen == 0) ||
           (LittleX == 0) ||
           (LittleA == 0) ||
           (LittleU == 0) ||
           (PrimeModulusN == 0),
           "Null input to ClientGetPremasterSecret!\n");

    bignum LittleXBigNum;
    HashOutputToBigNumUnchecked(&LittleXBigNum, LittleX);

    // OutputSecret := g^x
    MontModExpRBigNumMax(OutputSecret, Gen, &LittleXBigNum, PrimeModulusN);

    bignum LittleKBigNum;
    HashOutputToBigNumUnchecked(&LittleKBigNum, LittleK);

    Stopif((LittleKBigNum.SizeWords + OutputSecret->SizeWords + 1) > MAX_BIGNUM_SIZE_WORDS,
           "Potential overflow on multiplying k*g^x in TestImplementSrpTestVec!\n");

    // OutputSecret := k * g^x (mod N)
    BigNumMultiplyModP(OutputSecret, &LittleKBigNum, OutputSecret, PrimeModulusN);

    // OutputSecret := (B - (k * g^x))
    BigNumSubtractModP(OutputSecret, BigB, OutputSecret, PrimeModulusN);

    // BigNumScratchExponent := u * x
    bignum LittleUBigNum;
    HashOutputToBigNumUnchecked(&LittleUBigNum, LittleU);

    bignum BigNumScratchExponent;
    BigNumMultiplyOperandScanning(&BigNumScratchExponent, &LittleUBigNum, &LittleXBigNum);

    // BigNumScratchExponent := a + (u * x)
    BigNumAdd(&BigNumScratchExponent, LittleA, &BigNumScratchExponent);

    // OutputSecret := <premaster secret>
    MontModExpRBigNumMax(OutputSecret, OutputSecret, &BigNumScratchExponent, PrimeModulusN);
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

    u32 PSizeBytes = BigNumSizeBytesUnchecked((bignum *)&RFC_5054_NIST_PRIME_1024);
    u8 MessageScratch[2*PSizeBytes];

    // u := SHA1(PAD(A) | PAD(B))
    u8 LittleU[SHA_1_HASH_LENGTH_BYTES];
    Sha1PaddedAConcatPaddedB(LittleU,
                             MessageScratch,
                             &BigA,
                             (bignum *)&RFC_5054_TEST_BIG_B,
                             PSizeBytes);

    MinUnitAssert(AreVectorsEqualByteSwapped(LittleU, (u8 *)RFC_5054_TEST_U.Num, sizeof(LittleU)),
                  "Little u mismatch (Client) in TestImplementSrpTestVec!\n");

    // k := SHA1(N | PAD(g))
    u8 LittleK[SHA_1_HASH_LENGTH_BYTES];
    Sha1PaddedAConcatPaddedB(LittleK,
                             MessageScratch,
                             (bignum *)&RFC_5054_NIST_PRIME_1024,
                             (bignum *)&NIST_RFC_5054_GEN_BIGNUM,
                             PSizeBytes);

    MinUnitAssert(AreVectorsEqualByteSwapped(LittleK, (u8 *)RFC_5054_TEST_K.Num, sizeof(LittleK)),
                  "Little k mismatch (Client) in TestImplementSrpTestVec!\n");

    u8 LittleX[SHA_1_HASH_LENGTH_BYTES];
    u32 SaltLengthBytes = BigNumSizeBytesUnchecked((bignum *)&RFC_5054_TEST_SALT);
    SrpGetX(LittleX,
            (u8 *)RFC_5054_TEST_SALT.Num,
            SaltLengthBytes,
            MessageScratch,
            sizeof(MessageScratch),
            (u8 *)SRP_TEST_VEC_EMAIL,
            STR_LEN(SRP_TEST_VEC_EMAIL),
            (u8 *)SRP_TEST_VEC_PASSWORD,
            STR_LEN(SRP_TEST_VEC_PASSWORD));

    MinUnitAssert(AreVectorsEqualByteSwapped(LittleX, (u8 *)RFC_5054_TEST_X.Num, sizeof(LittleX)),
                  "Little x mismatch (Client) in TestImplementSrpTestVec!\n");

    // <premaster secret> = (B - (k * g^x)) ^ (a + (u * x)) % N
    bignum BigNumScratch;
    ClientGetPremasterSecret(&BigNumScratch,
                             (bignum *)&RFC_5054_TEST_BIG_B,
                             LittleK,
                             (bignum *)&NIST_RFC_5054_GEN_BIGNUM,
                             LittleX,
                             (bignum *)&RFC_5054_TEST_LITTLE_A,
                             LittleU,
                             (bignum *)&RFC_5054_NIST_PRIME_1024);

    MinUnitAssert(AreVectorsEqual(BigNumScratch.Num,
                                  (void *)RFC_5054_TEST_PREMASTER_SECRET.Num,
                                  RFC_5054_TEST_PREMASTER_SECRET.SizeWords) &&
                  (BigNumScratch.SizeWords == RFC_5054_TEST_PREMASTER_SECRET.SizeWords),
                  "Premaster secret mismatch (Client) in TestImplementSrpTestVec!\n");

    // Server
    ServerGetPremasterSecret(&BigNumScratch,
                             (bignum *)&RFC_5054_TEST_V,
                             (bignum *)&RFC_5054_TEST_LITTLE_B,
                             (bignum *)&RFC_5054_TEST_BIG_A);

    MinUnitAssert(AreVectorsEqual(BigNumScratch.Num,
                                  (void *)RFC_5054_TEST_PREMASTER_SECRET.Num,
                                  RFC_5054_TEST_PREMASTER_SECRET.SizeWords) &&
                  (BigNumScratch.SizeWords == RFC_5054_TEST_PREMASTER_SECRET.SizeWords),
                  "Premaster secret mismatch (Server) in TestImplementSrpTestVec!\n");
}

internal MIN_UNIT_TEST_FUNC(TestClientServerAuth)
{
    /*
       Client                                            Server

       Client Hello (I)        -------->
                                                   Server Hello
                                                   Certificate*
                                            Server Key Exchange (N, g, s, B)
                               <--------      Server Hello Done
       Client Key Exchange (A) -------->
       [Change cipher spec]
       Finished                -------->
                                           [Change cipher spec]
                               <--------               Finished

       Application Data        <------->       Application Data
   */

    sockaddr_in ServerSocketAddr;
    ServerSocketAddr.sin_family = AF_INET;
    ServerSocketAddr.sin_addr.s_addr = inet_addr(IP_ADDRESS);
    ServerSocketAddr.sin_port = htons(PORT);

    memcpy(GlobalCommand + STR_LEN(TEST_SRP_PREFIX), USER_PREFIX, STR_LEN(USER_PREFIX));

    memcpy(GlobalCommand + STR_LEN(TEST_SRP_PREFIX) + STR_LEN(USER_PREFIX),
           SRP_TEST_VEC_EMAIL,
           STR_LEN(SRP_TEST_VEC_EMAIL));

    GlobalCommand[TEST_USER_CMD_LENGTH] = 0;

	i32 SocketFileDescriptor;
    OpenSocketAndConnect(&SocketFileDescriptor, &ServerSocketAddr);

    write(SocketFileDescriptor, GlobalCommand, TEST_USER_CMD_LENGTH);

    u8 ClientSendRecvBuffer[4*sizeof(bignum)];
    u32 ReadBytes = read(SocketFileDescriptor, ClientSendRecvBuffer, sizeof(ClientSendRecvBuffer));
    Stopif(ReadBytes != sizeof(ClientSendRecvBuffer),
           "Invalid bytes read from (N, g, s ,B) in TestClientServerAuth!");

    bignum ModulusN;
    BigNumCopyUnchecked(&ModulusN, (bignum *)ClientSendRecvBuffer);

    bignum LittleG;
    BigNumCopyUnchecked(&LittleG, (bignum *)ClientSendRecvBuffer + 1);

    bignum Salt;
    BigNumCopyUnchecked(&Salt, (bignum *)ClientSendRecvBuffer + 2);

    bignum BigB;
    BigNumCopyUnchecked(&BigB, (bignum *)ClientSendRecvBuffer + 3);

    BigNumCopyUnchecked((bignum *)ClientSendRecvBuffer, (bignum *)&RFC_5054_TEST_BIG_A);

    write(SocketFileDescriptor, ClientSendRecvBuffer, sizeof(ClientSendRecvBuffer));

    // u := SHA1(PAD(A) | PAD(B))
    u8 LittleU[SHA_1_HASH_LENGTH_BYTES];
    u32 ModulusSizeBytes = BigNumSizeBytesUnchecked((bignum *)&RFC_5054_NIST_PRIME_1024);
    u8 MessageScratch[2*ModulusSizeBytes];
    Sha1PaddedAConcatPaddedB(LittleU,
                             MessageScratch,
                             (bignum *)&RFC_5054_TEST_BIG_A,
                             &BigB,
                             ModulusSizeBytes);

    // k := SHA1(N | PAD(g))
    u8 LittleK[SHA_1_HASH_LENGTH_BYTES];
    Sha1PaddedAConcatPaddedB(LittleK,
                             MessageScratch,
                             (bignum *)&RFC_5054_NIST_PRIME_1024,
                             (bignum *)&NIST_RFC_5054_GEN_BIGNUM,
                             ModulusSizeBytes);

    MinUnitAssert(AreVectorsEqualByteSwapped(LittleK, (u8 *)RFC_5054_TEST_K.Num, sizeof(LittleK)),
                  "Little k mismatch (Client) in TestImplementSrpTestVec!\n");

    // x := SHA1(s | SHA1(I | ":" | P))
    u8 LittleX[SHA_1_HASH_LENGTH_BYTES];
    u32 SaltSizeBytes = BigNumSizeBytesUnchecked(&Salt);
    SrpGetX(LittleX,
            (u8 *)Salt.Num,
            SaltSizeBytes,
            MessageScratch,
            sizeof(MessageScratch),
            (u8 *)SRP_TEST_VEC_EMAIL,
            STR_LEN(SRP_TEST_VEC_EMAIL),
            (u8 *)SRP_TEST_VEC_PASSWORD,
            STR_LEN(SRP_TEST_VEC_PASSWORD));

    MinUnitAssert(AreVectorsEqualByteSwapped(LittleX, (u8 *)RFC_5054_TEST_X.Num, sizeof(LittleX)),
                  "Little x mismatch (Client) in TestClientServerAuth!\n");

    bignum BigNumScratch;
    ClientGetPremasterSecret(&BigNumScratch,
                             &BigB,
                             LittleK,
                             &LittleG,
                             LittleX,
                             (bignum *)&RFC_5054_TEST_LITTLE_A,
                             LittleU,
                             &ModulusN);

    u8 ClientHashScratch[SHA_1_HASH_LENGTH_BYTES];
    u32 ClientSecretSizeBytes = BigNumSizeBytesUnchecked(&BigNumScratch);
    Sha1(ClientHashScratch, (u8 *)BigNumScratch.Num, ClientSecretSizeBytes);

    // Send HMAC(K, salt)
    HmacSha1(ClientHashScratch, (u8 *)BigNumScratch.Num, ClientSecretSizeBytes, (u8 *)Salt.Num, SaltSizeBytes);

    memcpy(ClientSendRecvBuffer, ClientHashScratch, sizeof(ClientHashScratch));

    write(SocketFileDescriptor, ClientSendRecvBuffer, STR_LEN(GlobalCommand));

    ReadBytes = read(SocketFileDescriptor, ClientSendRecvBuffer, sizeof(ClientSendRecvBuffer));
    Stopif(ReadBytes >= sizeof(HMAC_VALID_STRING), "Overflow read from (N, g, s ,B) in TestClientServerAuth!");

    MinUnitAssert(AreVectorsEqual(ClientSendRecvBuffer, (void *)HMAC_VALID_STRING, STR_LEN(HMAC_VALID_STRING)),
                  "HMAC mismatch in TestClientServerAuth!");
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestImplementSrpTestVec);
	MinUnitRunTest(TestClientServerAuth);
}

int main()
{
	srand(time(0));
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
