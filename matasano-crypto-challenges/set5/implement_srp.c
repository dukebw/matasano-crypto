#include "crypt_helper.h"

// Source for RFC 5054: https://tools.ietf.org/html/rfc5054

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
    // <premaster secret> = (B - (k * g^x)) ^ (a + (u * x)) % N
    bignum BigNumScratch;
    ClientGetPremasterSecret(&BigNumScratch,
                             (bignum *)&RFC_5054_NIST_PRIME_1024,
                             (bignum *)&NIST_RFC_5054_GEN_BIGNUM,
                             (bignum *)&RFC_5054_TEST_SALT,
                             (bignum *)&RFC_5054_TEST_BIG_B,
                             (bignum *)&RFC_5054_TEST_LITTLE_A);

    MinUnitAssert(AreVectorsEqual(BigNumScratch.Num,
                                  (void *)RFC_5054_TEST_PREMASTER_SECRET.Num,
                                  RFC_5054_TEST_PREMASTER_SECRET.SizeWords) &&
                  (BigNumScratch.SizeWords == RFC_5054_TEST_PREMASTER_SECRET.SizeWords),
                  "Premaster secret mismatch (Client) in TestImplementSrpTestVec!\n");

    // Server
    // <premaster secret> = (A * v^u) ^ b % N
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

    u8 ClientSendRecvBuffer[4*sizeof(bignum)];
    bignum ModulusN;
    bignum LittleG;
    bignum Salt;
    bignum BigB;
	i32 SocketFileDescriptor;
    ClientConnectAndGetServerHello(ClientSendRecvBuffer,
                                   sizeof(ClientSendRecvBuffer),
                                   &SocketFileDescriptor,
                                   &ModulusN,
                                   &LittleG,
                                   &Salt,
                                   &BigB);

    BigNumCopyUnchecked((bignum *)ClientSendRecvBuffer, (bignum *)&RFC_5054_TEST_BIG_A);

    write(SocketFileDescriptor, ClientSendRecvBuffer, sizeof(RFC_5054_TEST_BIG_A));

    bignum ClientPremasterSecret;
    ClientGetPremasterSecret(&ClientPremasterSecret,
                             &ModulusN,
                             &LittleG,
                             &Salt,
                             &BigB,
                             (bignum *)&RFC_5054_TEST_LITTLE_A);

    u8 ClientHashScratch[SHA_1_HASH_LENGTH_BYTES];
    u32 ClientSecretSizeBytes = BigNumSizeBytesUnchecked(&ClientPremasterSecret);

    // Send HMAC(K, salt)
    HmacSha1(ClientHashScratch,
             (u8 *)ClientPremasterSecret.Num,
             ClientSecretSizeBytes,
             (u8 *)Salt.Num,
             BigNumSizeBytesUnchecked(&Salt));

    write(SocketFileDescriptor, ClientHashScratch, sizeof(ClientHashScratch));

    u32 ReadBytes = read(SocketFileDescriptor, ClientSendRecvBuffer, sizeof(ClientSendRecvBuffer));
    Stopif(ReadBytes > STR_LEN(HMAC_VALID_STRING), "Overflow read from (N, g, s ,B) in TestClientServerAuth!");

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
