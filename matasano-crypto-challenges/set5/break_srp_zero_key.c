#include "crypt_helper.h"

internal MIN_UNIT_TEST_FUNC(TestBreakSrpZeroKey)
{
    u8 ClientSendRecvBuffer[4*sizeof(bignum) + 1];
    bignum ModulusN;
    bignum LittleG;
    bignum Salt;
    bignum BigB;
    i32 SocketFileDescriptor;
    u32 ClientBufferMaxSize = sizeof(ClientSendRecvBuffer) - 1;
    ClientConnectAndGetServerHello(ClientSendRecvBuffer,
                                   ClientBufferMaxSize,
                                   &SocketFileDescriptor,
                                   &ModulusN,
                                   &LittleG,
                                   &Salt,
                                   &BigB);

    // Send A == 0, so that Server calculates <premaster secret> = (A * v^u) ^ b % N == 0
    bignum Zero;
    Zero.SizeWords = 0;
    write(SocketFileDescriptor, &Zero, sizeof(Zero));

    // Hash 0, since pre-master secret is 0
    u8 ClientHashScratch[SHA_1_HASH_LENGTH_BYTES];
    HmacSha1(ClientHashScratch,
             ClientSendRecvBuffer,
             0,
             (u8 *)Salt.Num,
             BigNumSizeBytesUnchecked(&Salt));

    write(SocketFileDescriptor, ClientHashScratch, sizeof(ClientHashScratch));

    u32 ReadBytes = read(SocketFileDescriptor, ClientSendRecvBuffer, ClientBufferMaxSize);
    Stopif(ReadBytes > STR_LEN(HMAC_VALID_STRING),
           "Overflow read from HMAC Valid response in TestBreakSrpZeroKey!\n");

    MinUnitAssert(AreVectorsEqual(ClientSendRecvBuffer, (void *)HMAC_VALID_STRING, STR_LEN(HMAC_VALID_STRING)),
                  "Zero-key attack mismatch in TestBreakSrpZeroKey!\n");
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestBreakSrpZeroKey);
}

int main()
{
	srand(time(0));
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
