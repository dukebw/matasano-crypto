#include "crypt_helper.h"

internal MIN_UNIT_TEST_FUNC(TestBreakSrpZeroKey)
{
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

    // Send A == 0, so that Server calculates <premaster secret> = (A * v^u) ^ b % N == 0
    memset(ClientSendRecvBuffer, 0, sizeof(bignum));
    write(SocketFileDescriptor, ClientSendRecvBuffer, sizeof(bignum));

    // Hash 0, since pre-master secret is 0
    u8 ClientHashScratch[SHA_1_HASH_LENGTH_BYTES];
    HmacSha1(ClientHashScratch,
             ClientSendRecvBuffer,
             0,
             (u8 *)Salt.Num,
             BigNumSizeBytesUnchecked(&Salt));

    PrintArray(ClientHashScratch, sizeof(ClientHashScratch));

    write(SocketFileDescriptor, ClientHashScratch, sizeof(ClientHashScratch));

    u32 ReadBytes = read(SocketFileDescriptor, ClientSendRecvBuffer, sizeof(ClientSendRecvBuffer));
    Stopif(ReadBytes != STR_LEN(HMAC_VALID_STRING),
           "Invalid size %d of HMAC Valid response in TestBreakSrpZeroKey!\n",
           ReadBytes);

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
