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

internal void
CopyPaddedToBigEndianUnchecked(u8 *OutPaddedBigEndian, bignum *Input, u32 PSizeBytes)
{
    u32 InputSizeBytes = BigNumSizeBytesUnchecked(Input);
    Stopif(InputSizeBytes > PSizeBytes, "Invalid Input/PSizeBytes input to CopyPaddedToBigEndianUnchecked!\n");

    u32 PaddingBytes = (PSizeBytes - InputSizeBytes);
    memset(OutPaddedBigEndian, 0, PaddingBytes);

    CopyByteSwappedUnchecked(OutPaddedBigEndian, (u8 *)Input->Num, PSizeBytes);
}

internal void
Sha1PaddedAConcatPaddedB(u8 *OutputHash, u8 *ScratchBuffer, bignum *A, bignum *B, u32 PSizeBytes)
{
    Stopif((OutputHash == 0) || (ScratchBuffer == 0) || (A == 0) || (B == 0),
           "Null input to Sha1PaddedAConcatPaddedB!\n");

    CopyPaddedToBigEndianUnchecked(ScratchBuffer, A, PSizeBytes);

    CopyPaddedToBigEndianUnchecked(ScratchBuffer + PSizeBytes, B, PSizeBytes);

    Sha1(OutputHash, ScratchBuffer, 2*PSizeBytes);
}

internal void
SrpClientGetX(u8 *OutLittleX,
              u8 *Salt,
              u32 SaltLengthBytes,
              u8 *MessageScratch,
              u32 MessageScratchMaxSizeBytes,
              u8 *UserName,
              u32 UserLengthBytes,
              u8 *Password,
              u32 PasswordLengthBytes)
{
    Stopif((OutLittleX == 0) || (Salt == 0) || (MessageScratch == 0), "Null input to SrpClientGetX!\n");

    u32 EmailPasswordMsgLengthBytes = UserLengthBytes + 1 + PasswordLengthBytes;
    u32 SaltConcatHashEmailPwdLengthBytes = SaltLengthBytes + SHA_1_HASH_LENGTH_BYTES;
    Stopif((SaltConcatHashEmailPwdLengthBytes > MessageScratchMaxSizeBytes) ||
           (EmailPasswordMsgLengthBytes > MessageScratchMaxSizeBytes),
           "MessageScratch buffer overflow in TestImplementSrpTestVec!\n");

    memcpy(MessageScratch, UserName, UserLengthBytes);

    MessageScratch[UserLengthBytes] = ':';

    memcpy(MessageScratch + UserLengthBytes + 1,
           Password,
           PasswordLengthBytes);

    Sha1(MessageScratch, MessageScratch, EmailPasswordMsgLengthBytes);

    memmove(MessageScratch + SaltLengthBytes, MessageScratch, SHA_1_HASH_LENGTH_BYTES);

    CopyByteSwappedUnchecked(MessageScratch, Salt, SaltLengthBytes);

    // x := SHA1(s | SHA1(I | ":" | P))
    Sha1(OutLittleX, MessageScratch, SaltConcatHashEmailPwdLengthBytes);
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

    u32 TestModulusSizeBytes = BigNumSizeBytesUnchecked((bignum *)&RFC_5054_TEST_BIG_B);
    u8 MessageScratch[2*TestModulusSizeBytes];

    // u := SHA1(PAD(A) | PAD(B))
    u8 LittleU[SHA_1_HASH_LENGTH_BYTES];
    Sha1PaddedAConcatPaddedB(LittleU,
                             MessageScratch,
                             &BigA,
                             (bignum *)&RFC_5054_TEST_BIG_B,
                             TestModulusSizeBytes);

    MinUnitAssert(AreVectorsEqualByteSwapped(LittleU, (u8 *)RFC_5054_TEST_U.Num, sizeof(LittleU)),
                  "Little u mismatch (Client) in TestImplementSrpTestVec!\n");

    u32 PSizeBytes = BigNumSizeBytesUnchecked((bignum *)&RFC_5054_NIST_PRIME_1024);

    // k := SHA1(N | PAD(g))
    u8 LittleK[SHA_1_HASH_LENGTH_BYTES];
    Sha1PaddedAConcatPaddedB(LittleK,
                             MessageScratch,
                             (bignum *)&RFC_5054_NIST_PRIME_1024,
                             (bignum *)&NIST_RFC_5054_GEN_BIGNUM,
                             PSizeBytes);

    MinUnitAssert(AreVectorsEqualByteSwapped(LittleK, (u8 *)RFC_5054_TEST_K.Num, sizeof(LittleK)),
                  "Little k mismatch (Client) in TestImplementSrpTestVec!\n");

    // MessageScratch := SHA1(I | ":" | P)
    u8 LittleX[SHA_1_HASH_LENGTH_BYTES];
    u32 SaltLengthBytes = BigNumSizeBytesUnchecked((bignum *)&RFC_5054_TEST_SALT);
    SrpClientGetX(LittleX,
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

    // BigNumScratch := k * g^x (mod N)
    BigNumMultiplyModP(&BigNumScratch, &LittleKBigNum, &BigNumScratch, (bignum *)&RFC_5054_NIST_PRIME_1024);

    // BigNumScratch := (B - (k * g^x))
    BigNumSubtractModP(&BigNumScratch,
                       (bignum *)&RFC_5054_TEST_BIG_B,
                       (bignum *)&BigNumScratch,
                       (bignum *)&RFC_5054_NIST_PRIME_1024);

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

    // Server
    Sha1PaddedAConcatPaddedB(LittleK,
                             MessageScratch,
                             (bignum *)&RFC_5054_NIST_PRIME_1024,
                             (bignum *)&NIST_RFC_5054_GEN_BIGNUM,
                             PSizeBytes);

    MinUnitAssert(AreVectorsEqualByteSwapped(LittleK, (u8 *)RFC_5054_TEST_K.Num, sizeof(LittleK)),
                  "Little k mismatch (Server) in TestImplementSrpTestVec!\n");

    HashOutputToBigNumUnchecked(&LittleKBigNum, LittleK);

    // BigNumScratch := k*v (mod N)
    BigNumMultiplyModP(&BigNumScratch,
                       &LittleKBigNum,
                       (bignum *)&RFC_5054_TEST_V,
                       (bignum *)&RFC_5054_NIST_PRIME_1024);

    // BigNumScratchExponent := g^b
    MontModExpRBigNumMax(&BigNumScratchExponent,
                         (bignum *)&NIST_RFC_5054_GEN_BIGNUM,
                         (bignum *)&RFC_5054_TEST_LITTLE_B,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

    // BigNumScratch := (k*v + g^b) % N
    BigNumAddModN(&BigNumScratch, &BigNumScratch, &BigNumScratchExponent, (bignum *)&RFC_5054_NIST_PRIME_1024);

    MinUnitAssert(AreVectorsEqual((void *)RFC_5054_TEST_BIG_B.Num, &BigNumScratch,
                                  BigNumSizeBytesUnchecked((bignum *)&RFC_5054_TEST_BIG_B)) &&
                  (BigNumScratch.SizeWords == RFC_5054_TEST_BIG_B.SizeWords),
                  "Big B Mismatch (Server) in TestImplementSrpTestVec!\n");

    Sha1PaddedAConcatPaddedB(LittleU,
                             MessageScratch,
                             (bignum *)&RFC_5054_TEST_BIG_A,
                             &BigNumScratch,
                             PSizeBytes);

    MinUnitAssert(AreVectorsEqualByteSwapped(LittleU, (u8 *)RFC_5054_TEST_U.Num, sizeof(LittleU)),
                  "Little u mismatch (Server) in TestImplementSrpTestVec!\n");

    HashOutputToBigNumUnchecked(&LittleUBigNum, LittleU);

    // BigNumScratch := v^u (mod N)
    MontModExpRBigNumMax(&BigNumScratch,
                         (bignum *)&RFC_5054_TEST_V,
                         &LittleUBigNum,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

    // BigNumScratch := A * v^u (mod N)
    BigNumMultiplyModP(&BigNumScratch,
                       (bignum *)&RFC_5054_TEST_BIG_A,
                       &BigNumScratch,
                       (bignum *)&RFC_5054_NIST_PRIME_1024);

    // BigNumScratch := <premaster secret>
    MontModExpRBigNumMax(&BigNumScratch,
                         &BigNumScratch,
                         (bignum *)&RFC_5054_TEST_LITTLE_B,
                         (bignum *)&RFC_5054_NIST_PRIME_1024);

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

    write(SocketFileDescriptor, ClientSendRecvBuffer, STR_LEN(GlobalCommand));

    // u := SHA1(PAD(A) | PAD(B))
    u8 LittleU[SHA_1_HASH_LENGTH_BYTES];
    // TODO(bwd): fix ModulusSizeBytes + add SrpClientGetX() call + continue S->C/C->S HMAC-validation
    u8 MessageScratch[2*TestModulusSizeBytes];
    Sha1PaddedAConcatPaddedB(LittleU,
                             MessageScratch,
                             &BigA,
                             (bignum *)&RFC_5054_TEST_BIG_B,
                             BigNumSizeBytesUnchecked((bignum *)&RFC_5054_NIST_PRIME_1024));

    // x := SHA1(s | SHA1(I | ":" | P))
    u8 LittleX[SHA_1_HASH_LENGTH_BYTES];
    Sha1(LittleX, MessageScratch, SaltConcatHashEmailPwdLengthBytes);
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
