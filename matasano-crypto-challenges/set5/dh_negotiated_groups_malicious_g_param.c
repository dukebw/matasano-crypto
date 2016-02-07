#include "crypt_helper.h"

#define DH_MALICIOUS_G_MAX_PLAINTEXT_SIZE_BYTES (4*AES_128_BLOCK_LENGTH_BYTES)
#define G_EQUALS_1_ATTACK 0
#define G_EQUALS_P_ATTACK 0
#define G_EQUALS_P_MINUS_1_ATTACK 1

typedef struct
{
    u8 *Ciphertext;
    u32 CtSizeBytes;
    u8 *Iv;
} ciphertext_iv_payload;

typedef struct
{
    void *Message;
    b32 MsgReceived;
    b32 AckMessage;
} mailbox;

global_variable volatile mailbox
GlobalMasterMailbox =
{
    .Message = 0,
    .MsgReceived = false,
    .AckMessage = false
};

global_variable volatile mailbox
GlobalSlaveMailbox =
{
    .Message = 0,
    .MsgReceived = false,
    .AckMessage = false
};

const timespec
TWENTY_MS_SLEEP_REQUEST =
{
    .tv_sec = 0,
    .tv_nsec = 20*ONE_MILLION
};

internal void *
ReceiveMessage(volatile mailbox *Mailbox)
{
    void *Result;

    while (!Mailbox->MsgReceived)
    {
        nanosleep(&TWENTY_MS_SLEEP_REQUEST, 0);
    }

    if (Mailbox == &GlobalMasterMailbox)
    {
        printf("Master: Message received!\n");
    }
    else
    {
        printf("Slave: Message received!\n");
    }

    Result = Mailbox->Message;

    Stopif(!Result, "Null message to Slave!\n");

    return Result;
}

internal void
AckMessage(volatile mailbox *Mailbox)
{
    Mailbox->MsgReceived = false;
    Mailbox->AckMessage = true;
}

internal void *
ReceiveMessageAndAck(volatile mailbox *Mailbox)
{
    void *Result = ReceiveMessage(Mailbox);

    AckMessage(Mailbox);

    return Result;
}

internal void
SendMessage(volatile mailbox *Mailbox, void *Message)
{
    Mailbox->Message = Message;
    Mailbox->MsgReceived = true;

    while (!Mailbox->AckMessage)
    {
        nanosleep(&TWENTY_MS_SLEEP_REQUEST, 0);
    }

    Mailbox->AckMessage = false;

    if (Mailbox == &GlobalMasterMailbox)
    {
        printf("Slave: Master ACK'ed!\n");
    }
    else
    {
        printf("Master: Slave ACK'ed!\n");
    }
}

internal void
GenRandKeyAndGPowerRandKeyUnchecked(bignum *RandKey, bignum *GPowerRandKey, bignum *P, bignum *G)
{
    GenRandBigNumModNUnchecked(RandKey, P);

    MontModExpRBigNumMax(GPowerRandKey, G, RandKey, P);
}

internal inline void
EveInterceptMessage()
{
    while (!GlobalSlaveMailbox.MsgReceived)
    {
    }

    GlobalSlaveMailbox.MsgReceived = false;
}

global_variable bignum GlobalEveScratch;

internal inline void
EveWaitSlaveMessage(char *InterceptString)
{
    EveInterceptMessage();

    Stopif(InterceptString == 0, "Null input to EveWaitSlaveMessage!");

    printf("%s", InterceptString);

    GlobalSlaveMailbox.MsgReceived = true;

    while (!GlobalSlaveMailbox.AckMessage)
    {
    }
}

internal void *
EveEntryPoint(void *Arg)
{
    Stopif(Arg, "Arg should be 0 in EveEntryPoint!\n");

    EveWaitSlaveMessage("Entered Eve thread!\nEve intercepted A->B send p!\n");

    EveInterceptMessage();

    printf("Eve intercepted A->B send g!\n");

#if (G_EQUALS_1_ATTACK | G_EQUALS_P_ATTACK | G_EQUALS_P_MINUS_1_ATTACK)
    GlobalSlaveMailbox.Message = &GlobalEveScratch;
#endif // some attack

#if G_EQUALS_1_ATTACK // g := 1
    GlobalEveScratch.Num[0] = 1;
    GlobalEveScratch.SizeWords = 1;
#elif G_EQUALS_P_ATTACK // g := p
    BigNumCopyUnchecked(&GlobalEveScratch, (bignum *)&NIST_RFC_3526_PRIME_1536);
#elif G_EQUALS_P_MINUS_1_ATTACK // g := p - 1
    // TODO(bwd): works half the time... ((-1)^(X*Y) == -1) iff (X*Y) odd
    GlobalEveScratch.Num[0] = 1;
    GlobalEveScratch.SizeWords = 1;

    BigNumSubtract(&GlobalEveScratch, (bignum *)&NIST_RFC_3526_PRIME_1536, &GlobalEveScratch);
#endif // some attack

    GlobalSlaveMailbox.MsgReceived = true;

    while (!GlobalSlaveMailbox.AckMessage)
    {
    }

    EveWaitSlaveMessage("Eve intercepted A->B send A!\n");

    EveInterceptMessage();

    u8 SessionSymmetricKey[SHA_1_HASH_LENGTH_BYTES];
    Sha1(SessionSymmetricKey,
         (u8 *)GlobalEveScratch.Num,
         sizeof(GlobalEveScratch.Num[0])*GlobalEveScratch.SizeWords);

    printf("Eve SessionSymmetricKey:\n");
    PrintArray(SessionSymmetricKey, sizeof(SessionSymmetricKey));

    ciphertext_iv_payload *MasterPayload = GlobalSlaveMailbox.Message;

    u8 DecryptedMasterPt[DH_MALICIOUS_G_MAX_PLAINTEXT_SIZE_BYTES];

    Stopif(MasterPayload->CtSizeBytes > sizeof(DecryptedMasterPt),
           "Received ciphertext too large in EveEntryPoint!\n");

    AesCbcDecrypt(DecryptedMasterPt,
                  MasterPayload->Ciphertext,
                  MasterPayload->CtSizeBytes,
                  SessionSymmetricKey,
                  MasterPayload->Iv);

    printf("Eve intercepted message:\n%s", DecryptedMasterPt);

    GlobalSlaveMailbox.MsgReceived = true;

    return (void *)0;
}

internal void *
SlaveEntryPoint(void *Arg)
{
    Stopif(Arg, "Arg should be 0 in SlaveEntryPoint!\n");

    printf("Entered Slave thread!\n");

    bignum *SlaveP = (bignum *)ReceiveMessageAndAck(&GlobalSlaveMailbox);

    bignum *G = (bignum *)ReceiveMessageAndAck(&GlobalSlaveMailbox);

    printf("Slave G->Num[0]: 0x%lx, G->SizeWords: 0x%x\n", G->Num[0], G->SizeWords);

    bignum BigA;
    bignum *ReceivedBigA = (bignum *)ReceiveMessage(&GlobalSlaveMailbox);
    BigNumCopyUnchecked(&BigA, ReceivedBigA);

    AckMessage(&GlobalSlaveMailbox);

    bignum LittleB;
    bignum SessionKeyB;
    GenRandKeyAndGPowerRandKeyUnchecked(&LittleB, &SessionKeyB, SlaveP, G);

    SendMessage(&GlobalMasterMailbox, (void *)&SessionKeyB);

    MontModExpRBigNumMax(&SessionKeyB, &BigA, &LittleB, (bignum *)&NIST_RFC_3526_PRIME_1536);

    u8 SlavePlaintext[DH_MALICIOUS_G_MAX_PLAINTEXT_SIZE_BYTES] = "Slave: This is my message... Mwahaha you can't crack it!\n";
    u32 SlaveCiphertextSizeBytes = strlen((char *)SlavePlaintext) + 1;

    Stopif(SlaveCiphertextSizeBytes > sizeof(SlavePlaintext), "SlavePlaintext buffer overflow\n");

    u8 SlaveCiphertext[sizeof(SlavePlaintext) + AES_128_BLOCK_LENGTH_BYTES];
    u8 SlaveIv[AES_128_BLOCK_LENGTH_BYTES];
    u8 SessionSymmetricKey[SHA_1_HASH_LENGTH_BYTES];

    HashSessionKeyGenIvAndEncrypt(SlaveCiphertext,
                                  SlaveIv,
                                  (u8 *)SessionKeyB.Num,
                                  sizeof(u64)*SessionKeyB.SizeWords,
                                  SlavePlaintext,
                                  SlaveCiphertextSizeBytes,
                                  SessionSymmetricKey);

    printf("Slave SessionSymmetricKey:\n");
    PrintArray(SessionSymmetricKey, SHA_1_HASH_LENGTH_BYTES);

    ciphertext_iv_payload *MasterPayload = ReceiveMessage(&GlobalSlaveMailbox);

    u8 DecryptedMasterPt[DH_MALICIOUS_G_MAX_PLAINTEXT_SIZE_BYTES];

    Stopif(MasterPayload->CtSizeBytes > sizeof(DecryptedMasterPt),
           "Received ciphertext too large in SlaveEntryPoint!\n");

    AesCbcDecrypt(DecryptedMasterPt,
                  MasterPayload->Ciphertext,
                  MasterPayload->CtSizeBytes,
                  SessionSymmetricKey,
                  MasterPayload->Iv);

    AckMessage(&GlobalSlaveMailbox);

    ciphertext_iv_payload SlavePayload =
    {
        .Ciphertext = SlaveCiphertext,
        .CtSizeBytes = SlaveCiphertextSizeBytes,
        .Iv = SlaveIv,
    };
    SendMessage(&GlobalMasterMailbox, (void *)&SlavePayload);

    printf("Master's message:\n%s", DecryptedMasterPt);

    return (void *)0;
}

internal MIN_UNIT_TEST_FUNC(TestDhNegotiatedGroups)
{
    printf("Entered Master thread!\n");

    pthread_t SlaveThread;
    i32 Status = pthread_create(&SlaveThread, 0, SlaveEntryPoint, 0);
    Stopif(Status != 0, "pthread_create failed in TestDhNegotiatedGroups!\n");

    pthread_t EveThread;
    Status = pthread_create(&EveThread, 0, EveEntryPoint, 0);
    Stopif(Status != 0, "pthread_create failed in TestDhNegotiatedGroups!\n");

    // A -> B Send "p"
    SendMessage(&GlobalSlaveMailbox, (void *)&NIST_RFC_3526_PRIME_1536);

    // A -> B Send "g"
    SendMessage(&GlobalSlaveMailbox, (void *)&NIST_RFC_3526_GEN_BIGNUM);

    // A -> B Send "A"
    bignum LittleA;
    // SessionKeyA used as temp bignum to send BigA (copied by B)
    bignum SessionKeyA;
    GenRandKeyAndGPowerRandKeyUnchecked(&LittleA,
                                        &SessionKeyA,
                                        (bignum *)&NIST_RFC_3526_PRIME_1536,
                                        (bignum *)&NIST_RFC_3526_GEN_BIGNUM);

    SendMessage(&GlobalSlaveMailbox, (void *)&SessionKeyA);

    // B -> A Send "B"
    bignum BigB;
    bignum *ReceivedBigB = (bignum *)ReceiveMessage(&GlobalMasterMailbox);
    BigNumCopyUnchecked(&BigB, ReceivedBigB);

    AckMessage(&GlobalMasterMailbox);

    MontModExpRBigNumMax(&SessionKeyA, &BigB, &LittleA, (bignum *)&NIST_RFC_3526_PRIME_1536);

    u8 MasterPlaintext[DH_MALICIOUS_G_MAX_PLAINTEXT_SIZE_BYTES] = "Master: This is my message!\nYou decrypted it!\n";
    u32 MasterCiphertextSizeBytes = strlen((char *)MasterPlaintext) + 1;

    Stopif(MasterCiphertextSizeBytes > sizeof(MasterPlaintext), "MasterPlaintext buffer overflow\n");

    u8 MasterCiphertext[sizeof(MasterPlaintext) + AES_128_BLOCK_LENGTH_BYTES];
    u8 MasterIv[AES_128_BLOCK_LENGTH_BYTES];
    u8 SessionSymmetricKey[SHA_1_HASH_LENGTH_BYTES];

    HashSessionKeyGenIvAndEncrypt(MasterCiphertext,
                                  MasterIv,
                                  (u8 *)SessionKeyA.Num,
                                  sizeof(u64)*SessionKeyA.SizeWords,
                                  MasterPlaintext,
                                  MasterCiphertextSizeBytes,
                                  SessionSymmetricKey);

    printf("Master SessionSymmetricKey:\n");
    PrintArray(SessionSymmetricKey, SHA_1_HASH_LENGTH_BYTES);

    ciphertext_iv_payload MasterPayload =
    {
        .Ciphertext = MasterCiphertext,
        .CtSizeBytes = MasterCiphertextSizeBytes,
        .Iv = MasterIv,
    };
    SendMessage(&GlobalSlaveMailbox, (void *)&MasterPayload);

    ciphertext_iv_payload *SlavePayload = ReceiveMessage(&GlobalMasterMailbox);

    u8 DecryptedSlavePt[DH_MALICIOUS_G_MAX_PLAINTEXT_SIZE_BYTES];

    Stopif(SlavePayload->CtSizeBytes > sizeof(DecryptedSlavePt),
           "Received ciphertext too large in TestDhNegotiatedGroups!\n");

    AesCbcDecrypt(DecryptedSlavePt,
                  SlavePayload->Ciphertext,
                  SlavePayload->CtSizeBytes,
                  SessionSymmetricKey,
                  SlavePayload->Iv);

    printf("Slave's Message:\n%s", DecryptedSlavePt);

    AckMessage(&GlobalMasterMailbox);

    void *Result;
    Status = pthread_join(SlaveThread, &Result);

    printf("Slave thread returned %lu\n", (u64)Result);

    Status = pthread_join(EveThread, &Result);

    printf("Eve thread returned %lu\n", (u64)Result);
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestDhNegotiatedGroups);
}

int main()
{
	srand(time(0));
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);

    exit(EXIT_SUCCESS);
}
