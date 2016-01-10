#include "crypt_helper.h"

typedef struct
{
    void *Message;
    b32 MsgReceived;
} mailbox;

global_variable volatile mailbox
GlobalMasterMailbox =
{
    .Message = 0,
    .MsgReceived = false
};

global_variable volatile mailbox
GlobalSlaveMailbox =
{
    .Message = 0,
    .MsgReceived = false
};

const timespec
TWO_MS_SLEEP_REQUEST =
{
    .tv_sec = 0,
    .tv_nsec = 2*ONE_MILLION
};

internal void *
ReceiveMessage(volatile mailbox *Mailbox)
{
    void *Result;

    while (!Mailbox->MsgReceived)
    {
        nanosleep(&TWO_MS_SLEEP_REQUEST, 0);
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

    while (Mailbox->MsgReceived)
    {
        nanosleep(&TWO_MS_SLEEP_REQUEST, 0);
    }

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

internal void *
SlaveEntryPoint(void *Arg)
{
    Stopif(Arg, "Arg should be 0 in SlaveEntryPoint!\n");

    bignum *SlaveP = (bignum *)ReceiveMessageAndAck(&GlobalSlaveMailbox);

    bignum *G = (bignum *)ReceiveMessageAndAck(&GlobalSlaveMailbox);

    bignum BigA;
    BigNumCopyUnchecked(&BigA, (bignum *)ReceiveMessage(&GlobalSlaveMailbox));

    AckMessage(&GlobalSlaveMailbox);

    bignum LittleB;
    bignum SessionKeyB;
    GenRandKeyAndGPowerRandKeyUnchecked(&LittleB, &SessionKeyB, SlaveP, G);

    SendMessage(&GlobalMasterMailbox, (void *)&SessionKeyB);

    return (void *)0;
}

internal MIN_UNIT_TEST_FUNC(TestDhNegotiatedGroups)
{
    pthread_t SlaveThread;

    i32 Status = pthread_create(&SlaveThread, 0, SlaveEntryPoint, 0);
    Stopif(Status != 0, "pthread_create failed in TestDhNegotiatedGroups!");

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
    BigNumCopyUnchecked(&BigB, (bignum *)ReceiveMessage(&GlobalMasterMailbox));

    AckMessage(&GlobalMasterMailbox);

    MontModExpRBigNumMax(&SessionKeyA, &BigB, &LittleA, (bignum *)&NIST_RFC_3526_PRIME_1536);

    void *Result;
    Status = pthread_join(SlaveThread, &Result);

    printf("Thread returned %lu\n", (u64)Result);
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
