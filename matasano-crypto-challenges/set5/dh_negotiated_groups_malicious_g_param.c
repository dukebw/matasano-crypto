#include "crypt_helper.h"

internal MIN_UNIT_TEST_FUNC(TestDhNegotiatedGroups)
{
    pthread_t *MasterThread;

    i32 Status = pthread_create(&MasterThread, 0, void *(*)(void *), void *);
    Stopif(Status != 0, "pthread_create failed in TestDhNegotiatedGroups!");

    if (ChildPid == 0)
    {
        printf("Child!\n");

        exit(EXIT_SUCCESS);
    }
    else
    {
        printf("Parent!\n");
    }
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
}
