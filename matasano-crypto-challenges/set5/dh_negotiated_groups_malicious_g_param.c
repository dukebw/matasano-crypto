#include "crypt_helper.h"

// TODO(bwd): use pthreads so the threads can share data/heap to communicate
internal MIN_UNIT_TEST_FUNC(TestDhNegotiatedGroups)
{
    i32 ChildPid = fork();
    Stopif(ChildPid < 0, "fork() failed in TestDhNegotiatedGroups!");

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
