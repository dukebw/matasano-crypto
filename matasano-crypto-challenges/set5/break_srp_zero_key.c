#include "crypt_helper.h"

internal MIN_UNIT_TEST_FUNC(TestBreakSrpZeroKey)
{
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
