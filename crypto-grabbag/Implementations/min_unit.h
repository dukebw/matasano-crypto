#ifndef MIN_UNIT_H
#define MIN_UNIT_H

#include "allheads.h"

global_variable u32 MinUnitGlobalTestsRun;

#define MIN_UNIT_TEST_FUNC(Name) void Name(void)
typedef MIN_UNIT_TEST_FUNC(min_unit_test_func);

internal void
MinUnitAssert(b32 Test, char *Message)
{
	if (!Test)
	{
		fprintf(stderr, "Test failed!\n%s\nTests run: %d\n", Message, MinUnitGlobalTestsRun);
		abort();
	}
}

internal void
MinUnitRunTest(min_unit_test_func *TestFunction)
{
	Stopif(TestFunction == 0, "Null input to MinUnitRunTest");
	++MinUnitGlobalTestsRun;
	TestFunction();
}

#endif // MIN_UNIT_H
