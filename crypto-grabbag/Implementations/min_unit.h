#ifndef MIN_UNIT_H
#define MIN_UNIT_H

#include "allheads.h"

global_variable u32 MinUnitGlobalTestsRun;

#define MIN_UNIT_TEST_FUNC(Name) void Name(void)
typedef MIN_UNIT_TEST_FUNC(min_unit_test_func);

internal void
MinUnitAssert(b32 Test, char *MessageFormat, ...)
{
	if (!Test)
	{
		va_list Args;
		va_start(Args, MessageFormat);

		vprintf(MessageFormat, Args);
		fprintf(stderr, "Test failed!\nTests run: %d\n", MinUnitGlobalTestsRun);
		abort();

		va_end(Args);
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
