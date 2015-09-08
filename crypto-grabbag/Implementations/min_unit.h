#ifndef MIN_UNIT_H
#define MIN_UNIT_H

#include "allheads.h"

extern u32 MinUnitGlobalTestsRun;

#define MIN_UNIT_TEST_FUNC(Name) char *Name(void)
typedef MIN_UNIT_TEST_FUNC(min_unit_test_func);

internal inline char *
MinUnitAssert(char *Message, b32 Test)
{
	char *Result = 0;
	if (!Test)
	{
		Result = Message;
	}
	return Result;
}

internal inline char *
MinUnitRunTest(min_unit_test_func *TestFunction)
{
	Stopif(TestFunction == 0, return "Null", "Null input to MinUnitRunTest");
	char *Result = TestFunction();
	++MinUnitGlobalTestsRun;
	return Result;
}

#endif // MIN_UNIT_H
