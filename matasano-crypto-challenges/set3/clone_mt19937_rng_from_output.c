#include "crypt_helper.h"

internal MIN_UNIT_TEST_FUNC(TestCloneMt19937Rng)
{
	mersenne_twister Mt;
	MtInitUnchecked(&Mt);
	MtSeed(&Mt, time(0));

	u32 ClonedMt[MT19937_N];
	for (u32 TappedMtIndex = 0;
		 TappedMtIndex < ARRAY_LENGTH(ClonedMt);
		 ++TappedMtIndex)
	{
		u32 NextClonedMtState = MtUntemper(MtExtractNumber(&Mt));

		u32 ExpectedState = Mt.State[TappedMtIndex];
		MinUnitAssert(NextClonedMtState == ExpectedState,
					  "Mt.State[TappedMtIndex] not untempered! Expected: %x, Actual: 0x%x\n",
					  ExpectedState, NextClonedMtState);

		ClonedMt[TappedMtIndex] = NextClonedMtState;
	}
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestCloneMt19937Rng);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
