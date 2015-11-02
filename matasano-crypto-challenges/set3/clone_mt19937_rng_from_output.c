#include "crypt_helper.h"

internal MIN_UNIT_TEST_FUNC(TestCloneMt19937Rng)
{
	mersenne_twister Mt;
	Mt.Index = MT19937_N + 1;
	MtSeed(&Mt, time(0));

	u32 ClonedMt[MT19937_N];
	for (u32 TappedMtIndex = 0;
		 TappedMtIndex < ARRAY_LENGTH(ClonedMt);
		 ++TappedMtIndex)
	{
		u32 NextClonedMtState = MtExtractNumber(&Mt);

		// Test temper
		u32 A = Mt.State[TappedMtIndex];
		u32 B = A ^ ((A >> MT19937_U) & MT19937_D);
		u32 C = B ^ ((B << MT19937_S) & MT19937_B);
		u32 D = C ^ ((C << MT19937_T) & MT19937_C);
		u32 E = D ^ (D >> MT19937_L);

		Stopif(NextClonedMtState != E, "E doesn't match result from MtExtractNumber");

		// Untemper
		NextClonedMtState = NextClonedMtState ^ (NextClonedMtState >> MT19937_L);

		MinUnitAssert(NextClonedMtState == D, "D not untempered! Expected: %x, Actual: %x\n",
					  D, NextClonedMtState);

		u32 Temp = (NextClonedMtState ^ ((NextClonedMtState << MT19937_T) & MT19937_C)) & 0x3FFFFFFF;
		NextClonedMtState = (((NextClonedMtState ^ ((Temp << MT19937_T) & MT19937_C)) & 0xC0000000) |
							 Temp);

		MinUnitAssert(NextClonedMtState == C, "C not untempered! Expected: %x, Actual: %x\n",
					  C, NextClonedMtState);

		// TODO(bwd): recover B, A (the state)

		ClonedMt[TappedMtIndex] = NextClonedMtState;
	}

/*
	A = Mt->State[Mt->Index];
	B = A ^ ((A >> MT19937_U) & MT19937_D);
	C = B ^ ((B << MT19937_S) & MT19937_B);
	D = C ^ ((C << MT19937_T) & MT19937_C);
	E = D ^ (D >> MT19937_L);

	D = E ^ (E >> L)
	C' = ((D ^ ((D << MT19937_T) & MT19937_C)) & 0x3FFF_FFFF)
	C = C' | (D ^ ((C' << T) & C))
*/
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
