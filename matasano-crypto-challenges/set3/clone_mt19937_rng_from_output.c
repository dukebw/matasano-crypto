#include "crypt_helper.h"

#define BITS_IN_WORD 32

internal inline u32
Untemper(u32 TemperedValue, u32 Shift, u32 Mask)
{
	u32 Result = 0;
	for (u32 MaskShiftIndex = 0;
		 (MaskShiftIndex*Shift) < BITS_IN_WORD;
		 ++MaskShiftIndex)
	{
		u32 ShiftedMask = (SHIFT_TO_MASK(Shift) << (MaskShiftIndex*Shift));
		Result |= ((TemperedValue ^ ((Result << Shift) & Mask)) & ShiftedMask);
	}

	return Result;
}

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

		MinUnitAssert(NextClonedMtState == D, "D not untempered! Expected: %x, Actual: 0x%x\n",
					  D, NextClonedMtState);

		NextClonedMtState = Untemper(NextClonedMtState, MT19937_T, MT19937_C);

		MinUnitAssert(NextClonedMtState == C, "C not untempered! Expected: %x, Actual: 0x%x\n",
					  C, NextClonedMtState);

		NextClonedMtState = Untemper(NextClonedMtState, MT19937_S, MT19937_B);

		MinUnitAssert(NextClonedMtState == B, "B not untempered! Expected: %x, Actual: 0x%x\n",
					  B, NextClonedMtState);

		u32 InitialMask = SHIFT_TO_MASK(MT19937_U) << (BITS_IN_WORD - MT19937_U);
		u32 Temp = 0;
		for (u32 MaskShiftIndex = 0;
			 (MaskShiftIndex*MT19937_U) < BITS_IN_WORD;
			 ++MaskShiftIndex)
		{
			u32 ShiftedMask = (InitialMask >> (MaskShiftIndex*MT19937_U));
			Temp |= ((NextClonedMtState ^ (Temp >> MT19937_U)) & ShiftedMask);
		}
		NextClonedMtState = Temp;

		MinUnitAssert(NextClonedMtState == A, "A not untempered! Expected: %x, Actual: 0x%x\n",
					  A, NextClonedMtState);

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
