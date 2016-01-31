#include "crypt_helper.h"

#define TEST_SEED_RANGE_SECONDS 1024
#define TEST_ITERATIONS	1024

internal MIN_UNIT_TEST_FUNC(TestCrackMt19937Seed)
{
	srand(time(0));

	mersenne_twister Mt;
	MtInitUnchecked(&Mt);

	u32 StartTime = time(0);
	u32 SeedOracle[TEST_SEED_RANGE_SECONDS];
	for (u32 CurrentTimeIndex = StartTime;
		 CurrentTimeIndex < (StartTime + TEST_SEED_RANGE_SECONDS);
		 ++CurrentTimeIndex)
	{
		MtSeed(&Mt, CurrentTimeIndex);
		SeedOracle[CurrentTimeIndex - StartTime] = MtExtractNumber(&Mt);
	}

	for (u32 TestNumber = 0;
		 TestNumber < TEST_ITERATIONS;
		 ++TestNumber)
	{
		u32 TestSeedSeconds = StartTime + (rand() % TEST_SEED_RANGE_SECONDS);
		MtSeed(&Mt, TestSeedSeconds);
		u32 RandomTestWord = MtExtractNumber(&Mt);
		u32 SeedOracleIndex;
		for (SeedOracleIndex = 0;
			 SeedOracleIndex < ARRAY_LENGTH(SeedOracle);
			 ++SeedOracleIndex)
		{
			if (RandomTestWord == SeedOracle[SeedOracleIndex])
			{
				break;
			}
		}
		u32 GuessSeed = (StartTime + SeedOracleIndex);
		MinUnitAssert(GuessSeed == TestSeedSeconds,
					  "Seed not guessed!\n Expected: %d Actual %d\n", TestSeedSeconds, GuessSeed);
	}
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestCrackMt19937Seed);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
