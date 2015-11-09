#include "crypt_helper.h"

#define MT19937_STREAM_SEED_BITS 16

internal void
Mt19937StreamCipher(u8 *Output, u8 *Input, u32 InputLength, mersenne_twister *Mt, u32 Seed)
{
	Stopif((Output == 0) || (Input == 0) || (Mt == 0), "Null input to Mt19937StreamCipher!");
	Stopif(Seed & (~SHIFT_TO_MASK(MT19937_STREAM_SEED_BITS)), "Seed must be 16 bits for Mt19937StreamCipher");

	MtSeed(Mt, Seed);
	u32 NextKeystreamWord;
	for (u32 InputIndex = 0;
		 InputIndex < InputLength;
		 ++InputIndex)
	{
		u32 PtNextWordByteIndex = (InputIndex % sizeof(NextKeystreamWord));
		if (PtNextWordByteIndex == 0)
		{
			NextKeystreamWord = MtExtractNumber(Mt);
		}
		Output[InputIndex] = (Input[InputIndex] ^ ((NextKeystreamWord >> (InputIndex*8)) & 0xFF));
	}
}

internal MIN_UNIT_TEST_FUNC(TestMt19937StreamCipher)
{
	mersenne_twister Mt;
	MtInitUnchecked(&Mt);

	u8 TestInput[] = "thequickbrownfoxjumpedoverthelazydog";
	u32 TestLength = sizeof(TestInput);
	u8 TestOutput[TestLength];
	Mt19937StreamCipher(TestOutput, TestInput, TestLength, &Mt, 0xABCD);

	u8 TestScratch[TestLength];
	Mt19937StreamCipher(TestScratch, TestOutput, TestLength, &Mt, 0xABCD);
	MinUnitAssert(VectorsEqual(TestScratch, TestInput, TestLength),
				  "Positive test failure in TestMt19937StreamCipher");

	Mt19937StreamCipher(TestScratch, TestOutput, TestLength, &Mt, 0xABCE);
	MinUnitAssert(!VectorsEqual(TestScratch, TestInput, TestLength),
				  "Negative test failure in TestMt19937StreamCipher");
}

internal MIN_UNIT_TEST_FUNC(TestBreakMt19937StreamCipher)
{
	mersenne_twister Mt;
	MtInitUnchecked(&Mt);
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestMt19937StreamCipher);
	MinUnitRunTest(TestBreakMt19937StreamCipher);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
