#include "crypt_helper.h"

#define RANDOM_CHAR_COUNT_MAX 256
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

	u32 RandomPrefixCharCount = rand() % RANDOM_CHAR_COUNT_MAX;

	const u8 KNOWN_PLAINTEXT[] =
	{
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
	};
	u32 PlaintextMaxSize = RANDOM_CHAR_COUNT_MAX + sizeof(KNOWN_PLAINTEXT);
	u8 Plaintext[PlaintextMaxSize];
	for (u32 PlaintextIndex = 0;
		 PlaintextIndex < RandomPrefixCharCount;
		 ++PlaintextIndex)
	{
		Plaintext[PlaintextIndex] = rand() % 0xFF;
	}

	u8 Ciphertext[PlaintextMaxSize];
	u32 Seed = rand() & 0xFFFF;
	u32 EncryptedLength = RandomPrefixCharCount + sizeof(KNOWN_PLAINTEXT);
	Mt19937StreamCipher(Ciphertext, Plaintext, EncryptedLength, &Mt, Seed);

#if 0
	Mt->State[MtStateIndex] =
		(MT19937_F*(Mt->State[MtStateIndex - 1] ^ (Mt->State[MtStateIndex - 1] >> (MT19937_W - 2))) +
		 MtStateIndex);
#endif

	// Recover the 16-bit seed

	// TODO(bwd): Get state for first word congruent to 0 mod 4, then find state backwards to seed by
	// reverting above
	u32 KnownPtByteOffsetFromWord = RandomPrefixCharCount % sizeof(u32);
	if ()
	{
	}
	else
	{
	}

	u32 CtFirstKnownWord = *(u32 *)(Ciphertext + (EncryptedLength - sizeof(KNOWN_PLAINTEXT)));
	u32 NthState = MtUntemper(*(u32 *)KNOWN_PLAINTEXT ^ CtFirstKnownWord);
	for (u32 StateIndex = ;
		 ;
		)
	{
	}

	// Generate a random "password reset token" using MT19937 seeded from current time

	// Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded
	// with the current time.
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	srand(time(0));
	MinUnitRunTest(TestMt19937StreamCipher);
	MinUnitRunTest(TestBreakMt19937StreamCipher);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
