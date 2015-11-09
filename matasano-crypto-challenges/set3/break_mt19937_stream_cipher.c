#include "crypt_helper.h"

#define MT19937_STREAM_SEED_BITS 16

internal void
Mt19937StreamEncrypt(u8 *Ciphertext, u8 *Plaintext, u32 PlaintextLength, mersenne_twister *Mt, u32 Seed)
{
	Stopif((Ciphertext == 0) || (Plaintext == 0) || (Mt == 0), "Null input to Mt19937StreamEncrypt!");
	Stopif(Seed & (~SHIFT_TO_MASK(MT19937_STREAM_SEED_BITS)), "Seed must be 16 bits for Mt19937StreamEncrypt");

	MtSeed(Mt, Seed);
	u32 NextKeystreamWord;
	for (u32 PlaintextIndex = 0;
		 PlaintextIndex < PlaintextLength;
		 ++PlaintextIndex)
	{
		u32 PtNextWordByteIndex = (PlaintextIndex % sizeof(NextKeystreamWord));
		if (PtNextWordByteIndex == 0)
		{
			NextKeystreamWord = MtExtractNumber(Mt);
		}
		// TODO(bwd):
		Ciphertext[PlaintextIndex] = Plaintext[PlaintextIndex] ^ (NextKeystreamWord);
	}
}

internal void
Mt19937StreamDecrypt(mersenne_twister *Mt)
{
}

internal MIN_UNIT_TEST_FUNC(TestBreakMt19937StreamCipher)
{
	mersenne_twister Mt;
	MtInitUnchecked(&Mt);
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestMt19937StreamEncrypt);
	MinUnitRunTest(TestBreakMt19937StreamCipher);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
