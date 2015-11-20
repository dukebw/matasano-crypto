#include "crypt_helper.h"

#define MAX_PLAINTEXT_LENGTH 65536

internal void
CtrEdit(u8 *Ciphertext, u8 *Key, u32 Offset, u8 *NewPlaintext, u32 NewPlaintextLength)
{
	Stopif((Ciphertext == 0) || (Key == 0) || (NewPlaintext == 0), "Null input to CtrEdit!");

	u32 BlocksBeforeOffset = Offset/AES_128_BLOCK_LENGTH_BYTES;
	u32 Aligned16ByteOffset = BlocksBeforeOffset*AES_128_BLOCK_LENGTH_BYTES;
	u32 ExtraAlignmentBytes = (Offset - Aligned16ByteOffset);
	u32 TotalDecryptLength = ExtraAlignmentBytes + NewPlaintextLength;

	u8 NonceCounter[AES_128_BLOCK_LENGTH_BYTES] = {0};
	*(u32 *)(NonceCounter + 8) = BlocksBeforeOffset;

	u8 *CtAlignedBlockStart = Ciphertext + Aligned16ByteOffset;
	AesCtrMode(CtAlignedBlockStart, CtAlignedBlockStart, TotalDecryptLength, Key, NonceCounter);

	memcpy(Ciphertext + Offset, NewPlaintext, NewPlaintextLength);
	*(u32 *)(NonceCounter + 8) = BlocksBeforeOffset;
	AesCtrMode(CtAlignedBlockStart, CtAlignedBlockStart, TotalDecryptLength, Key, NonceCounter);
}

internal MIN_UNIT_TEST_FUNC(TestBreakRandomAccessRwAesCtr)
{
    u8 CipherBase64[MAX_PLAINTEXT_LENGTH];
	u32 CipherBase64Length = FileReadIgnoreSpace(CipherBase64, "25.txt", MAX_PLAINTEXT_LENGTH);
	Stopif(CipherBase64Length == MAX_PLAINTEXT_LENGTH, "File too long");

    u8 Key[] =
	{
		'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'
	};
    u32 KeyLength = sizeof(Key);
	Stopif(KeyLength != AES_128_BLOCK_LENGTH_BYTES,
		   "Invalid AES-128 key length in TestBreakRandomAccessRwAesCtr\n");

    u8 Ciphertext[MAX_PLAINTEXT_LENGTH];
    u32 CiphertextLength = Base64ToAscii(Ciphertext, CipherBase64, CipherBase64Length);

	u8 Plaintext[MAX_PLAINTEXT_LENGTH];
	AesEcbDecrypt(Plaintext, Ciphertext, CiphertextLength, Key, KeyLength);

	GenRandUnchecked((u32 *)Key, AES_128_BLOCK_LENGTH_WORDS);

	u8 NonceCounter[AES_128_BLOCK_LENGTH_BYTES] = {0};
	AesCtrMode(Ciphertext, Plaintext, CiphertextLength, Key, NonceCounter);

	u8 KnownPlaintext[] =
	{
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A'
	};
	u32 KnownPtLength = sizeof(KnownPlaintext);
	CtrEdit(Ciphertext, Key, 0, KnownPlaintext, KnownPtLength);

	// TODO(bwd): Debug this step -- key guessing by XORing Known PT with first 16-bytes of ciphertext
	u8 GuessedPlaintext[MAX_PLAINTEXT_LENGTH];
	u8 GuessedKey[AES_128_BLOCK_LENGTH_BYTES];
	XorVectorsUnchecked(GuessedKey, Ciphertext, KnownPlaintext, sizeof(GuessedKey));
	MinUnitAssert(VectorsEqual(GuessedKey, Key, KeyLength),
				  "Guessed key mismatch in TestBreakRandomAccessRwAesCtr!\n");

	CtrEdit(Ciphertext, Key, 0, Plaintext, KnownPtLength);

	memset(NonceCounter, 0, sizeof(NonceCounter));
	AesCtrMode(GuessedPlaintext, Ciphertext, CiphertextLength, GuessedKey, NonceCounter);

	MinUnitAssert(VectorsEqual(GuessedPlaintext, Plaintext, CiphertextLength),
				  "Guessed Plaintext mismatch in TestBreakRandomAccessRwAesCtr!\n");
}

internal MIN_UNIT_TEST_FUNC(TestCtrEdit)
{
	u8 EditTestBuffer[MAX_PLAINTEXT_LENGTH];
	u32 EditTestBuffLength = sizeof(EditTestBuffer);
	GenRandUnchecked((u32 *)EditTestBuffer, sizeof(EditTestBuffer)/sizeof(u32));

	u32 Offset = rand() % EditTestBuffLength;
	u8 NewPlaintext[MAX_PLAINTEXT_LENGTH];
	u32 NewPtLength = rand() % (EditTestBuffLength - Offset);
	memcpy(NewPlaintext, EditTestBuffer + Offset, NewPtLength);

	u8 Key[AES_128_BLOCK_LENGTH_BYTES];
	GenRandUnchecked((u32 *)Key, sizeof(Key)/sizeof(u32));

	u8 NonceCounter[AES_128_BLOCK_LENGTH_BYTES] = {0};
	AesCtrMode(EditTestBuffer, EditTestBuffer, EditTestBuffLength, Key, NonceCounter);

	u8 ExpectedCiphertext[sizeof(EditTestBuffer)];
	memcpy(ExpectedCiphertext, EditTestBuffer, EditTestBuffLength);

	CtrEdit(EditTestBuffer, Key, Offset, NewPlaintext, NewPtLength);

	MinUnitAssert(VectorsEqual(EditTestBuffer, ExpectedCiphertext, EditTestBuffLength),
				  "EditTestBuffer changed by CtrEdit in TestCtrEdit!\n");
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestCtrEdit);
	MinUnitRunTest(TestBreakRandomAccessRwAesCtr);
}

int main()
{
	srand(time(0));
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
