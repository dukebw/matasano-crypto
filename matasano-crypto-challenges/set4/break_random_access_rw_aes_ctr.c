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

    u8 Ciphertext[MAX_PLAINTEXT_LENGTH];
    u32 CiphertextLength = Base64ToAscii(Ciphertext, CipherBase64, CipherBase64Length);

	u8 Plaintext[MAX_PLAINTEXT_LENGTH];
	AesEcbDecrypt(Plaintext, Ciphertext, CiphertextLength, Key, KeyLength);

	GenRandUnchecked((u32 *)Key, AES_128_BLOCK_LENGTH_WORDS);

	u8 NonceCounter[AES_128_BLOCK_LENGTH_BYTES] = {0};
	AesCtrMode(Ciphertext, Plaintext, CiphertextLength, Key, NonceCounter);
}

internal MIN_UNIT_TEST_FUNC(TestCtrEdit)
{
	u8 EditTestBuffer[MAX_PLAINTEXT_LENGTH];
	// TODO(bwd): continue debugging failed test
	/* GenRandUnchecked((u32 *)EditTestBuffer, sizeof(EditTestBuffer)/sizeof(u32)); */
	memset(EditTestBuffer, 'A', sizeof(EditTestBuffer));

	u8 Key[AES_128_BLOCK_LENGTH_BYTES];
	GenRandUnchecked((u32 *)Key, sizeof(Key)/sizeof(u32));

	u8 NonceCounter[AES_128_BLOCK_LENGTH_BYTES] = {0};
	AesCtrMode(EditTestBuffer, EditTestBuffer, sizeof(EditTestBuffer), Key, NonceCounter);

	u8 ExpectedCiphertext[sizeof(EditTestBuffer)];
	memcpy(ExpectedCiphertext, EditTestBuffer, sizeof(EditTestBuffer));

	u32 Offset = rand() % sizeof(EditTestBuffer);
	u8 NewPlaintext[MAX_PLAINTEXT_LENGTH];
	u32 NewPtLength = rand() % (sizeof(EditTestBuffer) - Offset);
	memcpy(NewPlaintext, EditTestBuffer + Offset, NewPtLength);
	CtrEdit(EditTestBuffer, Key, Offset, NewPlaintext, NewPtLength);

	MinUnitAssert(VectorsEqual(EditTestBuffer, ExpectedCiphertext, sizeof(EditTestBuffer)),
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
