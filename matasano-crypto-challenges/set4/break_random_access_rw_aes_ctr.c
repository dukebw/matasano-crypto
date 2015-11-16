#include "crypt_helper.h"

#define MAX_PLAINTEXT_LENGTH 65536

internal void
CtrEdit(u8 *Ciphertext, u8 *Key, u32 Offset, u8 *NewPlaintext, u32 NewPlaintextLength)
{
	Stopif((Ciphertext == 0) || (Key == 0) || (NewPlaintext == 0), "Null input to CtrEdit!");

	u32 BlocksBeforeOffset = Offset/AES_128_BLOCK_LENGTH_BYTES;
	u32 Aligned16ByteOffset = BlocksBeforeOffset*AES_128_BLOCK_LENGTH_BYTES;
	u32 ExtraAlignmentBytes = (Offset - Aligned16ByteOffset);

	u8 NonceCounter[AES_128_BLOCK_LENGTH_BYTES] = {0};
	*(u32 *)(NonceCounter + 8) = BlocksBeforeOffset;

	AesCtrMode(Ciphertext + Aligned16ByteOffset, Ciphertext, ExtraAlignmentBytes + NewPlaintextLength,
			   Key, NonceCounter);

	memcpy(Ciphertext + Offset, NewPlaintext, NewPlaintextLength);
	*(u32 *)(NonceCounter + 8) = BlocksBeforeOffset;
	AesCtrMode(Ciphertext + Aligned16ByteOffset, Ciphertext, ExtraAlignmentBytes + NewPlaintextLength,
			   Key, NonceCounter);
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
	GenRandUnchecked((u32 *)EditTestBuffer, MAX_PLAINTEXT_LENGTH/sizeof(u32));
	// TODO(bwd): test editting with same buffer and different, aligned/non-aligned
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestCtrEdit);
	MinUnitRunTest(TestBreakRandomAccessRwAesCtr);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
