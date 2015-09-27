#include "aes.h"

#define MAX_BYTE_AT_A_TIME_MSG_LEN 4096
#define MAX_BLOCK_SIZE_GUESS 32

int main()
{
	u32 Key[AES_128_BLOCK_LENGTH_WORDS];
	u32 Iv[AES_128_BLOCK_LENGTH_WORDS];
	u8 Cipher[2*MAX_BYTE_AT_A_TIME_MSG_LEN];

	// TODO(bwd): append this "unknown-string" to the end of the plaintext
	u8 Base64Plaintext[] = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFp"
						   "ciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRv"
						   "IHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

	Stopif(sizeof(Base64Plaintext) > MAX_BYTE_AT_A_TIME_MSG_LEN, return 1, "Plaintext too short");

	GenRandUnchecked(Key, AES_128_BLOCK_LENGTH_WORDS);

    u8 Plaintext[MAX_BYTE_AT_A_TIME_MSG_LEN];
    u32 PlaintextLength = Base64ToAscii(Plaintext, Base64Plaintext, sizeof(Base64Plaintext) - 1);
    Plaintext[PlaintextLength] = 0;

	// TODO(bwd):
	AesEcbEncrypt(Cipher, (u8 *)GlobalOracleScratch, AppendedMessageLength,
				  (u8 *)Key, AES_128_BLOCK_LENGTH_BYTES);

	for (u32 BlockSizeGuess = 1;
		 BlockSizeGuess <= MAX_BLOCK_SIZE_GUESS;
		 ++BlockSizeGuess)
	{
	}
}
