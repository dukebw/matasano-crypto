#include "crypt_helper.h"

#define MAX_BYTE_AT_A_TIME_MSG_LEN 4096
#define MAX_BLOCK_SIZE_GUESS 32
#define MIN_BLOCK_SIZE_GUESS 16
#define POSSIBLE_BYTE_COUNT 256

u32 GlobalOracleKey[AES_128_BLOCK_LENGTH_WORDS];

internal void
OracleFunction(u8 *Cipher, u8 *Plaintext, u32 PlaintextLength)
{
	Stopif((Plaintext == 0) || (Cipher == 0), "Null input to OracleFunction");
	AesEcbEncrypt(Cipher, Plaintext, PlaintextLength, (u8 *)GlobalOracleKey);
}

internal void
CreateDictionary(u8 *OracleByteDictionary, u8 *DictionaryMessage)
{
	Stopif((OracleByteDictionary == 0) || (DictionaryMessage == 0), "Null inputs to CreateDictionary");

	for (u32 DictionaryIndex = 0;
		 DictionaryIndex < POSSIBLE_BYTE_COUNT;
		 ++DictionaryIndex)
	{
		DictionaryMessage[AES_128_BLOCK_LENGTH_BYTES - 1] = LowByte(DictionaryIndex);
		OracleFunction(OracleByteDictionary + DictionaryIndex*AES_128_BLOCK_LENGTH_BYTES,
					   DictionaryMessage,
					   AES_128_BLOCK_LENGTH_BYTES);
	}
}

internal inline u32
GenerateRandomPrepend(u8 *Plaintext)
{
	Stopif(Plaintext == 0, "Null input to GenerateRandomPrepend");
	u32 RandomPtPrependLengthWords = (rand() % MAX_BYTE_AT_A_TIME_MSG_LEN)/sizeof(u32);
	GenRandUnchecked((u32 *)Plaintext, RandomPtPrependLengthWords);
	return RandomPtPrependLengthWords;
}

int main()
{
	srand(time(0));

	GenRandUnchecked(GlobalOracleKey, AES_128_BLOCK_LENGTH_WORDS);

	u8 UnpaddedPlaintext[MAX_BYTE_AT_A_TIME_MSG_LEN];
	memset(UnpaddedPlaintext, 'A', sizeof(UnpaddedPlaintext));

	u8 Cipher[2*MAX_BYTE_AT_A_TIME_MSG_LEN];

	b32 BlockSizeFound = false;
	u32 BlockSizeGuess;
	for (BlockSizeGuess = MIN_BLOCK_SIZE_GUESS;
		 BlockSizeGuess <= MAX_BLOCK_SIZE_GUESS;
		 BlockSizeGuess += 8)
	{
		OracleFunction(Cipher, UnpaddedPlaintext, sizeof(UnpaddedPlaintext));
		if (AreVectorsEqual(Cipher, Cipher + BlockSizeGuess, BlockSizeGuess))
		{
			BlockSizeFound = true;
			break;
		}
	}

	Stopif(!BlockSizeFound || (BlockSizeGuess != AES_128_BLOCK_LENGTH_BYTES), "Cipher size not determined");

	Stopif(!CipherIsEcbEncrypted(Cipher, sizeof(UnpaddedPlaintext)), "Cipher not ECB encrypted!\n");

	u8 Base64Plaintext[] = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFp"
						   "ciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRv"
						   "IHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

	Stopif(sizeof(Base64Plaintext) > MAX_BYTE_AT_A_TIME_MSG_LEN, "UnpaddedPlaintext too short");

	u32 UnpaddedPtLength = Base64ToAscii(UnpaddedPlaintext, Base64Plaintext, sizeof(Base64Plaintext) - 1);
	UnpaddedPlaintext[UnpaddedPtLength] = 0;

	u8 DictionaryMessage[AES_128_BLOCK_LENGTH_BYTES];
	memset(DictionaryMessage, 'B', sizeof(DictionaryMessage));

	u8 MarkerCipherBlock[2*AES_128_BLOCK_LENGTH_BYTES];
	OracleFunction(MarkerCipherBlock, DictionaryMessage, sizeof(MarkerCipherBlock));

	u8 OracleByteDictionary[POSSIBLE_BYTE_COUNT*AES_128_BLOCK_LENGTH_BYTES];

	// NOTE(bwd): Includes "guess" byte
	u8 AttackPlaintext[MAX_BYTE_AT_A_TIME_MSG_LEN];
	u32 CipherBlockIndex = 0;
	u8 PaddedPlaintext[2*sizeof(UnpaddedPlaintext)];
	u32 KnownPaddingBytes = AES_128_BLOCK_LENGTH_BYTES - 1;
	memset(DictionaryMessage, 'A', sizeof(DictionaryMessage));
	for (u32 CipherIndex = 0;
		 CipherIndex < UnpaddedPtLength;
		 ++CipherIndex)
	{
		b32 MarkerFound = false;
		u32 CipherTargetStartIndex;
		while (!MarkerFound)
		{
			u32 RandomPtPrependLengthBytes = GenerateRandomPrepend(PaddedPlaintext)*sizeof(u32);
			u32 TotalPrependedLength = (RandomPtPrependLengthBytes + KnownPaddingBytes +
										AES_128_BLOCK_LENGTH_BYTES);

			memset(PaddedPlaintext + RandomPtPrependLengthBytes, 'B', AES_128_BLOCK_LENGTH_BYTES);
			memset(PaddedPlaintext + RandomPtPrependLengthBytes + AES_128_BLOCK_LENGTH_BYTES, 'A',
				   KnownPaddingBytes);
			memcpy(PaddedPlaintext + TotalPrependedLength, UnpaddedPlaintext, UnpaddedPtLength);
			u32 PaddedPtTotalLength = TotalPrependedLength + UnpaddedPtLength;
			PaddedPlaintext[PaddedPtTotalLength] = 0;

			OracleFunction(Cipher, PaddedPlaintext, PaddedPtTotalLength);

			for (CipherTargetStartIndex = 0;
				 CipherTargetStartIndex < PaddedPtTotalLength;
				 CipherTargetStartIndex += AES_128_BLOCK_LENGTH_BYTES)
			{
				if (memcmp(Cipher + CipherTargetStartIndex, MarkerCipherBlock, sizeof(MarkerCipherBlock)) == 0)
				{
					MarkerFound = true;
					break;
				}
			}
		}

		CreateDictionary(OracleByteDictionary, DictionaryMessage);

		u8 *CipherTargetBytesStart = Cipher + CipherTargetStartIndex + sizeof(MarkerCipherBlock);

		b32 MatchingVectorFound = false;
		for (u32 DictionaryIndex = 0;
			 DictionaryIndex < POSSIBLE_BYTE_COUNT;
			 ++DictionaryIndex)
		{
            if (AreVectorsEqual(CipherTargetBytesStart + CipherBlockIndex*AES_128_BLOCK_LENGTH_BYTES,
                                OracleByteDictionary + DictionaryIndex*AES_128_BLOCK_LENGTH_BYTES,
                                AES_128_BLOCK_LENGTH_BYTES))
			{
				AttackPlaintext[CipherIndex] = DictionaryIndex;
				DictionaryMessage[sizeof(DictionaryMessage) - 1] = DictionaryIndex;
				memcpy(DictionaryMessage, DictionaryMessage + 1, sizeof(DictionaryMessage) - 1);
				MatchingVectorFound = true;
				break;
			}
		}
		Stopif(!MatchingVectorFound, "No matching vector found!");

		if (KnownPaddingBytes > 0)
		{
			--KnownPaddingBytes;
		}
		else
		{
			++CipherBlockIndex;
			KnownPaddingBytes = AES_128_BLOCK_LENGTH_BYTES - 1;
		}
	}
	Stopif(strlen((char *)AttackPlaintext) != strlen((char *)UnpaddedPlaintext),
		   "AttackPlaintext not equal length to UnpaddedPlaintext");
	Stopif(!AreVectorsEqual(AttackPlaintext, UnpaddedPlaintext, strlen((char *)AttackPlaintext)),
		   "AttackPlaintext and UnpaddedPlaintext unequal!")
	printf("%s", AttackPlaintext);
}
