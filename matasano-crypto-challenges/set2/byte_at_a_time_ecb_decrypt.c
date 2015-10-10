#include "crypt_helper.h"

#define MAX_BYTE_AT_A_TIME_MSG_LEN 4096
#define MAX_BLOCK_SIZE_GUESS 32
#define MIN_BLOCK_SIZE_GUESS 16
#define POSSIBLE_BYTE_COUNT 256

u32 GlobalOracleKey[AES_128_BLOCK_LENGTH_WORDS];

internal void
OracleFunction(u8 *Cipher, u8 *Plaintext, u32 PlaintextLength)
{
	Stopif((Plaintext == 0) || (Cipher == 0), return, "Null input to OracleFunction");
	AesEcbEncrypt(Cipher, Plaintext, PlaintextLength, (u8 *)GlobalOracleKey, sizeof(GlobalOracleKey));
}

internal void
CreateDictionary(u8 *OracleByteDictionary, u8 *DictionaryMessage)
{
	Stopif((OracleByteDictionary == 0) || (DictionaryMessage == 0), return, "Null inputs to CreateDictionary");

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

internal void
ResetPaddedPlaintext(u8 *PaddedPlaintext, u8 *UnpaddedPlaintext, u32 UnpaddedPtLength)
{
	Stopif((PaddedPlaintext == 0) || (UnpaddedPlaintext == 0), return, "Null input to ResetPaddedPlaintext");
	Stopif((UnpaddedPtLength + AES_128_BLOCK_LENGTH_BYTES) >= MAX_BYTE_AT_A_TIME_MSG_LEN,
		   return, "UnpaddedPtLength too long");
	u32 KnownPaddingBytes = AES_128_BLOCK_LENGTH_BYTES - 1;
	memcpy(PaddedPlaintext + KnownPaddingBytes, UnpaddedPlaintext, UnpaddedPtLength);
	PaddedPlaintext[UnpaddedPtLength + KnownPaddingBytes] = 0;
	memset(PaddedPlaintext, 'A', KnownPaddingBytes);
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
		if (VectorsEqual(Cipher, Cipher + BlockSizeGuess, BlockSizeGuess))
		{
			BlockSizeFound = true;
			break;
		}
	}

	Stopif(!BlockSizeFound || (BlockSizeGuess != AES_128_BLOCK_LENGTH_BYTES),
		   return EXIT_FAILURE,
		   "Cipher size not determined");

	Stopif(!CipherIsEcbEncrypted(Cipher, sizeof(UnpaddedPlaintext)),
		   return EXIT_FAILURE,
		   "Cipher not ECB encrypted!\n");

	u8 Base64Plaintext[] = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFp"
						   "ciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRv"
						   "IHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

	Stopif(sizeof(Base64Plaintext) > MAX_BYTE_AT_A_TIME_MSG_LEN,
		   return EXIT_FAILURE,
		   "UnpaddedPlaintext too short");

	u32 KnownPaddingBytes = (AES_128_BLOCK_LENGTH_BYTES - 1);
	u32 UnpaddedPtLength = Base64ToAscii(UnpaddedPlaintext, Base64Plaintext, sizeof(Base64Plaintext) - 1);
	UnpaddedPlaintext[UnpaddedPtLength] = 0;

	u8 PaddedPlaintext[2*sizeof(UnpaddedPlaintext)];
	u32 RandomPtPrependLength = rand() % MAX_BYTE_AT_A_TIME_MSG_LEN;
	GenRandUnchecked((u32 *)PaddedPlaintext, RandomPtPrependLength/sizeof(u32));

	ResetPaddedPlaintext(PaddedPlaintext + RandomPtPrependLength, UnpaddedPlaintext, UnpaddedPtLength);

	u8 DictionaryMessage[AES_128_BLOCK_LENGTH_BYTES];
	memset(DictionaryMessage, 'A', KnownPaddingBytes);

	u8 OracleByteDictionary[POSSIBLE_BYTE_COUNT*AES_128_BLOCK_LENGTH_BYTES];

	// NOTE(bwd): Includes "guess" byte
	u8 AttackPlaintext[MAX_BYTE_AT_A_TIME_MSG_LEN];
	u32 CipherBlockIndex = 0;
	for (u32 CipherIndex = 0;
		 CipherIndex < UnpaddedPtLength;
		 ++CipherIndex)
	{
		OracleFunction(Cipher, PaddedPlaintext, RandomPtPrependLength + UnpaddedPtLength + KnownPaddingBytes);

		CreateDictionary(OracleByteDictionary, DictionaryMessage);

		b32 MatchingVectorFound = false;
		for (u32 DictionaryIndex = 0;
			 DictionaryIndex < POSSIBLE_BYTE_COUNT;
			 ++DictionaryIndex)
		{
			if (VectorsEqual(Cipher + CipherBlockIndex*AES_128_BLOCK_LENGTH_BYTES,
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

		Stopif(!MatchingVectorFound, return EXIT_FAILURE, "No matching vector found in dictionary");

		if (KnownPaddingBytes > 0)
		{
			--KnownPaddingBytes;
			memcpy(PaddedPlaintext + KnownPaddingBytes,
				   PaddedPlaintext + (KnownPaddingBytes + 1),
				   UnpaddedPtLength);
		}
		else
		{
			++CipherBlockIndex;
			KnownPaddingBytes = AES_128_BLOCK_LENGTH_BYTES - 1;
			memcpy(DictionaryMessage,
				   AttackPlaintext + (CipherBlockIndex - 1)*AES_128_BLOCK_LENGTH_BYTES + 1,
				   AES_128_BLOCK_LENGTH_BYTES - 1);
			ResetPaddedPlaintext(PaddedPlaintext, UnpaddedPlaintext, UnpaddedPtLength);
		}
	}
	Stopif(strlen((char *)AttackPlaintext) != strlen((char *)UnpaddedPlaintext),
		   return EXIT_FAILURE,
		   "AttackPlaintext not equal length to UnpaddedPlaintext");
	Stopif(!VectorsEqual(AttackPlaintext, UnpaddedPlaintext, strlen((char *)AttackPlaintext)),
		   return EXIT_FAILURE,
		   "AttackPlaintext and UnpaddedPlaintext unequal!")
	printf("%s", AttackPlaintext);
}
