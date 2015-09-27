#include "aes.h"

#define ORACLE_MSG_MAX_WORDS		8192
#define ORACLE_MSG_MAX_BYTES		(ORACLE_MSG_MAX_WORDS*sizeof(u32))
#define RANDOM_ECB					0
#define RANDOM_CBC					1
#define APPEND_MAX_BYTES			10

u32 GlobalOracleScratch[2*ORACLE_MSG_MAX_WORDS];

int main()
{
	u32 Key[AES_128_BLOCK_LENGTH_WORDS];
	u32 Iv[AES_128_BLOCK_LENGTH_WORDS];
	u8 Message[ORACLE_MSG_MAX_BYTES];
	u8 Cipher[2*ORACLE_MSG_MAX_BYTES];

	u32 MessageLength = FileRead(Message, "t8.shakespeare.txt", ORACLE_MSG_MAX_BYTES);
	if (MessageLength == ORACLE_MSG_MAX_BYTES)
	{
		printf("Warning! Max bytes reached\n");
	}

	srand(time(0));

	u32 RandomPrependBytes = APPEND_MAX_BYTES - (rand() % (APPEND_MAX_BYTES/2));
	u32 RandomAppendBytes = APPEND_MAX_BYTES - (rand() % (APPEND_MAX_BYTES/2));

	memset(GlobalOracleScratch, 0xFF, RandomPrependBytes);
	memcpy((u8 *)GlobalOracleScratch + RandomPrependBytes, Message, MessageLength);
	memset((u8 *)GlobalOracleScratch + RandomPrependBytes + MessageLength, 0xFF, RandomAppendBytes);
	u32 AppendedMessageLength = MessageLength + RandomPrependBytes + RandomAppendBytes;

	GenRandUnchecked(Key, AES_128_BLOCK_LENGTH_WORDS);

	u32 RandomEcbCbc = rand() % 2;
	if (RandomEcbCbc == RANDOM_ECB)
	{
		AesEcbEncrypt(Cipher, (u8 *)GlobalOracleScratch, AppendedMessageLength,
					  (u8 *)Key, AES_128_BLOCK_LENGTH_BYTES);
	}
	else
	{
		GenRandUnchecked(Iv, AES_128_BLOCK_LENGTH_WORDS);
		AesCbcEncrypt(Cipher, (u8 *)GlobalOracleScratch, AppendedMessageLength,
					  (u8 *)Key, AES_128_BLOCK_LENGTH_BYTES, (u8 *)Iv);
	}

	u32 PaddedMsgBlockCount;
	if ((AppendedMessageLength % AES_128_BLOCK_LENGTH_BYTES) == 0)
	{
		PaddedMsgBlockCount = (AppendedMessageLength/AES_128_BLOCK_LENGTH_BYTES);
	}
	else
	{
		PaddedMsgBlockCount = (AppendedMessageLength/AES_128_BLOCK_LENGTH_BYTES + 1);
	}

	u32 BlocksEqualCount = 0;
	for (u32 FirstBlockIndex = 0;
		 FirstBlockIndex < (PaddedMsgBlockCount - 1);
		 ++FirstBlockIndex)
	{
		for (u32 SecondBlockIndex = FirstBlockIndex + 1;
			 SecondBlockIndex < PaddedMsgBlockCount;
			 ++SecondBlockIndex)
		{
			char *FirstBlock = (char *)(Cipher + FirstBlockIndex*AES_128_BLOCK_LENGTH_BYTES);
			char *SecondBlock = (char *)(Cipher + SecondBlockIndex*AES_128_BLOCK_LENGTH_BYTES);
			if (memcmp(FirstBlock, SecondBlock, AES_128_BLOCK_LENGTH_BYTES) == 0)
			{
				++BlocksEqualCount;
			}
		}
	}

	printf("BlocksEqualCount: %d\n", BlocksEqualCount);
	printf("RandomEcbCbc: %d\n", RandomEcbCbc);
}
