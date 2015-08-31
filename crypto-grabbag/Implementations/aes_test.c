#include "aes.h"

#define MAX_MESSAGE_SIZE 2048

int main()
{
	u8 Message[MAX_MESSAGE_SIZE];
	u8 Cipher[MAX_MESSAGE_SIZE];
	u8 Key[KEY_LENGTH*4] =
	{
		0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
	};
	memset(Message, 0xFF, sizeof(Message));
	AesEncryptBlock(Cipher, Message, sizeof(Message), Key, KEY_LENGTH*4);
}
