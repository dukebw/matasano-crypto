#ifndef AES_VECTOR_H
#define AES_VECTOR_H

#include "allheads.h"

#define MAX_MESSAGE_SIZE (512*4)
#define MAX_KEY_LENGTH 16

typedef struct
{
	u8 Message[MAX_MESSAGE_SIZE];
	u8 Cipher[MAX_MESSAGE_SIZE];
	u8 Key[MAX_KEY_LENGTH];
	u32 MessageLength;
	u32 KeyLength;
} aes_test_vector;

global_variable aes_test_vector
AesVectors[] =
{
	{
		.Message =
		{
			"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"
		},
		.Cipher =
		{
			"\x69\xC4\xE0\xD8\x6A\x7B\x04\x30\xD8\xCD\xB7\x80\x70\xB4\xC5\x5A"
		},
		.Key =
		{
			"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
		},
		.MessageLength = 16,
		.KeyLength = 16
	},
	{
		.Message =
		{
			"\x32\x43\xF6\xA8\x88\x5A\x30\x8D\x31\x31\x98\xA2\xE0\x37\x07\x34"
		},
		.Cipher =
		{
			"\x39\x25\x84\x1D\x02\xDC\x09\xFB\xDC\x11\x85\x97\x19\x6A\x0B\x32"
		},
		.Key =
		{
			"\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C"
		},
		.MessageLength = 16,
		.KeyLength = 16
	},
};

#endif // AES_VECTOR_H
