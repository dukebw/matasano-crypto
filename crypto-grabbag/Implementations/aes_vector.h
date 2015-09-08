#ifndef AES_VECTOR_H
#define AES_VECTOR_H

#include "allheads.h"

#define MAX_MESSAGE_SIZE 512
#define MAX_KEY_LENGTH 4

typedef struct
{
	u32 Message[MAX_MESSAGE_SIZE];
	u32 Cipher[MAX_MESSAGE_SIZE];
	u32 Key[MAX_KEY_LENGTH];
	u32 MessageLength;
	u32 KeyLength;
} aes_test_vector;

global_variable aes_test_vector
AesVector1 =
{
	.Message =
	{
		0xA8F64332, 0x8D305A88, 0xA2983131, 0x340737E0
	},
	.Cipher =
	{
		0x1D842539, 0xFB09DC02, 0x978511DC, 0x320B6A19
	},
	.Key =
	{
		0x16157E2B, 0xA6D2AE28, 0x8815F7AB, 0x3C4FCF09
	},
	.MessageLength = 4,
	.KeyLength = 4
};

#endif // AES_VECTOR_H
