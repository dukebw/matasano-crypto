#ifndef AES_TEST_VEC_COMMON_H
#define AES_TEST_VEC_COMMON_H

#include "allheads.h"

#define AES_TEST_MAX_MSG_SIZE	512
#define AES_TEST_BLOCK_SIZE		16

typedef struct
{
	u8 Message[AES_TEST_MAX_MSG_SIZE];
	u8 Cipher[AES_TEST_MAX_MSG_SIZE];
	u8 Key[AES_TEST_BLOCK_SIZE];
	u32 MessageLength;
	u32 KeyLength;
} aes_test_vector;

#endif // AES_TEST_VEC_COMMON_H
