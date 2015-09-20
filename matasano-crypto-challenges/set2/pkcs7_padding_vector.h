#ifndef PKCS7_PADDING_VECTOR_H
#define PKCS7_PADDING_VECTOR_H

#include "allheads.h"

#define PKCS7_TEST_MAX_MSG_SIZE 128

typedef struct
{
	u8 Message[PKCS7_TEST_MAX_MSG_SIZE];
	u8 PaddedMessage[PKCS7_TEST_MAX_MSG_SIZE];
	u32 MessageLength;
	u32 PaddedLength;
} pkcs7_padding_vec;

global_variable pkcs7_padding_vec
Pkcs7PaddingVecs[] =
{
	{
		.Message = "YELLOW",
		.PaddedMessage = "YELLOW\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A",
		.MessageLength = 6,
		.PaddedLength = 16
	},
	{
		.Message = "YELLOW SUBMARINE SHIP",
		.PaddedMessage = "YELLOW SUBMARINE SHIP\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B",
		.MessageLength = 21,
		.PaddedLength = 32
	},
};

#endif // PKCS7_PADDING_VECTOR_H
