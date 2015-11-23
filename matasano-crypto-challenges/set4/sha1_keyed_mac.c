#include "crypt_helper.h"

#define SHA_TEST_MAX_MSG_LENGTH 256

typedef struct
{
	const u8 *Message;
	u8 Hash[SHA_1_HASH_LENGTH_BYTES];
	u32 MessageLength;
} sha_test_vector;

#define SHA_1_TEST_MESSAGE_LENGTH(Message) (sizeof(Message) - 1)
const u8 SHA_1_TEST_MESSAGE_0[] = "";
const u8 SHA_1_TEST_MESSAGE_1[] = "\x36";
const u8 SHA_1_TEST_MESSAGE_2[] = "\x19\x5A";
const u8 SHA_1_TEST_MESSAGE_3[] = "\xDF\x4B\xD2";
const u8 SHA_1_TEST_MESSAGE_4[] = "\x54\x9E\x95\x9E";
const u8 SHA_1_TEST_MESSAGE_5[] = "\xF7\xFB\x1B\xE2\x05";
const u8 SHA_1_TEST_MESSAGE_6[] = "\xC0\xE5\xAB\xEA\xEA\x63";
const u8 SHA_1_TEST_MESSAGE_7[] = "\x63\xBF\xC1\xED\x7F\x78\xAB";
const u8 SHA_1_TEST_MESSAGE_8[] = "\x7E\x3D\x7B\x3E\xAD\xA9\x88\x66";
const u8 SHA_1_TEST_MESSAGE_9[] = "\x9E\x61\xE5\x5D\x9E\xD3\x7B\x1C\x20";
const u8 SHA_1_TEST_MESSAGE_10[] = "\x7C\x9C\x67\x32\x3A\x1D\xF1\xAD\xBF\xE5\xCE\xB4\x15\xEA\xEF\x01"
								   "\x55\xEC\xE2\x82\x0F\x4D\x50\xC1\xEC\x22\xCB\xA4\x92\x8A\xC6\x56"
								   "\xC8\x3F\xE5\x85\xDB\x6A\x78\xCE\x40\xBC\x42\x75\x7A\xBA\x7E\x5A"
								   "\x3F\x58\x24\x28\xD6\xCA\x68\xD0\xC3\x97\x83\x36\xA6\xEF\xB7\x29"
								   "\x61\x3E\x8D\x99\x79\x01\x62\x04\xBF\xD9\x21\x32\x2F\xDD\x52\x22"
								   "\x18\x35\x54\x44\x7D\xE5\xE6\xE9\xBB\xE6\xED\xF7\x6D\x7B\x71\xE1"
								   "\x8D\xC2\xE8\xD6\xDC\x89\xB7\x39\x83\x64\xF6\x52\xFA\xFC\x73\x43"
								   "\x29\xAA\xFA\x3D\xCD\x45\xD4\xF3\x1E\x38\x8E\x4F\xAF\xD7\xFC\x64"
								   "\x95\xF3\x7C\xA5\xCB\xAB\x7F\x54\xD5\x86\x46\x3D\xA4\xBF\xEA\xA3"
								   "\xBA\xE0\x9F\x7B\x8E\x92\x39\xD8\x32\xB4\xF0\xA7\x33\xAA\x60\x9C"
								   "\xC1\xF8\xD4";

const sha_test_vector
SHA_1_TEST_VECTORS[] =
{
	{
		.Message = SHA_1_TEST_MESSAGE_0,
		.Hash =
		{
			0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55,
			0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09
		},
		.MessageLength = SHA_1_TEST_MESSAGE_LENGTH(SHA_1_TEST_MESSAGE_0),
	},
	{
		.Message = SHA_1_TEST_MESSAGE_1,
		.Hash =
		{
			0xC1, 0xDF, 0xD9, 0x6E, 0xEA, 0x8C, 0xC2, 0xB6, 0x27, 0x85,
			0x27, 0x5B, 0xCA, 0x38, 0xAC, 0x26, 0x12, 0x56, 0xE2, 0x78, 
		},
		.MessageLength = SHA_1_TEST_MESSAGE_LENGTH(SHA_1_TEST_MESSAGE_1),
	},
	{
		.Message = SHA_1_TEST_MESSAGE_2,
		.Hash =
		{
			0x0A, 0x1C, 0x2D, 0x55, 0x5B, 0xBE, 0x43, 0x1A, 0xD6, 0x28,
			0x8A, 0xF5, 0xA5, 0x4F, 0x93, 0xE0, 0x44, 0x9C, 0x92, 0x32, 
		},
		.MessageLength = SHA_1_TEST_MESSAGE_LENGTH(SHA_1_TEST_MESSAGE_2),
	},
	{
		.Message = SHA_1_TEST_MESSAGE_3,
		.Hash =
		{
			0xBF, 0x36, 0xED, 0x5D, 0x74, 0x72, 0x7D, 0xFD, 0x5D, 0x78,
			0x54, 0xEC, 0x6B, 0x1D, 0x49, 0x46, 0x8D, 0x8E, 0xE8, 0xAA, 
		},
		.MessageLength = SHA_1_TEST_MESSAGE_LENGTH(SHA_1_TEST_MESSAGE_3),
	},
	{
		.Message = SHA_1_TEST_MESSAGE_4,
		.Hash =
		{
			0xB7, 0x8B, 0xAE, 0x6D, 0x14, 0x33, 0x8F, 0xFC, 0xCF, 0xD5,
			0xD5, 0xB5, 0x67, 0x4A, 0x27, 0x5F, 0x6E, 0xF9, 0xC7, 0x17, 
		},
		.MessageLength = SHA_1_TEST_MESSAGE_LENGTH(SHA_1_TEST_MESSAGE_4),
	},
	{
		.Message = SHA_1_TEST_MESSAGE_5,
		.Hash =
		{
			0x60, 0xB7, 0xD5, 0xBB, 0x56, 0x0A, 0x1A, 0xCF, 0x6F, 0xA4,
			0x57, 0x21, 0xBD, 0x0A, 0xBB, 0x41, 0x9A, 0x84, 0x1A, 0x89, 
		},
		.MessageLength = SHA_1_TEST_MESSAGE_LENGTH(SHA_1_TEST_MESSAGE_5),
	},
	{
		.Message = SHA_1_TEST_MESSAGE_6,
		.Hash =
		{
			0xA6, 0xD3, 0x38, 0x45, 0x97, 0x80, 0xC0, 0x83, 0x63, 0x09,
			0x0F, 0xD8, 0xFC, 0x7D, 0x28, 0xDC, 0x80, 0xE8, 0xE0, 0x1F, 
		},
		.MessageLength = SHA_1_TEST_MESSAGE_LENGTH(SHA_1_TEST_MESSAGE_6),
	},
	{
		.Message = SHA_1_TEST_MESSAGE_7,
		.Hash =
		{
			0x86, 0x03, 0x28, 0xD8, 0x05, 0x09, 0x50, 0x0C, 0x17, 0x83,
			0x16, 0x9E, 0xBF, 0x0B, 0xA0, 0xC4, 0xB9, 0x4D, 0xA5, 0xE5, 
		},
		.MessageLength = SHA_1_TEST_MESSAGE_LENGTH(SHA_1_TEST_MESSAGE_7),
	},
	{
		.Message = SHA_1_TEST_MESSAGE_8,
		.Hash =
		{
			0x24, 0xA2, 0xC3, 0x4B, 0x97, 0x63, 0x05, 0x27, 0x7C, 0xE5,
			0x8C, 0x2F, 0x42, 0xD5, 0x09, 0x20, 0x31, 0x57, 0x25, 0x20, 
		},
		.MessageLength = SHA_1_TEST_MESSAGE_LENGTH(SHA_1_TEST_MESSAGE_8),
	},
	{
		.Message = SHA_1_TEST_MESSAGE_9,
		.Hash =
		{
			0x41, 0x1C, 0xCE, 0xE1, 0xF6, 0xE3, 0x67, 0x7D, 0xF1, 0x26,
			0x98, 0x41, 0x1E, 0xB0, 0x9D, 0x3F, 0xF5, 0x80, 0xAF, 0x97, 
		},
		.MessageLength = SHA_1_TEST_MESSAGE_LENGTH(SHA_1_TEST_MESSAGE_9),
	},
	{
		.Message = SHA_1_TEST_MESSAGE_10,
		.Hash =
		{
			0xD8, 0xFD, 0x6A, 0x91, 0xEF, 0x3B, 0x6C, 0xED, 0x05, 0xB9,
			0x83, 0x58, 0xA9, 0x91, 0x07, 0xC1, 0xFA, 0xC8, 0xC8, 0x07, 
		},
		.MessageLength = SHA_1_TEST_MESSAGE_LENGTH(SHA_1_TEST_MESSAGE_10),
	},
};

const u8
SHA_1_KEYED_MAC_SECRET_KEY[] =
{
	0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
	0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
};
#define SHA_1_MAC_KEY_LENGTH (sizeof(SHA_1_KEYED_MAC_SECRET_KEY))

internal b32
Sha1KeyedMacAuthenticate(u8 *Message, u32 MessageLength, u8 *MacSignature)
{
	b32 Authenticated;

	Stopif((Message == 0) || (MacSignature == 0), "Null input to Sha1KeyedMacAuthenticate!");

	u8 Hmac[SHA_1_HASH_LENGTH_BYTES];
	Sha1KeyedMac(Hmac, Message, MessageLength, (u8 *)SHA_1_KEYED_MAC_SECRET_KEY, SHA_1_MAC_KEY_LENGTH);

	Authenticated = VectorsEqual(Hmac, MacSignature, sizeof(Hmac));

	return Authenticated;
}

internal MIN_UNIT_TEST_FUNC(TestSha1KeyedMac)
{
	u8 ScratchMessage[SHA_TEST_MAX_MSG_LENGTH/2];
	for (u32 GoodCaseIndex = 0;
		 GoodCaseIndex < 128;
		 ++GoodCaseIndex)
	{
		GenRandUnchecked((u32 *)ScratchMessage, sizeof(ScratchMessage)/sizeof(u32));

		u8 ScratchHmac[SHA_1_HASH_LENGTH_BYTES];
		Sha1KeyedMac(ScratchHmac, ScratchMessage, sizeof(ScratchMessage), (u8 *)SHA_1_KEYED_MAC_SECRET_KEY,
				 SHA_1_MAC_KEY_LENGTH);
		b32 Authenticated = Sha1KeyedMacAuthenticate(ScratchMessage, sizeof(ScratchMessage), ScratchHmac);
		MinUnitAssert(Authenticated, "Valid case not authenticated in TestSha1KeyedMac!");
	}

	for (u32 BadCaseIndex = 0;
		 BadCaseIndex < 128;
		 ++BadCaseIndex)
	{
		GenRandUnchecked((u32 *)ScratchMessage, sizeof(ScratchMessage)/sizeof(u32));
		u8 ScratchHmac[SHA_1_HASH_LENGTH_BYTES];
		Sha1(ScratchHmac, ScratchMessage, sizeof(ScratchMessage));
		b32 Authenticated = Sha1KeyedMacAuthenticate(ScratchMessage, sizeof(ScratchMessage), ScratchHmac);
		MinUnitAssert(!Authenticated, "Invalid case authenticated in TestSha1KeyedMac!");
	}
}

internal MIN_UNIT_TEST_FUNC(TestSha1)
{
	u8 Hash[SHA_1_HASH_LENGTH_BYTES];
	for (u32 TestVecIndex = 0;
		 TestVecIndex < ARRAY_LENGTH(SHA_1_TEST_VECTORS);
		 ++TestVecIndex)
	{
		Sha1(Hash, (u8 *)SHA_1_TEST_VECTORS[TestVecIndex].Message, SHA_1_TEST_VECTORS[TestVecIndex].MessageLength);
		MinUnitAssert(VectorsEqual(Hash, (void *)SHA_1_TEST_VECTORS[TestVecIndex].Hash, sizeof(Hash)),
					  "Hash/expected hash mismatch in TestSha1! TestVecIndex: %d\n", TestVecIndex);
	}
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestSha1);
	MinUnitRunTest(TestSha1KeyedMac);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
