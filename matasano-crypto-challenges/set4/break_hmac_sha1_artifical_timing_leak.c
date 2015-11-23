#include "crypt_helper.h"

const u8 IPAD[] =
{
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
};
const u8 OPAD[] =
{
	0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
	0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
	0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
	0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
};

#define SHA_1_BLOCK_SIZE 64
#define SHA_1_HMAC_MAX_HASH_INPUT_LENGTH 512

CASSERT(sizeof(IPAD) == SHA_1_BLOCK_SIZE, break_hmac_sha1_artifical_timing_leak_c);
CASSERT(sizeof(OPAD) == SHA_1_BLOCK_SIZE, break_hmac_sha1_artifical_timing_leak_c);

internal void
HmacSha1(u8 *Hmac, u8 *Message, u32 MessageLength, u8 *Key, u32 KeyLength)
{
	Stopif((Hmac == 0) || (Message == 0) || (Key == 0), "Null input to HmacSha1");
	u32 TotalHashedInputSize = (SHA_1_BLOCK_SIZE + MessageLength);
	Stopif(TotalHashedInputSize > SHA_1_HMAC_MAX_HASH_INPUT_LENGTH, "Buffer overflow in HmacSha1");

	u8 KeyScratch[SHA_1_BLOCK_SIZE];
	u8 *K_0;
	if (KeyLength == SHA_1_BLOCK_SIZE)
	{
		K_0 = Key;
	}
	else if (KeyLength > SHA_1_BLOCK_SIZE)
	{
		Sha1(KeyScratch, Key, KeyLength);
		memset(KeyScratch + SHA_1_HASH_LENGTH_BYTES, 0, sizeof(KeyScratch) - SHA_1_HASH_LENGTH_BYTES);
		K_0 = KeyScratch;
	}
	else
	{
		memcpy(KeyScratch, Key, KeyLength);
		memset(KeyScratch + KeyLength, 0, sizeof(KeyScratch) - KeyLength);
		K_0 = KeyScratch;
	}

	u8 HmacScratch[SHA_1_HMAC_MAX_HASH_INPUT_LENGTH];
	XorVectorsUnchecked(HmacScratch, K_0, (u8 *)IPAD, SHA_1_BLOCK_SIZE);
	memcpy(HmacScratch + SHA_1_BLOCK_SIZE, Message, MessageLength);
	Sha1(HmacScratch + SHA_1_BLOCK_SIZE, HmacScratch, TotalHashedInputSize);

	XorVectorsUnchecked(HmacScratch, K_0, (u8 *)OPAD, SHA_1_BLOCK_SIZE);

	Sha1(Hmac, HmacScratch, SHA_1_BLOCK_SIZE + SHA_1_HASH_LENGTH_BYTES);
}

const u8 HMAC_SHA_1_KEY_0[] =
{
	0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
	0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
};

const u32 HMAC_SHA_1_EXPECTED_HASH_0[] =
{
	0x70690E1D, 0xB71FB763, 0x324B7D64, 0x18AA6C08, 0xFBDB1D1B
};

internal MIN_UNIT_TEST_FUNC(TestHmacSha1)
{
	u8 HmacScratch[SHA_1_HASH_LENGTH_BYTES];
	HmacSha1(HmacScratch, (u8 *)"Hi there", 8, (u8 *)HMAC_SHA_1_KEY_0, 20);
	MinUnitAssert(VectorsEqual(HmacScratch, (u8 *)HMAC_SHA_1_EXPECTED_HASH_0, sizeof(HMAC_SHA_1_EXPECTED_HASH_0)),
				  "Expected HMAC mismatch in TestBreakHmacSha1TimingLeak!");
}

internal MIN_UNIT_TEST_FUNC(TestBreakHmacSha1TimingLeak)
{
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestHmacSha1);
	MinUnitRunTest(TestBreakHmacSha1TimingLeak);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
