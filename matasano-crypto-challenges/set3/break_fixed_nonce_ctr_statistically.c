#include "crypt_helper.h"

#define MAX_PT_LENGTH 64

const char PLAINTEXT_1[] = "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==";
const char PLAINTEXT_2[] = "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=";
const char PLAINTEXT_3[] = "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==";
const char PLAINTEXT_4[] = "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=";
const char PLAINTEXT_5[] = "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk";
const char PLAINTEXT_6[] = "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==";
const char PLAINTEXT_7[] = "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=";
const char PLAINTEXT_8[] = "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==";
const char PLAINTEXT_9[] = "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=";
const char PLAINTEXT_10[] = "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl";
const char PLAINTEXT_11[] = "VG8gcGxlYXNlIGEgY29tcGFuaW9u";
const char PLAINTEXT_12[] = "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==";
const char PLAINTEXT_13[] = "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=";
const char PLAINTEXT_14[] = "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==";
const char PLAINTEXT_15[] = "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=";
const char PLAINTEXT_16[] = "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=";
const char PLAINTEXT_17[] = "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==";
const char PLAINTEXT_18[] = "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==";
const char PLAINTEXT_19[] = "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==";
const char PLAINTEXT_20[] = "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==";
const char PLAINTEXT_21[] = "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==";
const char PLAINTEXT_22[] = "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==";
const char PLAINTEXT_23[] = "U2hlIHJvZGUgdG8gaGFycmllcnM/";
const char PLAINTEXT_24[] = "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=";
const char PLAINTEXT_25[] = "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=";
const char PLAINTEXT_26[] = "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=";
const char PLAINTEXT_27[] = "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=";
const char PLAINTEXT_28[] = "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==";
const char PLAINTEXT_29[] = "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==";
const char PLAINTEXT_30[] = "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=";
const char PLAINTEXT_31[] = "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==";
const char PLAINTEXT_32[] = "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu";
const char PLAINTEXT_33[] = "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=";
const char PLAINTEXT_34[] = "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs";
const char PLAINTEXT_35[] = "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=";
const char PLAINTEXT_36[] = "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0";
const char PLAINTEXT_37[] = "SW4gdGhlIGNhc3VhbCBjb21lZHk7";
const char PLAINTEXT_38[] = "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=";
const char PLAINTEXT_39[] = "VHJhbnNmb3JtZWQgdXR0ZXJseTo=";
const char PLAINTEXT_40[] = "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=";

const char *PLAINTEXT_ARRAY[] =
{
	PLAINTEXT_1, PLAINTEXT_2, PLAINTEXT_3, PLAINTEXT_4, PLAINTEXT_5, PLAINTEXT_6, PLAINTEXT_7, PLAINTEXT_8,
	PLAINTEXT_9, PLAINTEXT_10, PLAINTEXT_11, PLAINTEXT_12, PLAINTEXT_13, PLAINTEXT_14, PLAINTEXT_15,
	PLAINTEXT_16, PLAINTEXT_17, PLAINTEXT_18, PLAINTEXT_19, PLAINTEXT_20, PLAINTEXT_21, PLAINTEXT_22,
	PLAINTEXT_23, PLAINTEXT_24, PLAINTEXT_25, PLAINTEXT_26, PLAINTEXT_27, PLAINTEXT_28, PLAINTEXT_29,
	PLAINTEXT_30, PLAINTEXT_31, PLAINTEXT_32, PLAINTEXT_33, PLAINTEXT_34, PLAINTEXT_35, PLAINTEXT_36,
	PLAINTEXT_37, PLAINTEXT_38, PLAINTEXT_39, PLAINTEXT_40
};

const u32 PLAINTEXT_LENGTH_ARRAY[] =
{
	STR_LEN(PLAINTEXT_1), STR_LEN(PLAINTEXT_2), STR_LEN(PLAINTEXT_3), STR_LEN(PLAINTEXT_4),
	STR_LEN(PLAINTEXT_5), STR_LEN(PLAINTEXT_6), STR_LEN(PLAINTEXT_7), STR_LEN(PLAINTEXT_8),
	STR_LEN(PLAINTEXT_9), STR_LEN(PLAINTEXT_10), STR_LEN(PLAINTEXT_11), STR_LEN(PLAINTEXT_12),
	STR_LEN(PLAINTEXT_13), STR_LEN(PLAINTEXT_14), STR_LEN(PLAINTEXT_15), STR_LEN(PLAINTEXT_16),
	STR_LEN(PLAINTEXT_17), STR_LEN(PLAINTEXT_18), STR_LEN(PLAINTEXT_19), STR_LEN(PLAINTEXT_20),
	STR_LEN(PLAINTEXT_21), STR_LEN(PLAINTEXT_22), STR_LEN(PLAINTEXT_23), STR_LEN(PLAINTEXT_24),
	STR_LEN(PLAINTEXT_25), STR_LEN(PLAINTEXT_26), STR_LEN(PLAINTEXT_27), STR_LEN(PLAINTEXT_28),
	STR_LEN(PLAINTEXT_29), STR_LEN(PLAINTEXT_30), STR_LEN(PLAINTEXT_31), STR_LEN(PLAINTEXT_32),
	STR_LEN(PLAINTEXT_33), STR_LEN(PLAINTEXT_34), STR_LEN(PLAINTEXT_35), STR_LEN(PLAINTEXT_36),
	STR_LEN(PLAINTEXT_37), STR_LEN(PLAINTEXT_38), STR_LEN(PLAINTEXT_39), STR_LEN(PLAINTEXT_40)
};

internal MIN_UNIT_TEST_FUNC(TestBreakFixedNonceCtr)
{
	u8 Key[AES_128_BLOCK_LENGTH_BYTES];
	GenRandUnchecked((u32 *)Key, sizeof(Key)/sizeof(u32));

	u8 CiphertextArray[ARRAY_LENGTH(PLAINTEXT_ARRAY)*MAX_PT_LENGTH];
	u8 NonceCounter[AES_128_BLOCK_LENGTH_BYTES] = {0};
	u32 SmallestPtLength = UINT32_MAX;
	for (u32 PlaintextArrayIndex = 0;
		 PlaintextArrayIndex < ARRAY_LENGTH(PLAINTEXT_ARRAY);
		 ++PlaintextArrayIndex)
	{
		u8 *NextCiphertext = CiphertextArray + PlaintextArrayIndex*MAX_PT_LENGTH;
		u32 NextAsciiPtLength = Base64ToAscii(NextCiphertext, (u8 *)PLAINTEXT_ARRAY[PlaintextArrayIndex],
											  PLAINTEXT_LENGTH_ARRAY[PlaintextArrayIndex]);
		AesCtrMode(NextCiphertext, NextCiphertext, NextAsciiPtLength, Key, NonceCounter);
		memset(NonceCounter, 0, sizeof(NonceCounter));

		if (NextAsciiPtLength < SmallestPtLength)
		{
			SmallestPtLength = NextAsciiPtLength;
		}
	}
	Stopif(SmallestPtLength == 0, "Smallest plaintext has no length!");

	u8 DecryptedKey[SmallestPtLength];
	u8 DecryptedPlaintextArray[sizeof(CiphertextArray)];
	for (u32 DecryptedKeyIndex = 0;
		 DecryptedKeyIndex < SmallestPtLength;
		 ++DecryptedKeyIndex)
	{
		u8 NextBlockSameKeyByte[ARRAY_LENGTH(PLAINTEXT_ARRAY)];
		for (u32 CiphertextArrayIndex = 0;
			 CiphertextArrayIndex < ARRAY_LENGTH(PLAINTEXT_ARRAY);
			 ++CiphertextArrayIndex)
		{
			NextBlockSameKeyByte[CiphertextArrayIndex] =
				CiphertextArray[CiphertextArrayIndex*MAX_PT_LENGTH + DecryptedKeyIndex];
		}
		DecryptedKey[DecryptedKeyIndex] = ByteCipherAsciiDecode(NextBlockSameKeyByte,
																ARRAY_LENGTH(PLAINTEXT_ARRAY));
	}

	for (u32 DecryptedPtIndex = 0;
		 DecryptedPtIndex < ARRAY_LENGTH(PLAINTEXT_ARRAY);
		 ++DecryptedPtIndex)
	{
		u8 *NextDecryptedPt = DecryptedPlaintextArray + DecryptedPtIndex*MAX_PT_LENGTH;
		XorVectorsUnchecked(NextDecryptedPt, CiphertextArray + DecryptedPtIndex*MAX_PT_LENGTH,
							DecryptedKey, SmallestPtLength);

		u8 AsciiPlaintextScratch[PLAINTEXT_LENGTH_ARRAY[DecryptedPtIndex]];
		Base64ToAscii(AsciiPlaintextScratch, (u8 *)PLAINTEXT_ARRAY[DecryptedPtIndex],
					  PLAINTEXT_LENGTH_ARRAY[DecryptedPtIndex]);

		MinUnitAssert(AreVectorsEqual((void *)AsciiPlaintextScratch, (void *)NextDecryptedPt, SmallestPtLength),
					  "Expected: %s\nActual: %s\n"
					  "Plaintext/Decrypted ciphertext mismatch in TestBreakFixedNonceCtr at Vector %u\n",
					  AsciiPlaintextScratch, NextDecryptedPt, DecryptedPtIndex);
	}
}

internal MIN_UNIT_TEST_FUNC(AllTests)
{
	MinUnitRunTest(TestBreakFixedNonceCtr);
}

int main()
{
	AllTests();
	printf("All tests passed!\nTests run: %d\n", MinUnitGlobalTestsRun);
}
