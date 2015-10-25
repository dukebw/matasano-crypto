#ifndef AES_H
#define AES_H

#include "aes_test_vec_common.h"

// TODO(brendan): 128 bits for now -- add 192 and 256 bit versions
#define KEY_LENGTH_WORDS			4 // NOTE(brendan): 32-bit words
#define KEY_LENGTH_BYTES			(KEY_LENGTH_WORDS*sizeof(u32))
#define COL_COUNT_NB				4
#define ROW_COUNT_NK				KEY_LENGTH_WORDS
#define NUMBER_OF_ROUNDS			10
#define AES_SUCCESS					0
#define MIX_COL_COEFFS				0x01010302
#define INV_MIX_COL_COEFFS			0x090D0B0E
#define AES_128_BLOCK_LENGTH_BYTES	16
#define AES_128_BLOCK_LENGTH_WORDS	(AES_128_BLOCK_LENGTH_BYTES/sizeof(u32))

// TODO(brendan): use struct context instead of global state
global_variable u8 GlobalStateArray[ROW_COUNT_NK*COL_COUNT_NB];
global_variable u32 GlobalKeySchedule[(NUMBER_OF_ROUNDS + 1)*COL_COUNT_NB];

global_variable u8 SBox[] =
{
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
	0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
	0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
	0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
	0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
	0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
	0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
	0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
	0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
	0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
	0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
	0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
	0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
	0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
	0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
	0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
	0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

global_variable u8 InverseSBox[] =
{ 
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// NOTE(brendan): Rcon[i] contains [x^(i - 1), 0, 0, 0]
global_variable u8 RoundConstant[] =
{
  0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
  0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
  0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A,
  0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8,
  0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF,
  0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC,
  0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B,
  0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3,
  0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94,
  0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
  0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35,
  0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD, 0x61, 0xC2, 0x9F,
  0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB, 0x8D, 0x01, 0x02, 0x04,
  0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63,
  0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39, 0x72, 0xE4, 0xD3, 0xBD,
  0x61, 0xC2, 0x9F, 0x25, 0x4A, 0x94, 0x33, 0x66, 0xCC, 0x83, 0x1D, 0x3A, 0x74, 0xE8, 0xCB
};

internal inline u8
LowByte(u32 Word)
{
	u8 Result = (Word & 0xFF);
	return Result;
}

internal inline u8
MidLowByte(u32 Word)
{
	u8 Result = ((Word >> 8) & 0xFF);
	return Result;
}

internal inline u8
MidHighByte(u32 Word)
{
	u8 Result = ((Word >> 16) & 0xFF);
	return Result;
}

internal inline u8
HighByte(u32 Word)
{
	u8 Result = ((Word >> 24) & 0xFF);
	return Result;
}

// TODO(brendan): parallelize (operate on u32)?
internal inline u8
MultiplyByX(u8 ByteValue)
{
	u8 Result;
	if (ByteValue & 0x80)
	{
		// NOTE(brendan): if Result > m(x) reduce mod m(x)
		Result = (LowByte(ByteValue << 1) ^ 0x1B);
	}
	else
	{
		Result = LowByte(ByteValue << 1);
	}
	return Result;
}

internal inline u8
MultiplyByPowerOfX(u8 ByteValue, u32 Power)
{
	u8 Result = ByteValue;
	Stopif(Power >= 8, "Power of X too high");
	for (u32 PowerIndex = 0;
		 PowerIndex < Power;
		 ++PowerIndex)
	{
		Result = MultiplyByX(Result);
	}
	return Result;
}

internal inline u8
MultiplyByCoefficient(u8 Value, u8 Coefficient)
{
	Stopif(Coefficient & 0xF0, "Invalid coefficient in MultiplyByCoefficient");
	u8 Result = 0;
	if (Coefficient & 0x1)
	{
		Result ^= Value;
	}
	if (Coefficient & 0x2)
	{
		Result ^= MultiplyByX(Value);
	}
	if (Coefficient & 0x4)
	{
		Result ^= MultiplyByPowerOfX(Value, 2);
	}
	if (Coefficient & 0x8)
	{
		Result ^= MultiplyByPowerOfX(Value, 3);
	}
	return Result;
}

internal inline u8
MixColumnsByteTransform(u8 A, u8 B, u8 C, u8 D, u32 Coefficients)
{
	u8 Result = (MultiplyByCoefficient(A, LowByte(Coefficients)) ^
				 MultiplyByCoefficient(B, MidLowByte(Coefficients)) ^
				 MultiplyByCoefficient(C, MidHighByte(Coefficients)) ^
				 MultiplyByCoefficient(D, HighByte(Coefficients)));
	return Result;
}

internal inline u32
Word(u8 A, u8 B, u8 C, u8 D)
{
	u32 Result = (A | (B << 8) | (C << 16) | (D << 24));
	return Result;
}

internal void
AddRoundKey(u8 *StateArray, u32 *KeySchedule)
{
	Stopif((StateArray == 0) || (KeySchedule == 0), "Null inputs to AddRoundKey()");
	for (u32 RoundKeyIndex = 0;
		 RoundKeyIndex < COL_COUNT_NB;
		 ++RoundKeyIndex)
	{
		u32 *Column = (u32 *)(StateArray + 4*RoundKeyIndex);
		*Column = *Column ^ KeySchedule[RoundKeyIndex];
	}
}

internal inline u32
RotateWordLeft(u32 Word, i32 Amount)
{
	u32 Result;
	Amount &= 31;
	Result = ((Word << Amount) | (Word >> (32 - Amount)));
	return Result;
}

internal inline u32
RotateWordRight(u32 Word, i32 Amount)
{
	u32 Result;
	Amount &= 31;
	Result = ((Word >> Amount) | (Word << (32 - Amount)));
	return Result;
}

internal inline void
ShiftRowsInternal(u8 *StateArray, i32 InverseMultiplier)
{
	Stopif(StateArray == 0, "Null input to SubBytes()");
	Stopif((InverseMultiplier != -1) && (InverseMultiplier != 1), "Invalid value for InverseMultiplier");
	// s[r][c] = s[r][c + shift(r, Nb) mod Nb] for 0 < r < 4 and 0 <= c < Nb
	// where shift(n, 4) == n
	for (u32 RowIndex = 1;
		 RowIndex < ROW_COUNT_NK;
		 ++RowIndex)
	{
		u32 Row = Word(StateArray[RowIndex], StateArray[ROW_COUNT_NK + RowIndex],
					   StateArray[2*ROW_COUNT_NK + RowIndex], StateArray[3*ROW_COUNT_NK + RowIndex]);
		Row = RotateWordRight(Row, 8*InverseMultiplier*RowIndex);
		StateArray[RowIndex] = LowByte(Row);
		StateArray[RowIndex + ROW_COUNT_NK] = MidLowByte(Row);
		StateArray[RowIndex + 2*ROW_COUNT_NK] = MidHighByte(Row);
		StateArray[RowIndex + 3*ROW_COUNT_NK] = HighByte(Row);
	}
}

internal inline void
ShiftRows(u8 *StateArray)
{
	ShiftRowsInternal(StateArray, 1);
}

internal inline void
InverseShiftRows(u8 *StateArray)
{
	ShiftRowsInternal(StateArray, -1);
}

internal inline u32
SubstituteWord(u32 Word)
{
	u32 Result;
	Result = SBox[LowByte(Word)];
	Result |= (SBox[MidLowByte(Word)] << 8);
	Result |= (SBox[MidHighByte(Word)] << 16);
	Result |= (SBox[HighByte(Word)] << 24);
	return Result;
}

// NOTE(brendan): Internal so no need to check SBox != 0
internal inline void
SubBytesInternal(u8 *StateArray, u32 Length, u8 *SBoxInternal)
{
	Stopif(StateArray == 0, "Null input to SubBytes/InverseSubBytes()");
	// 1.	Take the multiplicative inverse in the finite field GF(2^8).
	// 2.	Apply the following affine transformation over GF(2):
	//		b[i] = b[i] ^ b[(i + 4) mod 8] ^ b[(i + 5) mod 8] ^ b[(i + 6) mod 8] ^
	//			   b[(i + 7) mod 8] ^ c[i]
	// 		Where b[i] is the i'th bit of the byte, and c[i] is the i'th bit of a
	//		byte c with value 0x63.
	for (u32 StateByteIndex = 0;
		 StateByteIndex < Length;
		 ++StateByteIndex)
	{
		StateArray[StateByteIndex] = SBoxInternal[StateArray[StateByteIndex]];
	}
}

internal inline void
SubBytes(u8 *StateArray, u32 Length)
{
	SubBytesInternal(StateArray, Length, SBox);
}

internal inline void
InverseSubBytes(u8 *StateArray, u32 Length)
{
	SubBytesInternal(StateArray, Length, InverseSBox);
}

internal void
MixColumnsInternal(u8 *StateArray, u32 Coefficients)
{
	Stopif(StateArray == 0, "Null input to MixColumns");
	// Columns are considered as four-term polynomials over GF(2^8) and multiplied
	// modulo x^4 + 1 with fixed polynomial a(x) = 3x^3 + x^2 + x + 2.
	for (u32 ColumnOffset = 0;
		 ColumnOffset < 4*COL_COUNT_NB;
		 ColumnOffset += 4)
	{
		// NOTE(brendan): Multiplication of polynomials over GF(2^8) by x:
		// x*b(x), where b(x) := b[7]*x^7 + ... + b[0] is obtained by
		// reducing the above result modulo m(x) := x^8 + x^4 + x^3 + x + 1
		// (irreducible polynomial over GF(2^8)). If b[7] == 0, the result is
		// already reduced. If b[7] == 1, the reduction is accomplished by XOR'ing m(x)
		// (subtracting m(x)).
		u32 Column = *(u32 *)(StateArray + ColumnOffset);
		u8 ColumnLow = LowByte(Column);
		u8 ColumnMidLow = MidLowByte(Column);
		u8 ColumnMidHigh = MidHighByte(Column);
		u8 ColumnHigh = HighByte(Column);

		u8 *Row0 = (StateArray + ColumnOffset);
		u8 *Row1 = (StateArray + ColumnOffset + 1);
		u8 *Row2 = (StateArray + ColumnOffset + 2);
		u8 *Row3 = (StateArray + ColumnOffset + 3);
		*Row0 = MixColumnsByteTransform(ColumnLow, ColumnMidLow, ColumnMidHigh, ColumnHigh, Coefficients);
		*Row1 = MixColumnsByteTransform(ColumnMidLow, ColumnMidHigh, ColumnHigh, ColumnLow, Coefficients);
		*Row2 = MixColumnsByteTransform(ColumnMidHigh, ColumnHigh, ColumnLow, ColumnMidLow, Coefficients);
		*Row3 = MixColumnsByteTransform(ColumnHigh, ColumnLow, ColumnMidLow, ColumnMidHigh, Coefficients);
	}
}

internal inline void
MixColumns(u8 *StateArray)
{
	MixColumnsInternal(StateArray, MIX_COL_COEFFS);
}

internal inline void
InverseMixColumns(u8 *StateArray)
{
	MixColumnsInternal(StateArray, INV_MIX_COL_COEFFS);
}

internal void
CreateKeySchedule(u32 *KeySchedule, u32 KeyScheduleLength, u8 *Key, u32 KeyLength)
{
	Stopif((Key == 0) || (KeySchedule == 0), "Null input passed to CreateKeySchedule()");
	memcpy(KeySchedule, Key, KeyLength);
	for (u32 KeyIndex = ROW_COUNT_NK;
		 KeyIndex < KeyScheduleLength;
		 ++KeyIndex)
	{
		u32 Temp = KeySchedule[KeyIndex - 1];
		if ((KeyIndex % ROW_COUNT_NK) == 0)
		{
			Temp = SubstituteWord(RotateWordRight(Temp, 8)) ^ (u32)RoundConstant[KeyIndex/ROW_COUNT_NK];
		}
		else if ((ROW_COUNT_NK > 6) && ((KeyIndex % ROW_COUNT_NK) == 4))
		{
			Temp = SubstituteWord(Temp);
		}
		KeySchedule[KeyIndex] = KeySchedule[KeyIndex - ROW_COUNT_NK] ^ Temp;
	}
}

// NOTE(brendan): INPUT: Sequences of 128 bits. OUTPUT: Same.
internal void
AesEncryptBlock(u8 *Cipher, u8 *Message, u8 *Key, u32 KeyLength)
{
	Stopif((Cipher == 0) || (Message == 0) || (Key == 0), "Null input to AesEncrypt()");
	Stopif(KeyLength != KEY_LENGTH_BYTES, "Invalid key length");

	// KeyExpansion(byte key[4*Nk], word w[Nb*(Nr + 1)], Nk)
	CreateKeySchedule(GlobalKeySchedule, ARRAY_LENGTH(GlobalKeySchedule), Key, KeyLength);

	memcpy(GlobalStateArray, Message, ARRAY_LENGTH(GlobalStateArray));

	// AddRoundKey(state, w[0, Nb - 1])
	AddRoundKey(GlobalStateArray, GlobalKeySchedule);

	for (u32 RoundIndex = 1;
		 RoundIndex < NUMBER_OF_ROUNDS;
		 ++RoundIndex)
	{
		SubBytes(GlobalStateArray, ARRAY_LENGTH(GlobalStateArray));
		ShiftRows(GlobalStateArray);

		// MixColumns(state)
		MixColumns(GlobalStateArray);
		AddRoundKey(GlobalStateArray, GlobalKeySchedule + RoundIndex*COL_COUNT_NB);
	}
	SubBytes(GlobalStateArray, ARRAY_LENGTH(GlobalStateArray));
	ShiftRows(GlobalStateArray);
	AddRoundKey(GlobalStateArray, GlobalKeySchedule + NUMBER_OF_ROUNDS*COL_COUNT_NB);

	memcpy(Cipher, GlobalStateArray, ARRAY_LENGTH(GlobalStateArray));
}

internal void
AesDecryptBlock(u8 *Message, u8 *Cipher, u32 CipherLength, u8 *Key, u32 KeyLength)
{
	Stopif((Cipher == 0) || (Message == 0) || (Key == 0), "Null input to AesDecryptBlock()");
	Stopif(CipherLength < COL_COUNT_NB*ROW_COUNT_NK, "Bad cipher block size");
	Stopif(KeyLength != KEY_LENGTH_BYTES, "Invalid key length");

	// KeyExpansion(byte key[4*Nk], word w[Nb*(Nr + 1)], Nk)
	CreateKeySchedule(GlobalKeySchedule, ARRAY_LENGTH(GlobalKeySchedule), Key, KeyLength);

	memcpy(GlobalStateArray, Cipher, ARRAY_LENGTH(GlobalStateArray));

	// AddRoundKey(state, w[Nr*Nb, (Nr + 1)*Nb - 1])
	AddRoundKey(GlobalStateArray, GlobalKeySchedule + NUMBER_OF_ROUNDS*COL_COUNT_NB);

	for (u32 RoundIndex = (NUMBER_OF_ROUNDS - 1);
		 RoundIndex >= 1;
		 --RoundIndex)
	{
		InverseShiftRows(GlobalStateArray);
		InverseSubBytes(GlobalStateArray, ARRAY_LENGTH(GlobalStateArray));

		// AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
		AddRoundKey(GlobalStateArray, GlobalKeySchedule + RoundIndex*COL_COUNT_NB);

		// InvMixColumns(state)
		InverseMixColumns(GlobalStateArray);
	}
	InverseShiftRows(GlobalStateArray);
	InverseSubBytes(GlobalStateArray, ARRAY_LENGTH(GlobalStateArray));

	// AddRoundKey(state, w[0, Nb - 1])
	AddRoundKey(GlobalStateArray, GlobalKeySchedule);

	memcpy(Message, GlobalStateArray, ARRAY_LENGTH(GlobalStateArray));
}

internal u32
Pkcs7Pad(u8 *PaddedMessage, u8 *Message, u32 MessageLength)
{
	u32 PaddedLength = MessageLength;
	Stopif((PaddedMessage == 0) || (Message == 0), "Null input to Pkcs7Pad()");

	if (PaddedMessage != Message)
	{
		memcpy(PaddedMessage, Message, MessageLength);
	}

	u32 MessageModBlock = MessageLength % AES_128_BLOCK_LENGTH_BYTES;
	u32 ExtraPaddingBytes = AES_128_BLOCK_LENGTH_BYTES - MessageModBlock;
	PaddedLength += ExtraPaddingBytes;
	for (u32 ExtraPaddingIndex = 0;
		 ExtraPaddingIndex < ExtraPaddingBytes;
		 ++ExtraPaddingIndex)
	{
		PaddedMessage[MessageLength + ExtraPaddingIndex] = ExtraPaddingBytes;
	}
	return PaddedLength;
}

internal inline void
XorVectorsUnchecked(u8 *Dest, u8 *A, u8 *B, u32 Length)
{
	for (u32 VectorIndex = 0;
		 VectorIndex < Length;
		 ++VectorIndex)
	{
		Dest[VectorIndex] = A[VectorIndex] ^ B[VectorIndex];
	}
}

internal u32
AesCbcEncrypt(u8 *Cipher, u8 *Message, u32 MessageLength, u8 *Key, u32 KeyLength, u8 *Iv)
{
	Stopif((Message == 0) || (Cipher == 0) || (Key == 0) || (Iv == 0), "Null inputs to AesCbcEncrypt");
	Stopif(KeyLength != KEY_LENGTH_BYTES, "Only AES-128 is supported");
	Stopif(MessageLength == 0, "AesCbcEncrypt - Message of length 0");

	u32 PaddedMsgLength = Pkcs7Pad(Message, Message, MessageLength);

	XorVectorsUnchecked(Cipher, Message, Iv, AES_128_BLOCK_LENGTH_BYTES);
	AesEncryptBlock(Cipher, Cipher, Key, KeyLength);

	for (u32 MessageBlockIndex = 1;
		 MessageBlockIndex < PaddedMsgLength/AES_128_BLOCK_LENGTH_BYTES;
		 ++MessageBlockIndex)
	{
		u32 MessageIndexBytes = MessageBlockIndex*AES_128_BLOCK_LENGTH_BYTES;
		XorVectorsUnchecked(Cipher + MessageIndexBytes,
							Message + MessageIndexBytes,
							Cipher + (MessageBlockIndex - 1)*AES_128_BLOCK_LENGTH_BYTES,
							AES_128_BLOCK_LENGTH_BYTES);
		AesEncryptBlock(Cipher + MessageIndexBytes, Cipher + MessageIndexBytes, Key, KeyLength);
	}
	return PaddedMsgLength;
}

internal inline u32
FindPaddedLength(u32 MessageLength)
{
	u32 Result = MessageLength;
	u32 MessageModBlock = (MessageLength % AES_128_BLOCK_LENGTH_BYTES);
	if (MessageModBlock != 0)
	{
		Result += AES_128_BLOCK_LENGTH_BYTES - MessageModBlock;
	}

	Stopif((Result % AES_128_BLOCK_LENGTH_BYTES) != 0, "FindPaddedLength output invalid byte-length");

	return Result;
}

internal void
AesCbcDecrypt(u8 *Message, u8 *Cipher, u32 MessageLength, u8 *Key, u32 KeyLength, u8 *Iv)
{
	Stopif((Message == 0) || (Cipher == 0) || (Key == 0) || (Iv == 0), "Null inputs to AesCbcDecrypt");
	Stopif(KeyLength != KEY_LENGTH_BYTES, "Only AES-128 is supported");
	Stopif(MessageLength == 0, "AesCbcDecrypt - Message of length 0");

	u32 PaddedMsgLength = FindPaddedLength(MessageLength);

	u32 PaddedBlockCount = PaddedMsgLength/AES_128_BLOCK_LENGTH_BYTES;
	Stopif(PaddedBlockCount < 1, "Invalid block count in AesCbcDecrypt");

	for (u32 MessageBlockIndex = (PaddedBlockCount - 1);
		 MessageBlockIndex > 0;
		 --MessageBlockIndex)
	{
		u32 MessageIndexBytes = MessageBlockIndex*AES_128_BLOCK_LENGTH_BYTES;
		u8 *MsgStartOfBlock = Message + MessageIndexBytes;
		AesDecryptBlock(MsgStartOfBlock, Cipher + MessageIndexBytes, AES_128_BLOCK_LENGTH_BYTES,
						Key, KeyLength);
		XorVectorsUnchecked(MsgStartOfBlock,
							MsgStartOfBlock,
							Cipher + (MessageBlockIndex - 1)*AES_128_BLOCK_LENGTH_BYTES,
							AES_128_BLOCK_LENGTH_BYTES);
	}

	AesDecryptBlock(Message, Cipher, PaddedMsgLength, Key, KeyLength);
	XorVectorsUnchecked(Message, Message, Iv, AES_128_BLOCK_LENGTH_BYTES);
}

internal void
AesEcbEncrypt(u8 *Cipher, u8 *Message, u32 MessageLength, u8 *Key, u32 KeyLength)
{
	Stopif((Message == 0) || (Cipher == 0) || (Key == 0), "Null inputs to AesCbcEncrypt");
	Stopif(KeyLength != KEY_LENGTH_BYTES, "Only AES-128 is supported");
	Stopif(MessageLength == 0, "AesEcbEncrypt - Message of length 0");

	u32 PaddedMsgLength = Pkcs7Pad(Message, Message, MessageLength);

	for (u32 MessageBlockIndex = 0;
		 MessageBlockIndex < PaddedMsgLength/AES_128_BLOCK_LENGTH_BYTES;
		 ++MessageBlockIndex)
	{
		u32 MessageIndexBytes = MessageBlockIndex*AES_128_BLOCK_LENGTH_BYTES;
		AesEncryptBlock(Cipher + MessageIndexBytes, Message + MessageIndexBytes, Key, KeyLength);
	}
}

internal void
AesEcbDecrypt(u8 *Message, u8 *Cipher, u32 MessageLength, u8 *Key, u32 KeyLength)
{
	Stopif((Message == 0) || (Cipher == 0) || (Key == 0), "Null inputs to AesCbcEncrypt");
	Stopif(KeyLength != KEY_LENGTH_BYTES, "Only AES-128 is supported");
	Stopif(MessageLength == 0, "AesEcbDecrypt - Message of length 0");

	u32 PaddedMsgLength = FindPaddedLength(MessageLength);

	for (u32 MessageBlockIndex = 0;
		 MessageBlockIndex < PaddedMsgLength/AES_128_BLOCK_LENGTH_BYTES;
		 ++MessageBlockIndex)
	{
		u32 MessageIndexBytes = MessageBlockIndex*AES_128_BLOCK_LENGTH_BYTES;
		AesDecryptBlock(Message + MessageIndexBytes, Cipher + MessageIndexBytes, AES_128_BLOCK_LENGTH_BYTES,
						Key, KeyLength);
	}
}

internal void
AesCtrMode(u8 *Output, u8 *Input, u32 MessageLength, u8 *Key, u8 *NonceCounter)
{
	Stopif((Output == 0) || (Input == 0) || (Key == 0) || (NonceCounter == 0), "Null input to AesCtrMode");

	u8 EncryptedCounterScratch[AES_128_BLOCK_LENGTH_BYTES];
	for (i32 InputIndex = 0;
		 InputIndex <= ((i32)MessageLength - AES_128_BLOCK_LENGTH_BYTES);
		 InputIndex += AES_128_BLOCK_LENGTH_BYTES)
	{
		AesEncryptBlock(EncryptedCounterScratch, NonceCounter, Key, AES_128_BLOCK_LENGTH_BYTES);
		XorVectorsUnchecked(Output + InputIndex, Input + InputIndex, EncryptedCounterScratch,
							AES_128_BLOCK_LENGTH_BYTES);
		u32 *Counter = (u32 *)(NonceCounter + 8);
		Stopif(*Counter == UINT32_MAX, "Counter overflow in TestCtrMode");
		++*Counter;
	}

	u32 InputLengthMod16 = MessageLength % AES_128_BLOCK_LENGTH_BYTES;
	if (InputLengthMod16)
	{
		AesEncryptBlock(EncryptedCounterScratch, NonceCounter, Key, AES_128_BLOCK_LENGTH_BYTES);
		u8 *LastPartialBlock = Input + (MessageLength - InputLengthMod16);
		XorVectorsUnchecked(LastPartialBlock, LastPartialBlock, EncryptedCounterScratch, InputLengthMod16);
	}
}

#endif // AES_H
