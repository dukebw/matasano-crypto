#include "crypt_helper.h"

// TODO(brendan): 128 bits for now -- add 192 and 256 bit versions
#define KEY_LENGTH 4 // NOTE(brendan): 32-bit words
#define BLOCK_SIZE 4
#define STATE_ARRAY_ROW_COUNT 4
#define NUMBER_OF_ROUNDS 10

global_variable uint32 StateArray[STATE_ARRAY_ROW_COUNT][BLOCK_SIZE];

internal void
AesEncrypt(uint8 *Cipher, uint8 *Message, uint32 MessageLength)
{
    Stopif(MessageLength != sizeof(StateArray[0])*STATE_ARRAY_ROW_COUNT*BLOCK_SIZE,
           return,
           "Bad Length");

    for (uint32 MessageIndex = 0;
         MessageIndex < MessageLength;
         ++MessageIndex)
    {
        StateArray[MessageIndex/BLOCK_SIZE][] = ;
    }
}
