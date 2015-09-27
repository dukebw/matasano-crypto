# NOTE(brendan): set P using "export P=program_name" from shell
OBJECTS=
STD_FLAGS=gnu11
MORE_FLAGS=#-DSHA1TEST
CRYPTO_IMPL=../../crypto-grabbag/Implementations
CFLAGS=`pkg-config --cflags glib-2.0` -ggdb3 -std=$(STD_FLAGS) -Wall -Wextra -Werror -O0 \
	   -I$(CRYPTO_IMPL)
LDLIBS=`pkg-config --libs glib-2.0` -lm
CC=gcc
CXX=g++

$(P):$(OBJECTS)

aes_ecb_mode:$(CRYPTO_IMPL)/aes.h
pkcs7_padding_test:$(CRYPTO_IMPL)/aes.h
byte_at_a_time_ecb_decrypt:$(CRYPTO_IMPL)/crypt_helper.h $(CRYPTO_IMPL)/aes.h
