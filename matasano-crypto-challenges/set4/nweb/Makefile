# NOTE(brendan): set P using "export P=program_name" from shell
P=nweb23

OBJECTS=
STD_FLAGS=gnu11
MORE_FLAGS=#-DSHA1TEST
CRYPTO_IMPL=../../../crypto-grabbag/Implementations
CFLAGS=`pkg-config --cflags glib-2.0` -ggdb3 -std=$(STD_FLAGS) -Wall -Wextra -Werror -O0 \
	   -I$(CRYPTO_IMPL)
LDLIBS=`pkg-config --libs glib-2.0` -lm
CC=gcc
CXX=g++

$(P):$(OBJECTS)

cbc_padding_oracle:$(CRYPTO_IMPL)/crypt_helper.h $(CRYPTO_IMPL)/aes.h
break_fixed_nonce_ctr_statistically:$(CRYPTO_IMPL)/crypt_helper.h $(CRYPTO_IMPL)/aes.h
sha1_keyed_mac:$(CRYPTO_IMPL)/crypt_helper.h $(CRYPTO_IMPL)/sha.h
