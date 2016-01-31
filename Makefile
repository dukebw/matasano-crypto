# NOTE(brendan): set P using "export P=program_name" from shell
P=matasano-crypto-challenges/set5/implement_srp
P2=matasano-crypto-challenges/set4/nweb/nweb23

OBJECTS=
STD_FLAGS=gnu11
MORE_FLAGS=#-DSHA1TEST
CRYPTO_IMPL=crypto-grabbag/Implementations
CFLAGS=-ggdb3 -std=$(STD_FLAGS) -Wall -Wextra -Werror -O0 -I$(CRYPTO_IMPL)
LDLIBS=-lm
CC=gcc
CXX=g++

all: $(P) $(P2)

$(P):$(CRYPTO_IMPL)/crypt_helper.h
$(P2):$(CRYPTO_IMPL)/crypt_helper.h
