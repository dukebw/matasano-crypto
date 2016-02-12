# NOTE(brendan): set P using "export P=program_name" from shell
P=matasano-crypto-challenges/set5/little_endian_bignum_64bit_to_big_endian
P2=matasano-crypto-challenges/set5/break_srp_zero_key
P3=matasano-crypto-challenges/set5/dh_negotiated_groups_malicious_g_param
P4=matasano-crypto-challenges/set5/implement_diffie_hellman
P5=matasano-crypto-challenges/set5/implement_srp
P6=matasano-crypto-challenges/set5/mitm_key_fixing_attack_dh
P7=matasano-crypto-challenges/set5/offline_dictionary_attack_simplified_srp
P8=matasano-crypto-challenges/set4/nweb/nweb23

OBJECTS=
STD_FLAGS=gnu11
MORE_FLAGS=#-DSHA1TEST
CRYPTO_IMPL=crypto-grabbag/Implementations
SLRE=slre
CFLAGS=-ggdb3 -std=$(STD_FLAGS) -Wall -Wextra -Werror -O2 -I$(CRYPTO_IMPL) -I$(SLRE)
LDLIBS=-lm
CC=gcc
CXX=g++

all: $(P) $(P2) $(P3) $(P4) $(P5) $(P6) $(P7) $(P8)

$(P):$(CRYPTO_IMPL)/crypt_helper.h
$(P2):$(CRYPTO_IMPL)/crypt_helper.h
$(P3):$(CRYPTO_IMPL)/crypt_helper.h
$(P4):$(CRYPTO_IMPL)/crypt_helper.h
$(P5):$(CRYPTO_IMPL)/crypt_helper.h
$(P6):$(CRYPTO_IMPL)/crypt_helper.h
$(P7):$(CRYPTO_IMPL)/crypt_helper.h
$(P8):$(CRYPTO_IMPL)/crypt_helper.h
