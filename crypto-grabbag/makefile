# NOTE(brendan): set P using "export P=program_name" from shell
HEADERS=
OBJECTS=
LIBS=-L/cygdrive/w/AES/lib_generic_c.lib
INCLUDE=-I/usr/src/openssl-1.0.2a-1.src/openssl-1.0.2a -I/cygdrive/c/bduke/crypto-grabbag\
		-I/cygdrive/w/AES
CFLAGS=`pkg-config --cflags glib-2.0` $(INCLUDE) -ggdb3 -std=gnu11 -Wall\
       -Wextra -Werror -O0
LDLIBS=-L. `pkg-config --libs glib-2.0` `pkg-config --libs openssl` -lm -lgeneric_c
CC=gcc

$(P):$(OBJECTS)
