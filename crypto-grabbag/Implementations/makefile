# NOTE(brendan): set P using "export P=program_name" from shell
OBJECTS=
STD_FLAGS=c++14#gnu11
MORE_FLAGS=#-DSHA1TEST
CPPFLAGS=`pkg-config --cflags glib-2.0` -I$(HOME)/tech/root/include/ -ggdb3\
		 -std=$(STD_FLAGS) -Wall -Wextra -Werror -O3 -pg $(MORE_FLAGS)
LDLIBS=`pkg-config --libs glib-2.0` -lm
CC=gcc
CXX=g++

$(P):$(OBJECTS)
