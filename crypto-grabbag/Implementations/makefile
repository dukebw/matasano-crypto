# NOTE(brendan): set P using "export P=program_name" from shell
OBJECTS=
CPPFLAGS=`pkg-config --cflags glib-2.0` -I$(HOME)/tech/root/include/ -g\
		 -std=c++14 -Wall -Wextra -Werror -O0
LDLIBS=`pkg-config --libs glib-2.0` -lm
CC=gcc
CXX=g++

$(P):$(OBJECTS)
