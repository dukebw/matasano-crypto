CPPFLAGS=-c `pkg-config --cflags glib-2.0` -I$(HOME)/tech/root/include/ -g\
		-std=c++14 -Wall -Wextra -Werror -O0
LDLIBS=`pkg-config --libs glib-2.0` -lm

CC=g++

SOURCES=break_repeating_key_xor.cpp helper.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=break_repeating_key_xor
# Build directory
BUILD=../build/

all: directories $(SOURCES) $(BUILD)$(EXECUTABLE)
	ctags -R .

$(BUILD)$(EXECUTABLE): $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDLIBS)

.cpp.o:
	$(CC) $(CPPFLAGS) $< -o $@

MKDIR_P=mkdir -p

.PHONY: directories OUT_DIR clean spotless

OUT_DIR=../build/

directories: OUT_DIR

OUT_DIR:
	$(MKDIR_P) $(OUT_DIR)

clean:
	rm -f *.o

spotless:
	rm -f *.o *~ .*~ $(BUILD)$(EXECUTABLE)

break_repeating_key_xor.o:helper.h stopif.h
helper.cpp: stopif.h
