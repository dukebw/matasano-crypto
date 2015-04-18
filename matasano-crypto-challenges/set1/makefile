CFLAGS=-c -Wall -Wextra -std=c++11 -g #-O3
INCLUDE_FLAGS=
LDFLAGS=

CC=g++

SOURCES=detect_single_char_xor.cpp helper.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=detect_single_char_xor
# Build directory
BUILD = ../build/

all: directories $(SOURCES) $(BUILD)$(EXECUTABLE)
	ctags -R .

$(BUILD)$(EXECUTABLE): $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS)

.cpp.o:
	$(CC) $(CFLAGS) $< $(INCLUDE_FLAGS) -o $@

MKDIR_P = mkdir -p

.PHONY: directories OUT_DIR clean spotless

OUT_DIR = ../build/

directories: OUT_DIR

OUT_DIR:
	$(MKDIR_P) $(OUT_DIR)

clean:
	rm -f *.o

spotless:
	rm -f *.o *~ .*~ $(BUILD)$(EXECUTABLE)

detect_single_char_xor.o:helper.h stopif.h
helper.cpp: stopif.h
