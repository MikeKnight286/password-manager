# Makefile

CC = gcc
CFLAGS = -Iinclude -I/mingw64/include -I/mingw64/include/SDL2 -I/mingw64/include/sodium
LDFLAGS = -L/mingw64/lib -lpng -ljpeg -lz -lSDL2 -lSDL2_image -lsodium 
SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)
TARGET = password_manager
UTILS_SRC = src/utils.c
UTILS_OBJ = $(UTILS_SRC:.c=.o)
TEST_LIBS_SRC = src/test_libs.c
TEST_LIBS_OBJ = $(TEST_LIBS_SRC:.c=.o)
TEST_SRC = tests/tests.c
TEST_OBJ = $(TEST_SRC:.c=.o)
TEST_TARGET = run_tests

all: $(TARGET) $(TEST_TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $(TARGET) $(OBJ) $(LDFLAGS)

$(TEST_TARGET): $(TEST_OBJ) $(TEST_LIBS_OBJ)
	$(CC) -o $(TEST_TARGET) $(TEST_OBJ) $(TEST_LIBS_OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f $(OBJ) $(TARGET) $(UTILS_OBJ) $(TEST_LIBS_OBJ) $(TEST_OBJ) $(TEST_TARGET)

.PHONY: clean
