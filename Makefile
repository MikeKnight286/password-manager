CC = gcc
CFLAGS = -Iinclude -I/mingw64/include -I/mingw64/include/SDL2 -I/mingw64/include/sodium -Ilibs/zxcvbn-c -I/mingw64/include/curl
LDFLAGS = -L/mingw64/lib -Llibs/zxcvbn-c -lpng -ljpeg -lz -lSDL2 -lSDL2_image -lsodium -lzxcvbn -lcrypto -lcurl
TEST_LDFLAGS = -L/mingw64/lib -Llibs/zxcvbn-c -lpng -ljpeg -lz -lSDL2 -lSDL2_image -lsodium -lzxcvbn -lcrypto -Wl,--subsystem,console

# List all source files
SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)
TARGET = password_manager

# Additional object files
UTILS_SRC = src/utils.c
UTILS_OBJ = $(UTILS_SRC:.c=.o)
PROFILES_SRC = src/profiles.c
PROFILES_OBJ = $(PROFILES_SRC:.c=.o)
TEST_LIBS_SRC = src/test_libs.c
TEST_LIBS_OBJ = $(TEST_LIBS_SRC:.c=.o)
TEST_UTILS_SRC = src/test_utils.c
TEST_UTILS_OBJ = $(TEST_UTILS_SRC:.c=.o)
TEST_PROFILES_SRC = src/test_profiles.c
TEST_PROFILES_OBJ = $(TEST_PROFILES_SRC:.c=.o)
TEST_SRC = tests/tests.c
TEST_OBJ = $(TEST_SRC:.c=.o)
TEST_TARGET = run_tests

# Build all targets
all: $(TARGET) $(TEST_TARGET)

# Build the main target
$(TARGET): $(OBJ)
	$(CC) -o $(TARGET) $(OBJ) $(LDFLAGS)

# Build the test target, ensuring all required object files are included
$(TEST_TARGET): $(TEST_OBJ) $(TEST_LIBS_OBJ) $(TEST_UTILS_OBJ) $(TEST_PROFILES_OBJ) $(UTILS_OBJ) $(PROFILES_OBJ)
	$(CC) -o $(TEST_TARGET) $(TEST_OBJ) $(TEST_LIBS_OBJ) $(TEST_UTILS_OBJ) $(TEST_PROFILES_OBJ) $(UTILS_OBJ) $(PROFILES_OBJ) $(TEST_LDFLAGS)

# Compile each .c file to .o file
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

# Clean up the build artifacts
clean:
	rm -f $(OBJ) $(TARGET) $(UTILS_OBJ) $(PROFILES_OBJ) $(TEST_LIBS_OBJ) $(TEST_UTILS_OBJ) $(TEST_PROFILES_OBJ) $(TEST_OBJ) $(TEST_TARGET)

.PHONY: clean
