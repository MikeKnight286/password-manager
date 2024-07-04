# Makefile

CC = gcc
CFLAGS = -Iinclude -I/mingw64/include
LDFLAGS = -L/mingw64/lib -lpng -ljpeg -lz
SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)
TARGET = password_manager

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $(TARGET) $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: clean
