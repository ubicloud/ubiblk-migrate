CC = gcc
CFLAGS = -Wall -Wextra -std=c99
TARGET = migrate
SOURCE = migrate.c
LIBS = -lssl -lcrypto -lyaml

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

clean:
	rm -f $(TARGET)

format:
	clang-format -i *.c

.PHONY: all run clean install format
