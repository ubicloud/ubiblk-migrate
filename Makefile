CC = gcc
CFLAGS = -Wall -Wextra -std=c99
TARGET = migrate
SOURCE = migrate.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

format:
	clang-format -i *.c

.PHONY: all run clean install format
