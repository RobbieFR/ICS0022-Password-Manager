CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
LIBS = -lsqlite3 -lsodium

SRC = src/main.c src/cli.c src/crypto.c src/db.c
OBJ = $(SRC:.c=.o)
TARGET = passmanager

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(TARGET) database.db