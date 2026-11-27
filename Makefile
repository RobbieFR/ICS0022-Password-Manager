CC      := gcc
TARGET  := password_manager
TESTBIN := tests/test_suite

CFLAGS  := -std=c11 -D_POSIX_C_SOURCE=200809L \
           -Wall -Wextra -Werror -Wformat=2 \
           -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE \
           -Iinclude
LDFLAGS := -pie -Wl,-z,relro,-z,now
LDLIBS  := -lsodium -lsqlite3

LIB_SRCS := src/crypto.c src/db.c src/log.c src/validation.c
SRCS     := src/main.c src/cli.c $(LIB_SRCS)
OBJS     := $(SRCS:.c=.o)

.PHONY: all debug test test-unit test-e2e test-asan test-valgrind clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

debug: CFLAGS := -std=c11 -D_POSIX_C_SOURCE=200809L \
                 -Wall -Wextra -Werror -Wformat=2 \
                 -g -O0 -fsanitize=address,undefined -Iinclude
debug: LDFLAGS := -fsanitize=address,undefined
debug: clean $(TARGET)

$(TESTBIN): tests/test_suite.c $(LIB_SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test-unit: $(TESTBIN)
	./$(TESTBIN)

test-e2e: $(TARGET)
	chmod +x tests/test_cli_e2e.sh
	./tests/test_cli_e2e.sh

test: test-unit test-e2e

test-asan:
	$(CC) -std=c11 -D_POSIX_C_SOURCE=200809L \
	      -Wall -Wextra -Werror -Wformat=2 \
	      -g -O0 -fsanitize=address,undefined -Iinclude \
	      -o $(TESTBIN)_asan tests/test_suite.c $(LIB_SRCS) $(LDLIBS)
	./$(TESTBIN)_asan

test-valgrind:
	$(CC) -std=c11 -D_POSIX_C_SOURCE=200809L \
	      -Wall -Wextra -Werror -Wformat=2 \
	      -g -O0 -Iinclude \
	      -o $(TESTBIN)_vg tests/test_suite.c $(LIB_SRCS) $(LDLIBS)
	valgrind --leak-check=full --track-origins=yes --error-exitcode=1 ./$(TESTBIN)_vg

clean:
	rm -f $(OBJS) $(TARGET) $(TESTBIN) $(TESTBIN)_asan $(TESTBIN)_vg
