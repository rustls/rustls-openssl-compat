CARGO ?= cargo
CARGOFLAGS += --locked

CFLAGS := -Werror -Wall -Wextra -Wpedantic -g $(shell pkg-config --cflags openssl)
PROFILE := debug

ifeq ($(CC), clang)
	CFLAGS += -fsanitize=address -fsanitize=undefined
	LDFLAGS += -fsanitize=address
endif

ifeq ($(PROFILE), release)
	CFLAGS += -O3
	CARGOFLAGS += --release
endif

ifneq (,$(TARGET))
	PROFILE := $(TARGET)/$(PROFILE)
	CARGOFLAGS += --target $(TARGET)
endif

all: target/ciphers target/client target/constants target/$(PROFILE)/libssl.so.3

test: all
	${CARGO} test --locked

integration: all
	${CARGO} test --locked -- --ignored

target:
	mkdir -p $@

target/$(PROFILE)/libssl.so.3: target/$(PROFILE)/libssl.so
	cp -v $^ $@

target/$(PROFILE)/libssl.so: *.rs src/*.rs Cargo.toml
	${CARGO} build $(CARGOFLAGS)

target/%.o: tests/%.c | target
	$(CC) -o $@ -c $< $(CFLAGS)

target/ciphers: target/ciphers.o
	$(CC) -o $@ $^ $(LDFLAGS) $(shell pkg-config --libs openssl)

target/client: target/client.o
	$(CC) -o $@ $^ $(LDFLAGS) $(shell pkg-config --libs openssl)

target/constants: target/constants.o
	$(CC) -o $@ $^ $(LDFLAGS) $(shell pkg-config --libs openssl)

clean:
	rm -rf target

format:
	find src tests \
		-name '*.[c|h]' | \
		xargs clang-format -i

format-check:
	find src tests \
		-name '*.[c|h]' | \
		xargs clang-format --dry-run -Werror -i

.PHONY: all clean test integration format format-check
