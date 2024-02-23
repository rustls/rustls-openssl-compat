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

all: target/$(PROFILE)/libssl.so.3

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

clean:
	rm -rf target

format:
	find . \
		-name '*.[c|h]' | \
		xargs clang-format -i

format-check:
	find . \
		-name '*.[c|h]' | \
		xargs clang-format --dry-run -Werror -i

.PHONY: all clean test integration format format-check
