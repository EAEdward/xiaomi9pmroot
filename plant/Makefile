# cross-compile the payload for the device (aarch64, static musl)
ZIG ?= zig
CC  := $(ZIG) cc -target aarch64-linux-musl -static -O2

all: plant

plant: uaf_plant_v6.c pc98260_rootd.c
	$(CC) -o $@ $^

clean:
	rm -f plant

.PHONY: all clean
