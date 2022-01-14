CC := gcc
CFLAGS :=  -Wall -Werror -g

hello-world: hello-world.c
	$(CC) $(CFLAGS) -o "$@" "$<"

.DEFAULT: build
.PHONY: build
build: hello-world

.PHONY: clean
clean:
	rm -f hello-world
