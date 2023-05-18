CC := gcc
CFLAGS :=  -Wall -Werror -g

blddir/bin/hello-world: blddir/obj/intermediate.obj blddir/obj/t.obj blddir/bin
	cd blddir/bin;	$(CC) $(CFLAGS) -o hello-world ../obj/intermediate.obj ../obj/t.obj

blddir/obj/intermediate.obj: hello-world.c blddir/obj headers/target.h
	cd blddir/obj; $(CC) $(CFLAGS) -c -I../../headers -o intermediate.obj ../../"$<"

blddir/obj/t.obj: target.c blddir/obj headers/target.h
	cd blddir/obj; $(CC) $(CFLAGS) -c -o t.obj -I ../../headers ../../"$<"

blddir/bin:
	mkdir -p $@
blddir/obj:
	mkdir -p $@

.DEFAULT: build
.PHONY: build
build: hello-world

.PHONY: clean
clean:
	rm -rf blddir
