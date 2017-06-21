#TOOLCHAIN=android-ndk-r12b/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin/aarch64-linux-android-
#ARCHI=arm64
CC=gcc
ifeq ($(KACCESS_DIR),)
   KACCESS_DIR=$(PWD)/..
endif
IDIR=$(KACCESS_DIR)/include
CFLAGS=-std=c11 -fPIC -static -I$(IDIR)
__DEPS=kacmd.h
DEPS=$(patsubst %,$(IDIR)/%,$(_OBJ))

test:  test_kmem.c $(DEPS)
	$(CC) -o $@.elf $(CFLAGS) $<

.PHONY: clean

clean:
	rm -f *.elf
