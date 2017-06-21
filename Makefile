ifeq ($(KERNEL_DIR),)
   KERNEL_DIR=../kernels/ubuntu-zesty
endif
KACCESS_DIR=$(PWD)
#TOOLCHAIN=toolchain5.0.2/bin/arm-linux-androideabi-
#TOOLCHAIN=android-ndk-r12b/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin/aarch64-linux-android-
#ARCHI=arm64

obj-m+=kaccess.o
kaccess-objs := src/kamem.o src/kaccess.o src/kacmd.o
ccflags-y=-I$(PWD)/include

all: module test

module:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
test:
	cd test && $(MAKE)

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	$(RM) Module.markers modules.order
	cd test && $(MAKE) clean

install: all
ifndef ROOTFS_DIR
	$(error ROOTFS_DIR undefined)
endif
	cp kaccess.ko $(ROOTFS_DIR)/root/
	cp test/test.elf $(ROOTFS_DIR)/root/

.PHONY: test clean install
#	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules_install
