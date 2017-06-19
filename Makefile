KERNEL_DIR=$(HOME)/ubuntu-zesty
#TOOLCHAIN=toolchain5.0.2/bin/arm-linux-androideabi-
#TOOLCHAIN=android-ndk-r12b/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin/aarch64-linux-android-
#ARCHI=arm64

obj-m+=kaccess.o
kaccess-objs := src/kamem.o src/kaccess.o src/kacmd.o
ccflags-y=-I$(PWD)/include

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	$(RM) Module.markers modules.order
copy:
	scp -r $(HOME)/kaccess/* gym@192.168.111.1:/home/gym/kaccess/
#install:
#	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules_install
