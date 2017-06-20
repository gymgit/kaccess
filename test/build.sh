#../../../toolchain5.0.2/bin/arm-linux-androideabi-gcc -std=c11 -fPIE -pie test_kmem.c -o test_arm
gcc -std=c11 -fPIE -pie test_kmem.c -static -o test.elf
