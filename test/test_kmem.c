#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include "../include/kacmd.h"

#define VREAD 0xffffffff811cff10
//#define VREAD 0xffffffffc00e730f
#define USERTOP 0x7fffffffffffffff
#define TEST 0x12248
#define KERNBOT 0xf000000000000000

int open_file(const char* fname, unsigned int flag)
{
    int fd = open(fname, flag);
    if (fd<0)
    {
        fprintf(stderr, "[E] Failed to open %s\n", fname);
        exit(1);
    }
    return fd;
}

void write_dev(int fd, const char* data, size_t length, unsigned long long address)
{
    printf("[I] Writing to address: %llx size: %lu\n", address, length);
    lseek64(fd, address, SEEK_SET);
    unsigned written = 0;
    int ret;
    do
    {
        ret = write(fd, &data[written], length-written);
        if (ret < 0)
        {
            fprintf(stderr, "[E] Failed to write file\n");
            exit(1);
        }
        written += ret;
    }
    while (written < length);
}

void read_dev(int fd, char* data, size_t length, unsigned long long address)
{
    printf("[I] Reading from address: %llx size: %lu\n", address, length);
    if (address)
    {
        lseek64(fd, address, SEEK_SET);
    }
    unsigned written = 0;
    int ret;
    do
    {
        ret = read(fd, &data[written], length-written);
        if (ret < 0)
        {
            fprintf(stderr, "[E] Failed to read file\n");
            exit(1);
        }
        written += ret;
    }
    while (written < length && ret != 0);
}

int main(int argc, char** argv)
{
    int vmem, pmem, cmd;
    char tmp;
    char reada[45];
    struct kacmd_info_params kip;
    struct kacmd_info_resp kir;
    struct kacmd_call_params kcp;
    kip.cmd = KACMD_INFO;
    

    vmem = open_file("/dev/ka_kmem", O_RDWR|O_LARGEFILE);
    pmem = open_file("/dev/ka_mem", O_RDWR|O_LARGEFILE);
    cmd = open_file("/dev/ka_cmd", O_RDWR|O_LARGEFILE);

    write_dev(cmd, (char*)&kip, sizeof(kip), 0);
    read_dev(cmd, (char*)&kir, sizeof(kir), 0);
    printf("[I] Vpg: %p Ppg: %p Epg: %p\n", kir.pg_vaddress, kir.pg_paddress, kir.exec_paddress);

    read_dev(vmem, reada, 45, (unsigned long long)(kir.pg_vaddress));
    reada[44] = 0;
    printf("[I] Dump vaddr: %p\n", kir.pg_vaddress);
    puts(reada);
    write_dev(vmem, "TEST123", 7, (unsigned long long)(kir.pg_vaddress));
    printf("[I] Written vaddr: %p\n", kir.pg_vaddress);
    /* read_dev(pmem, reada, 45, (unsigned long long)(kir.pg_paddress)); */
    /* reada[44] = 0; */
    /* printf("[I] Dump paddr: %p\n", kir.pg_paddress); */
    /* puts(reada); */

    tmp = 0xc3;
    write_dev(vmem, &tmp, 1, (unsigned long long)(kir.exec_paddress));
    read_dev(vmem, &tmp, 1, (unsigned long long)(kir.exec_paddress));
    printf("[I] Ret written to exec page: %hhx\n", tmp);

    kcp.cmd = KACMD_CALL_SIMPLE;
    kcp.address = (void(*)())kir.exec_paddress;
    // call the page (should just return)
    write_dev(cmd, (char*)&kcp, sizeof(kcp), 0);
    while (1){
        tmp++;
    }

    /* printf("RW to address: %llx\n", address); */
    /* lseek64(fp, address, SEEK_CUR); */
    /* //_llseek(fp, address>>32, address & 0xffffffff, &result, SEEK_SET); */
    /* read(fp, reada, sizeof(reada)); */
    /* printf("Kernel Dump:\n"); */
    /* puts(reada); */
    /* lseek64(fp, address, SEEK_SET); */
    /* //_llseek(fp, address>>32, address & 0xffffffff, &result, SEEK_SET); */
    /* write(fp, data, strlen(data)); */
    /* lseek64(fp, address, SEEK_SET); */
    /* //_llseek(fp, address>>32, address & 0xffffffff, &result, SEEK_SET); */
    /* //read(fp, dump, sizeof(dump)); */
    /* read(fp, reada, sizeof(reada)); */
    /* printf("Kernel Dump:\n"); */
    /* puts(reada); */
    /*  */
    /* fp = open("/dev/ka_mem", O_RDWR|O_LARGEFILE); */
    /* address -= 0xffffffff80000000; */
    /* printf("RW to phys address: %llx\n", address); */
    /* lseek64(fp, address, SEEK_CUR); */
    /* //_llseek(fp, address>>32, address & 0xffffffff, &result, SEEK_SET); */
    /* read(fp, reada, sizeof(reada)); */
    /* printf("Kernel Dump:\n"); */
    /* puts(reada); */
    /* lseek64(fp, address, SEEK_SET); */
    /* //_llseek(fp, address>>32, address & 0xffffffff, &result, SEEK_SET); */
    /* write(fp, data, strlen(data)); */
    /* lseek64(fp, address, SEEK_SET); */
    /* //_llseek(fp, address>>32, address & 0xffffffff, &result, SEEK_SET); */
    /* //read(fp, dump, sizeof(dump)); */
    /* read(fp, reada, sizeof(reada)); */
    /* printf("Kernel Dump:\n"); */
    /* puts(reada); */
    /*  */
    /* return 0; */
    /* for (int i =0; i < 4; i++) */
    /* { */
    /*     printf("\t0x%lx\n", dump[i]); */
    /* } */
    return 0;

}

