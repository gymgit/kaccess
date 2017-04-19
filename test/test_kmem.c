#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#define VREAD 0xffffffff811cff10
//#define VREAD 0xffffffffc00e730f
#define USERTOP 0x7fffffffffffffff
#define TEST 0x12248
#define KERNBOT 0xf000000000000000

int main(int argc, char** argv)
{
    int fp;
    long long unsigned address;
    long unsigned int dump[4];
    char *pEnd;
    char reada[45];
    char data[] = "ABABAB";
    loff_t result;
    memset(dump, 0, sizeof(dump));
    memset(reada, 0, sizeof(reada));
    

    fp = open("/dev/ka_kmem", O_RDWR|O_LARGEFILE);
    if (argc >= 1)
    {
        address = strtoull(argv[1], &pEnd, 16);
    }
    else
    {
        address = VREAD;
    }
    printf("RW to address: %llx\n", address);
    lseek64(fp, address, SEEK_CUR);
    //_llseek(fp, address>>32, address & 0xffffffff, &result, SEEK_SET);
    read(fp, reada, sizeof(reada));
    printf("Kernel Dump:\n");
    puts(reada);
    lseek64(fp, address, SEEK_SET);
    //_llseek(fp, address>>32, address & 0xffffffff, &result, SEEK_SET);
    write(fp, data, strlen(data));
    lseek64(fp, address, SEEK_SET);
    //_llseek(fp, address>>32, address & 0xffffffff, &result, SEEK_SET);
    //read(fp, dump, sizeof(dump));
    read(fp, reada, sizeof(reada));
    printf("Kernel Dump:\n");
    puts(reada);

    fp = open("/dev/ka_mem", O_RDWR|O_LARGEFILE);
    address -= 0xffffffff80000000;
    printf("RW to phys address: %llx\n", address);
    lseek64(fp, address, SEEK_CUR);
    //_llseek(fp, address>>32, address & 0xffffffff, &result, SEEK_SET);
    read(fp, reada, sizeof(reada));
    printf("Kernel Dump:\n");
    puts(reada);
    lseek64(fp, address, SEEK_SET);
    //_llseek(fp, address>>32, address & 0xffffffff, &result, SEEK_SET);
    write(fp, data, strlen(data));
    lseek64(fp, address, SEEK_SET);
    //_llseek(fp, address>>32, address & 0xffffffff, &result, SEEK_SET);
    //read(fp, dump, sizeof(dump));
    read(fp, reada, sizeof(reada));
    printf("Kernel Dump:\n");
    puts(reada);

    return 0;
    for (int i =0; i < 4; i++)
    {
        printf("\t0x%lx\n", dump[i]);
    }
    return 0;

}

