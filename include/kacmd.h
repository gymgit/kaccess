#ifndef KERNAL_ACCESS_MODULE_KACMD_H
#define KERNAL_ACCESS_MODULE_KACMD_H

// Kernel specific stuff
#ifdef MODULE
extern const struct file_operations cmd_fops;
struct cmd_result {
    unsigned char last_cmd;
    unsigned char ready;
    size_t pos;
    size_t size;
    char* resptr;
};
#endif

// Define commands

#define KACMD_JUMP_TO 0x01
#define KACMD_CALL_SIMPLE 0x02
#define KACMD_CALL_COMPLEX 0x03 //TODO set up registers

#define KACMD_KMALLOC 0x04
#define KACMD_KFREE 0x05

#define KACMD_INFO 0x06
// TODO kmalloc allocations
// kfree
// change page protection flags
// get kernel syms
// get Kacces info - exec page location...

#pragma pack(push, 1)
// Command structures
struct kacmd_jump_params{
    unsigned char cmd;
    void* address;
};
struct kacmd_call_params{
    unsigned char cmd;
    void (*address)(void);
};

struct kacmd_kmalloc_params{
    unsigned char cmd;
    unsigned int flag;
    unsigned long size;
};

struct kacmd_kfree_params{
    unsigned char cmd;
    void* address;
};

struct kacmd_info_params{
    unsigned char cmd;
};
// Response structures
struct kacmd_kmalloc_resp{
    unsigned char size;
    void* address;
};

struct kacmd_info_resp{
    void* pg_vaddress;
    void* pg_paddress;
    void* exec_paddress;
};

#pragma pack(pop)
#endif
