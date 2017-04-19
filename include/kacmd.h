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
#define KACMD_CALL 0x02


#endif
