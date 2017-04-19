#ifndef KERNEL_ACCESS_MODULE_H
#define KERNEL_ACCESS_MODULE_H

#include <linux/device.h>
extern int majorNum;
extern struct class* kmemClass;
extern struct device* tmpDev;

extern char playground[];
extern char* execplay;

#endif
