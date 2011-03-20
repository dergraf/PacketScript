#include <linux/kernel.h>

#define exit(E)         return
#define strtoul		simple_strtoul
#define strcoll		strcmp

#define CHAR_BIT 8
