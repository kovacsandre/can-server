/*
 * candump.c
 *
 * Copyright (c) 2002-2009 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Volkswagen nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * The provided data structures and external interfaces from this code
 * are not restricted to be used by modules with a GPL compatible license.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Send feedback to <linux-can@vger.kernel.org>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <libgen.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <dirent.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <net/if.h>

#include <linux/can.h>
#include <linux/can/raw.h>

#include "lib.h"

/* for hardware timestamps - since Linux 2.6.30 */
#ifndef SO_TIMESTAMPING
#define SO_TIMESTAMPING 37
#endif

/* from #include <linux/net_tstamp.h> - since Linux 2.6.30 */
#define SOF_TIMESTAMPING_SOFTWARE (1<<4)
#define SOF_TIMESTAMPING_RX_SOFTWARE (1<<3)
#define SOF_TIMESTAMPING_RAW_HARDWARE (1<<6)

#define MAXSOCK 5    /* max. number of CAN interfaces given on the cmdline */
#define MAXIFNAMES 30 /* size of receive name index to omit ioctls */
//#define MAXCOL 6      /* number of different colors for colorized output */
#define ANYDEV "any"  /* name of interface to receive from any CAN interface */
#define ANL "\r\n"    /* newline in ASC mode */

#define SILENT_INI 42 /* detect user setting on commandline */
#define SILENT_OFF 0  /* no silent mode */
#define SILENT_ANI 1  /* silent mode with animation */
#define SILENT_ON  2  /* silent mode (completely silent) */

#define SOCK_PATH "/var/run/can-server.sock"
#define max_clients 10
#define STREAM (((quiet) || (log)) ? logfile : stdout)

unsigned char log = 0;
unsigned char quiet = 0;

void _log_print(int pri, const char *fmt, ...)
    __attribute__((format (printf, 2, 3)));

#define log_print(pri, fmt, ...) _log_print(pri, fmt, ##__VA_ARGS__)

static char *cmdlinename[MAXSOCK];
static __u32 dropcnt[MAXSOCK];
static __u32 last_dropcnt[MAXSOCK];
static char devname[MAXIFNAMES][IFNAMSIZ+1];
static int  dindex[MAXIFNAMES];
static int  max_devname_len; /* to prevent frazzled device name output */
const int canfd_on = 1;

#define MAXANI 4
const char anichar[MAXANI] = {'|', '/', '-', '\\'};
const char extra_m_info[4][4] = {"- -", "B -", "- E", "B E"};

extern int optind, opterr, optopt;

static volatile int running = 1;

void print_usage(char *prg)
{
    fprintf(stderr, "\nUsage: %s [options] <CAN interface>+\n", prg);
    fprintf(stderr, "  (use CTRL-C to terminate %s)\n\n", prg);
    fprintf(stderr, "Options: -t <type>   (timestamp: (a)bsolute/(d)elta/(z)ero/(A)bsolute w date)\n");
    fprintf(stderr, "         -H          (read hardware timestamps instead of system timestamps)\n");
    fprintf(stderr, "         -c          (increment color mode level)\n");
    fprintf(stderr, "         -i          (binary output - may exceed 80 chars/line)\n");
    fprintf(stderr, "         -a          (enable additional ASCII output)\n");
    fprintf(stderr, "         -S          (swap byte order in printed CAN data[] - marked with '%c' )\n", SWAP_DELIMITER);
    fprintf(stderr, "         -s <level>  (silent mode - %d: off (default) %d: animation %d: silent)\n", SILENT_OFF, SILENT_ANI, SILENT_ON);
    fprintf(stderr, "         -b <can>    (bridge mode - send received frames to <can>)\n");
    fprintf(stderr, "         -B <can>    (bridge mode - like '-b' with disabled loopback)\n");
    fprintf(stderr, "         -u <usecs>  (delay bridge forwarding by <usecs> microseconds)\n");
    fprintf(stderr, "         -l          (log CAN-frames into file. Sets '-s %d' by default)\n", SILENT_ON);
    fprintf(stderr, "         -L          (use log file format on stdout)\n");
    fprintf(stderr, "         -n <count>  (terminate after receiption of <count> CAN frames)\n");
    fprintf(stderr, "         -r <size>   (set socket receive buffer to <size>)\n");
    fprintf(stderr, "         -D          (Don't exit if a \"detected\" can device goes down.\n");
    fprintf(stderr, "         -d          (monitor dropped CAN frames)\n");
    fprintf(stderr, "         -e          (dump CAN error frames in human-readable format)\n");
    fprintf(stderr, "         -x          (NEED FOR UNIX SOCKETS!!! print extra message infos, rx/tx brs esi)\n");
    fprintf(stderr, "         -T <msecs>  (terminate after <msecs> without any reception)\n");
    fprintf(stderr, "         -q          (Run in daemon mode. Sets '-l' by default.))\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Up to %d CAN interfaces with optional filter sets can be specified\n", MAXSOCK);
    fprintf(stderr, "on the commandline in the form: <ifname>[,filter]*\n");
    fprintf(stderr, "\nComma separated filters can be specified for each given CAN interface:\n");
    fprintf(stderr, " <can_id>:<can_mask> (matches when <received_can_id> & mask == can_id & mask)\n");
    fprintf(stderr, " <can_id>~<can_mask> (matches when <received_can_id> & mask != can_id & mask)\n");
    fprintf(stderr, " #<error_mask>       (set error frame filter, see include/linux/can/error.h)\n");
    fprintf(stderr, " [j|J]               (join the given CAN filters - logical AND semantic)\n");
    fprintf(stderr, "\nCAN IDs, masks and data content are given and expected in hexadecimal values.\n");
    fprintf(stderr, "When can_id and can_mask are both 8 digits, they are assumed to be 29 bit EFF.\n");
    fprintf(stderr, "Without any given filter all data frames are received ('0:0' default filter).\n");
    fprintf(stderr, "\nUse interface name '%s' to receive from all CAN interfaces.\n", ANYDEV);
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "%s -c -c -ta can0,123:7FF,400:700,#000000FF can2,400~7F0 can3 can8\n", prg);
    fprintf(stderr, "%s -l any,0~0,#FFFFFFFF    (log only error frames but no(!) data frames)\n", prg);
    fprintf(stderr, "%s -l any,0:0,#FFFFFFFF    (log error frames and also all data frames)\n", prg);
    fprintf(stderr, "%s vcan2,92345678:DFFFFFFF (match only for extended CAN ID 12345678)\n", prg);
    fprintf(stderr, "%s vcan2,123:7FF (matches CAN ID 123 - including EFF and RTR frames)\n", prg);
    fprintf(stderr, "%s vcan2,123:C00007FF (matches CAN ID 123 - only SFF and non-RTR frames)\n", prg);
    fprintf(stderr, "\n");
}

void sigterm(int signo)
{
    running = 0;
}

void
_log_print(int pri, const char *fmt, ...)
{
    va_list arg;
    va_start(arg, fmt);

    if (log || quiet) {
        vsyslog(pri, fmt, arg);
    }
    else {
        vfprintf(stderr, fmt, arg);
        fprintf(stderr, "\n");
    }

    va_end(arg);
}

int idx2dindex(int ifidx, int socket) {

    int i;
    struct ifreq ifr;

    for (i=0; i < MAXIFNAMES; i++) {
        if (dindex[i] == ifidx)
            return i;
    }

    /* create new interface index cache entry */

    /* remove index cache zombies first */
    for (i=0; i < MAXIFNAMES; i++) {
        if (dindex[i]) {
            ifr.ifr_ifindex = dindex[i];
            if (ioctl(socket, SIOCGIFNAME, &ifr) < 0)
                dindex[i] = 0;
        }
    }

    for (i=0; i < MAXIFNAMES; i++)
        if (!dindex[i]) /* free entry */
            break;

    if (i == MAXIFNAMES) {
        log_print(LOG_CRIT, "Interface index cache only supports %d interfaces.",
               MAXIFNAMES);
        exit(1);
    }

    dindex[i] = ifidx;

    ifr.ifr_ifindex = ifidx;
    if (ioctl(socket, SIOCGIFNAME, &ifr) < 0)
        log_print(LOG_ERR, "SIOCGIFNAME: %s", strerror(errno));

    if (max_devname_len < strlen(ifr.ifr_name))
        max_devname_len = strlen(ifr.ifr_name);

    strcpy(devname[i], ifr.ifr_name);

#ifdef DEBUG
    log_print(LOG_DEBUG, "new index %d (%s)\n", i, devname[i]);
#endif

    return i;
}

int main(int argc, char **argv)
{
    fd_set rdfs;
    int s[MAXSOCK];
    int bridge = 0;
    useconds_t bridge_delay = 0;
    unsigned char timestamp = 0;
    unsigned char hwtimestamp = 0;
    unsigned char down_causes_exit = 1;
    unsigned char dropmonitor = 0;
    unsigned char extra_msg_info = 0;
    unsigned char silent = SILENT_INI;
    //unsigned char silentani = 0;
    unsigned char color = 0;
    unsigned char view = 0;
    unsigned char logfrmt = 0;
    int count = 0;
    int rcvbuf_size = 0;
    int opt, ret;
    int currmax, numfilter;
    int join_filter;
    char *ptr, *nptr;
    struct sockaddr_can addr;
    char ctrlmsg[CMSG_SPACE(sizeof(struct timeval) + 3*sizeof(struct timespec) + sizeof(__u32))];
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct can_filter *rfilter;
    can_err_mask_t err_mask;
    struct canfd_frame frame;
    int nbytes, i, maxdlen;
    struct ifreq ifr;
    struct timeval tv, last_tv;
    struct timeval timeout, timeout_config = { 0, 0 }, *timeout_current = NULL;
    FILE *logfile = NULL;

    /* Variables for unix sockets */
    int client_socket[max_clients], master_socket,
        new_socket, sd, max_sd, len;
    socklen_t t;
    struct sockaddr_un local, remote;

    signal(SIGTERM, sigterm);
    signal(SIGHUP, sigterm);
    signal(SIGINT, sigterm);

    last_tv.tv_sec  = 0;
    last_tv.tv_usec = 0;

    while ((opt = getopt(argc, argv, "t:HciaSs:b:B:u:lDdxLn:r:heT:q?")) != -1) {
        switch (opt) {
        case 't':
            timestamp = optarg[0];
            if ((timestamp != 'a') && (timestamp != 'A') &&
                (timestamp != 'd') && (timestamp != 'z')) {
                fprintf(stderr, "%s: unknown timestamp mode '%c' - ignored\n",
                       basename(argv[0]), optarg[0]);
                timestamp = 0;
            }
            break;

        case 'H':
            hwtimestamp = 1;
            break;

        case 'c':
            color++;
            break;

        case 'i':
            view |= CANLIB_VIEW_BINARY;
            break;

        case 'a':
            view |= CANLIB_VIEW_ASCII;
            break;

        case 'S':
            view |= CANLIB_VIEW_SWAP;
            break;

        case 'e':
            view |= CANLIB_VIEW_ERROR;
            break;

        case 's':
            silent = atoi(optarg);
            if (silent > SILENT_ON) {
                print_usage(basename(argv[0]));
                exit(1);
            }
            break;

        case 'b':
        case 'B':
            if (strlen(optarg) >= IFNAMSIZ) {
                fprintf(stderr, "Name of CAN device '%s' is too long!\n\n", optarg);
                return 1;
            } else {
                bridge = socket(PF_CAN, SOCK_RAW, CAN_RAW);
                if (bridge < 0) {
                    perror("bridge socket");
                    return 1;
                }
                addr.can_family = AF_CAN;
                strcpy(ifr.ifr_name, optarg);
                if (ioctl(bridge, SIOCGIFINDEX, &ifr) < 0)
                    perror("SIOCGIFINDEX");
                addr.can_ifindex = ifr.ifr_ifindex;

                if (!addr.can_ifindex) {
                    perror("invalid bridge interface");
                    return 1;
                }

                /* disable default receive filter on this write-only RAW socket */
                setsockopt(bridge, SOL_CAN_RAW, CAN_RAW_FILTER, NULL, 0);

                if (opt == 'B') {
                    const int loopback = 0;

                    setsockopt(bridge, SOL_CAN_RAW, CAN_RAW_LOOPBACK,
                           &loopback, sizeof(loopback));
                }

                if (bind(bridge, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                    perror("bridge bind");
                    return 1;
                }
            }
            break;

        case 'u':
            bridge_delay = (useconds_t)strtoul(optarg, (char **)NULL, 10);
            break;

        case 'l':
            log = 1;
            break;

        case 'D':
            down_causes_exit = 0;
            break;

        case 'd':
            dropmonitor = 1;
            break;

        case 'x':
            extra_msg_info = 1;
            break;

        case 'L':
            logfrmt = 1;
            break;

        case 'n':
            count = atoi(optarg);
            if (count < 1) {
                print_usage(basename(argv[0]));
                exit(1);
            }
            break;

        case 'r':
            rcvbuf_size = atoi(optarg);
            if (rcvbuf_size < 1) {
                print_usage(basename(argv[0]));
                exit(1);
            }
            break;

        case 'T':
            errno = 0;
            timeout_config.tv_usec = strtol(optarg, NULL, 0);
            if (errno != 0) {
                print_usage(basename(argv[0]));
                exit(1);
            }
            timeout_config.tv_sec = timeout_config.tv_usec / 1000;
            timeout_config.tv_usec = (timeout_config.tv_usec % 1000) * 1000;
            timeout_current = &timeout;
            break;

        case 'q':
            quiet = 1;
            log = 1;
            break;
        default:
            print_usage(basename(argv[0]));
            exit(1);
            break;
        }
    }

    if (optind == argc) {
        print_usage(basename(argv[0]));
        exit(0);
    }

    if (quiet) {
        openlog("can-server", LOG_CONS | LOG_PID, LOG_USER);
        syslog(LOG_INFO, "Entering can-server daemon...");

        if (daemon(0, 0) < 0) {
            syslog(LOG_CRIT, "daemon(): %s", strerror(errno));
            return -2;
        }
    }

    if (logfrmt && view) {
        log_print(LOG_CRIT, "Log file format selected: Please disable ASCII/BINARY/SWAP options!");
        exit(0);
    }

    if (silent == SILENT_INI) {
        if (log) {
            silent = SILENT_ON; /* disable output on stdout */
        } else
            silent = SILENT_OFF; /* default output */
    }

    currmax = argc - optind; /* find real number of CAN devices */

    if (currmax > MAXSOCK) {
        log_print(LOG_CRIT, "More than %d CAN devices given on commandline!", MAXSOCK);
        return 1;
    }

    for (i=0; i < currmax; i++) {

        ptr = argv[optind+i];
        nptr = strchr(ptr, ',');

#ifdef DEBUG
        log_print(LOG_DEBUG, "open %d '%s'.\n", i, ptr);
#endif

        s[i] = socket(PF_CAN, SOCK_RAW, CAN_RAW);
        if (s[i] < 0) {
            log_print(LOG_CRIT, "socket(): %s", strerror(errno));
            return 1;
        }

        cmdlinename[i] = ptr; /* save pointer to cmdline name of this socket */

        if (nptr)
            nbytes = nptr - ptr;  /* interface name is up the first ',' */
        else
            nbytes = strlen(ptr); /* no ',' found => no filter definitions */

        if (nbytes >= IFNAMSIZ) {
            log_print(LOG_CRIT, "name of CAN device '%s' is too long!", ptr);
            return 1;
        }

        if (nbytes > max_devname_len)
            max_devname_len = nbytes; /* for nice printing */

        addr.can_family = AF_CAN;

        memset(&ifr.ifr_name, 0, sizeof(ifr.ifr_name));
        strncpy(ifr.ifr_name, ptr, nbytes);

#ifdef DEBUG
        log_print(LOG_DEBUG, "using interface name '%s'.\n", ifr.ifr_name);
#endif

        if (strcmp(ANYDEV, ifr.ifr_name)) {
            if (ioctl(s[i], SIOCGIFINDEX, &ifr) < 0) {
                log_print(LOG_CRIT, "SIOCGIFINDEX: %s", strerror(errno));
                exit(1);
            }
            addr.can_ifindex = ifr.ifr_ifindex;
        } else
            addr.can_ifindex = 0; /* any can interface */

        if (nptr) {

            /* found a ',' after the interface name => check for filters */

            /* determine number of filters to alloc the filter space */
            numfilter = 0;
            ptr = nptr;
            while (ptr) {
                numfilter++;
                ptr++; /* hop behind the ',' */
                ptr = strchr(ptr, ','); /* exit condition */
            }

            rfilter = malloc(sizeof(struct can_filter) * numfilter);
            if (!rfilter) {
                log_print(LOG_CRIT, "Failed to create filter space!");
                return 1;
            }

            numfilter = 0;
            err_mask = 0;
            join_filter = 0;

            while (nptr) {

                ptr = nptr+1; /* hop behind the ',' */
                nptr = strchr(ptr, ','); /* update exit condition */

                if (sscanf(ptr, "%x:%x",
                       &rfilter[numfilter].can_id,
                       &rfilter[numfilter].can_mask) == 2) {
                     rfilter[numfilter].can_mask &= ~CAN_ERR_FLAG;
                    numfilter++;
                } else if (sscanf(ptr, "%x~%x",
                          &rfilter[numfilter].can_id,
                          &rfilter[numfilter].can_mask) == 2) {
                     rfilter[numfilter].can_id |= CAN_INV_FILTER;
                     rfilter[numfilter].can_mask &= ~CAN_ERR_FLAG;
                    numfilter++;
                } else if (*ptr == 'j' || *ptr == 'J') {
                    join_filter = 1;
                } else if (sscanf(ptr, "#%x", &err_mask) != 1) {
                    log_print(LOG_CRIT, "Error in filter option parsing: '%s'", ptr);
                    return 1;
                }
            }

            if (err_mask)
                setsockopt(s[i], SOL_CAN_RAW, CAN_RAW_ERR_FILTER,
                       &err_mask, sizeof(err_mask));

            if (join_filter && setsockopt(s[i], SOL_CAN_RAW, CAN_RAW_JOIN_FILTERS,
                              &join_filter, sizeof(join_filter)) < 0) {
                log_print(LOG_CRIT, "setsockopt CAN_RAW_JOIN_FILTERS not supported by your Linux Kernel: %s", strerror(errno));
                return 1;
            }

            if (numfilter)
                setsockopt(s[i], SOL_CAN_RAW, CAN_RAW_FILTER,
                       rfilter, numfilter * sizeof(struct can_filter));

            free(rfilter);

        } /* if (nptr) */

        /* try to switch the socket into CAN FD mode */
        setsockopt(s[i], SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &canfd_on, sizeof(canfd_on));

        if (rcvbuf_size) {

            int curr_rcvbuf_size;
            socklen_t curr_rcvbuf_size_len = sizeof(curr_rcvbuf_size);

            /* try SO_RCVBUFFORCE first, if we run with CAP_NET_ADMIN */
            if (setsockopt(s[i], SOL_SOCKET, SO_RCVBUFFORCE,
                       &rcvbuf_size, sizeof(rcvbuf_size)) < 0) {
#ifdef DEBUG
                log_print(LOG_DEBUG, "SO_RCVBUFFORCE failed so try SO_RCVBUF ...\n");
#endif
                if (setsockopt(s[i], SOL_SOCKET, SO_RCVBUF,
                           &rcvbuf_size, sizeof(rcvbuf_size)) < 0) {
                    log_print(LOG_CRIT, "setsockopt SO_RCVBUF: %s", strerror(errno));
                    return 1;
                }

                if (getsockopt(s[i], SOL_SOCKET, SO_RCVBUF,
                           &curr_rcvbuf_size, &curr_rcvbuf_size_len) < 0) {
                    log_print(LOG_CRIT, "getsockopt SO_RCVBUF: %s", strerror(errno));
                    return 1;
                }

                /* Only print a warning the first time we detect the adjustment */
                /* n.b.: The wanted size is doubled in Linux in net/sore/sock.c */
                if (!i && curr_rcvbuf_size < rcvbuf_size*2)
                    log_print(LOG_WARNING, "The socket receive buffer size was "
                        "adjusted due to /proc/sys/net/core/rmem_max.");
            }
        }

        if (timestamp || log || logfrmt) {

            if (hwtimestamp) {
                const int timestamping_flags = (SOF_TIMESTAMPING_SOFTWARE | \
                                SOF_TIMESTAMPING_RX_SOFTWARE | \
                                SOF_TIMESTAMPING_RAW_HARDWARE);

                if (setsockopt(s[i], SOL_SOCKET, SO_TIMESTAMPING,
                        &timestamping_flags, sizeof(timestamping_flags)) < 0) {
                    log_print(LOG_CRIT, "setsockopt SO_TIMESTAMPING is not supported by your Linux kernel: %s", strerror(errno));
                    return 1;
                }
            } else {
                const int timestamp_on = 1;

                if (setsockopt(s[i], SOL_SOCKET, SO_TIMESTAMP,
                           &timestamp_on, sizeof(timestamp_on)) < 0) {
                    log_print(LOG_CRIT, "setsockopt SO_TIMESTAMP: %s", strerror(errno));
                    return 1;
                }
            }
        }

        if (dropmonitor) {

            const int dropmonitor_on = 1;

            if (setsockopt(s[i], SOL_SOCKET, SO_RXQ_OVFL,
                       &dropmonitor_on, sizeof(dropmonitor_on)) < 0) {
                log_print(LOG_CRIT, "setsockopt SO_RXQ_OVFL not supported by your Linux Kernel: %s", strerror(errno));
                return 1;
            }
        }

        if (bind(s[i], (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            log_print(LOG_CRIT, "bind(): %s", strerror(errno));
            return 1;
        }
    }

    if (log) {
        time_t currtime;
        struct tm now;
        char fname[sizeof("/var/log/can-server/can-server-2006-11-20_20:20:26.log")+1];

        DIR* dir = opendir("/var/log/can-server");
        if (dir) {
            /* Directory exists. */
            closedir(dir);
        }
        else if (ENOENT == errno) {
            /* Directory does not exist. Create with 775 */
            int status = mkdir("/var/log/can-server", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
            if (status < 0) {
                log_print(LOG_CRIT, "mkdir(): %s", strerror(errno));
                return -1;
            }
        }
        else {
            /* opendir() failed for some other reason. */
            log_print(LOG_CRIT, "opendir(): %s", strerror(errno));
            return -1;
        }

        if (time(&currtime) == (time_t)-1) {
            log_print(LOG_CRIT, "time(): %s", strerror(errno));
            return 1;
        }

        localtime_r(&currtime, &now);

        sprintf(fname, "/var/log/can-server/can-server-%04d-%02d-%02d_%02d:%02d:%02d.log",
            now.tm_year + 1900,
            now.tm_mon + 1,
            now.tm_mday,
            now.tm_hour,
            now.tm_min,
            now.tm_sec);

        logfile = fopen(fname, "w");
        if (!logfile) {
            log_print(LOG_CRIT, "fopen(): %s", strerror(errno));
            return 1;
        }
    }

    /* these settings are static and can be held out of the hot path */
    iov.iov_base = &frame;
    msg.msg_name = &addr;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &ctrlmsg;

    /* Init unix sockets */
    for (i = 0; i < max_clients; i++)
        client_socket[i] = 0;

    /* Master socket is the receiver for the incoming connections */
    if ((master_socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        log_print(LOG_CRIT, "socket(): %s", strerror(errno));
        exit(1);
    }

    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, SOCK_PATH);
    unlink(local.sun_path);
    len = strlen(local.sun_path) + sizeof(local.sun_family);
    if (bind(master_socket, (struct sockaddr *)&local, len) == -1) {
        log_print(LOG_CRIT, "bind(): %s", strerror(errno));
        exit(1);
    }

    if (listen(master_socket, 5) == -1) {
        log_print(LOG_CRIT, "listen(): %s", strerror(errno));
        exit(1);
    }

    t = sizeof(remote);

    syslog(LOG_INFO, "Init success!");

    while (running) {

        FD_ZERO(&rdfs);
        for (i=0; i<currmax; i++)
            FD_SET(s[i], &rdfs);

        FD_SET(master_socket, &rdfs);
        max_sd = master_socket;

        /* add child sockets to set */
        for (i = 0; i < max_clients; i++) {
            sd = client_socket[i];

            /* if valid socket descriptor then add to read list */
            if(sd > 0)
                FD_SET(sd , &rdfs);

            /* highest file descriptor number, need it for the select function */
            if(sd > max_sd)
                max_sd = sd;
        }

        if (timeout_current)
            *timeout_current = timeout_config;

        if ((ret = select(max_sd + 1, &rdfs, NULL, NULL, timeout_current)) <= 0) {
            //perror("select");
            running = 0;
            continue;
        }

        for (i=0; i<currmax; i++) {  /* check all CAN RAW sockets */

            if (FD_ISSET(s[i], &rdfs)) {

                int idx;

                /* these settings may be modified by recvmsg() */
                iov.iov_len = sizeof(frame);
                msg.msg_namelen = sizeof(addr);
                msg.msg_controllen = sizeof(ctrlmsg);
                msg.msg_flags = 0;

                nbytes = recvmsg(s[i], &msg, 0);
                idx = idx2dindex(addr.can_ifindex, s[i]);

                if (nbytes < 0) {
                    if ((errno == ENETDOWN) && !down_causes_exit) {
                        log_print(LOG_ERR, "%s: interface down", devname[idx]);
                        continue;
                    }
                    log_print(LOG_CRIT, "recvmsg(): %s", strerror(errno));
                    return 1;
                }

                if ((size_t)nbytes == CAN_MTU)
                    maxdlen = CAN_MAX_DLEN;
                else if ((size_t)nbytes == CANFD_MTU)
                    maxdlen = CANFD_MAX_DLEN;
                else {
                    log_print(LOG_CRIT, "read: incomplete CAN frame");
                    return 1;
                }

                if (count && (--count == 0))
                    running = 0;

                if (bridge) {
                    if (bridge_delay)
                        usleep(bridge_delay);

                    nbytes = write(bridge, &frame, nbytes);
                    if (nbytes < 0) {
                        log_print(LOG_CRIT, "bridge write(): %s", strerror(errno));
                        return 1;
                    } else if ((size_t)nbytes != CAN_MTU && (size_t)nbytes != CANFD_MTU) {
                        log_print(LOG_CRIT, "bridge write: incomplete CAN frame");
                        return 1;
                    }
                }

                for (cmsg = CMSG_FIRSTHDR(&msg);
                     cmsg && (cmsg->cmsg_level == SOL_SOCKET);
                     cmsg = CMSG_NXTHDR(&msg,cmsg)) {
                    if (cmsg->cmsg_type == SO_TIMESTAMP) {
                        memcpy(&tv, CMSG_DATA(cmsg), sizeof(tv));
                    } else if (cmsg->cmsg_type == SO_TIMESTAMPING) {

                        struct timespec *stamp = (struct timespec *)CMSG_DATA(cmsg);

                        /*
                         * stamp[0] is the software timestamp
                         * stamp[1] is deprecated
                         * stamp[2] is the raw hardware timestamp
                         * See chapter 2.1.2 Receive timestamps in
                         * linux/Documentation/networking/timestamping.txt
                         */
                        tv.tv_sec = stamp[2].tv_sec;
                        tv.tv_usec = stamp[2].tv_nsec/1000;
                    } else if (cmsg->cmsg_type == SO_RXQ_OVFL)
                        memcpy(&dropcnt[i], CMSG_DATA(cmsg), sizeof(__u32));
                }

                /* check for (unlikely) dropped frames on this specific socket */
                if (dropcnt[i] != last_dropcnt[i]) {

                    __u32 frames = dropcnt[i] - last_dropcnt[i];

                    if (silent != SILENT_ON)
                        printf("DROPCOUNT: dropped %d CAN frame%s on '%s' socket (total drops %d)",
                               frames, (frames > 1)?"s":"", devname[idx], dropcnt[i]);

                    if (log)
                        log_print(LOG_ERR, "DROPCOUNT: dropped %d CAN frame%s on '%s' socket (total drops %d)",
                            frames, (frames > 1)?"s":"", devname[idx], dropcnt[i]);

                    last_dropcnt[i] = dropcnt[i];
                }

                /* once we detected a EFF frame indent SFF frames accordingly */
                if (frame.can_id & CAN_EFF_FLAG)
                    view |= CANLIB_VIEW_INDENT_SFF;

                switch (timestamp) {
                    case 'a': /* absolute with timestamp */
                        fprintf(STREAM, "(%010ld.%06ld) ", tv.tv_sec, tv.tv_usec);
                        break;

                    case 'A': /* absolute with date */
                    {
                        struct tm tm;
                        char timestring[25];

                        tm = *localtime(&tv.tv_sec);
                        strftime(timestring, 24, "%Y-%m-%d %H:%M:%S", &tm);
                        fprintf(STREAM, "(%s.%06ld) ", timestring, tv.tv_usec);
                    }
                    break;

                    case 'd': /* delta */
                    case 'z': /* starting with zero */
                    {
                        struct timeval diff;

                        if (last_tv.tv_sec == 0)   /* first init */
                            last_tv = tv;
                        diff.tv_sec  = tv.tv_sec  - last_tv.tv_sec;
                        diff.tv_usec = tv.tv_usec - last_tv.tv_usec;
                        if (diff.tv_usec < 0)
                            diff.tv_sec--, diff.tv_usec += 1000000;
                        if (diff.tv_sec < 0)
                            diff.tv_sec = diff.tv_usec = 0;
                        fprintf(STREAM, "(%03ld.%06ld) ", diff.tv_sec, diff.tv_usec);

                        if (timestamp == 'd')
                            last_tv = tv; /* update for delta calculation */
                    }
                    break;

                    default: /* no timestamp output */
                        break;
                }

                fprintf(STREAM, " %*s", max_devname_len, devname[idx]);

                if (extra_msg_info) {
                    if (msg.msg_flags & MSG_DONTROUTE)
                        fprintf (STREAM, "  TX %s  ", extra_m_info[frame.flags & 3]);
                    else {
                        fprintf (STREAM, "  RX %s  ", extra_m_info[frame.flags & 3]);
                        /* Send data to clients */
                        for (i = 0; i < max_clients; i++) {
                            if (client_socket[i] != 0)
                                send(client_socket[i], &frame, sizeof(struct canfd_frame), 0);
                        }
                    }
                }

                fprint_long_canframe(STREAM, &frame, NULL, view, maxdlen);

                fprintf(STREAM, "\n");
            }
            fflush(STREAM);
        } // for

        if (FD_ISSET(master_socket, &rdfs)) {
            if ((new_socket = accept(master_socket,
                (struct sockaddr *)&remote, (socklen_t*)&t)) < 0) {
                log_print(LOG_CRIT, "accept(): %s", strerror(errno));
                return -1;
            }

            /* Add new socket to array of sockets */
            for (i = 0; i < max_clients; i++) {
                if(client_socket[i] == 0) {
                    client_socket[i] = new_socket;
                    break;
                }
            }
        }
        else {
            for (i = 0; i < max_clients; i++) {
                sd = client_socket[i];
                char buffer[128];

                if (FD_ISSET(sd, &rdfs)) {
                    /* Somebody disconnected */
                    if (read(sd, buffer, 127) == 0) {
                        /* Close the socket and mark as 0 in list for reuse */
                        close(sd);
                        client_socket[i] = 0;
                    }
                }
            }
        }
    }

    for (i=0; i<currmax; i++)
        close(s[i]);

    for (i = 0; i < max_clients; i++) {     // Send to all clients
        if (client_socket[i] != 0)
            close(client_socket[i]);
    }

    close(master_socket);
    unlink(SOCK_PATH);

    if (bridge)
        close(bridge);

    if (log)
        fclose(logfile);

    syslog(LOG_INFO, "Exiting can-server daemon...");
    closelog();

    return 0;
}
