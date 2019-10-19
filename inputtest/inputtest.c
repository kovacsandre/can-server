#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <libgen.h>
#include <time.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <net/if.h>
#include <sys/un.h>
#include <poll.h>

#include <linux/can.h>

#define TEST_CYCLE_NUM 10000
#define SOCK_PATH "/var/run/can-server.sock"

void
calc_time_diff(const struct timespec *lo,
	           const struct timespec *hi,
	           struct timespec *diff)
{
    diff->tv_sec = hi->tv_sec - lo->tv_sec;
    diff->tv_nsec = hi->tv_nsec - lo->tv_nsec;
    if (diff->tv_nsec < 0) {
	       diff->tv_sec--;
	       diff->tv_nsec += 1000000000;
    }
}

int
main(int argc, char **argv)
{
    int family = PF_CAN, type = SOCK_RAW, proto = CAN_RAW;
    struct sockaddr_can addr;
    struct ifreq ifr;
    struct can_frame frame;
    struct canfd_frame inframe;
    struct timespec start_time, end_time, elapsed_time, prg_start_time,
           prg_end_time, prg_running;
    struct timespec worst_cycle = {.tv_sec = 0, .tv_nsec = 0};
    struct timespec best_cycle = {.tv_sec = 1e6, .tv_nsec = 1e9};
    int i;
    unsigned char v;
    unsigned long int cnt = 0, worst_num, best_num;
    unsigned long long int cycle_times = 0;
    int c, s, t, len;
    struct sockaddr_un remote;

    /* Logging the stdout to file */
    if(dup2(fileno(popen("tee inputtest.log", "w")), STDOUT_FILENO) < 0) {
        perror("couldn't redirect output");
        return 1;
    }

    FILE *out, *in;

    out = fopen("out.num", "w");
    in = fopen("in.num", "w");

    if (out == NULL || in == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    srand(time(NULL));

    if ((c = socket(family, type, proto)) < 0) {
        perror("socket");
        return 1;
    }

    addr.can_family = family;
    strcpy(ifr.ifr_name, "can0");
    ioctl(c, SIOCGIFINDEX, &ifr);
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(c, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    printf("Connecting to can-server...\n");

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, SOCK_PATH);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    if (connect(s, (struct sockaddr *)&remote, len) == -1) {
        perror("connect");
        exit(1);
    }
    else
        printf("Success.\n");

    frame.can_id = 0x100;
    /* Output address */
    frame.data[0] = 0x30;
    frame.can_dlc = 2;

    int ret_poll;
    struct pollfd input;

    input.fd = s;
    input.events = POLLIN;

    clock_gettime(CLOCK_MONOTONIC_RAW, &prg_start_time);

    while (cnt < TEST_CYCLE_NUM) {
        /* Generate random number for output */
        unsigned char r = rand() % 8;
        /* Need new number if the previous is the same */
        if (v == r) {
            continue;
        }
        /* Assign the output data */
        frame.data[1] = (0x00 | 1 << r);
        v = r;
        cnt++;

        /* Save the time when write data to the bus */
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        if (write(c, &frame, CAN_MTU) != CAN_MTU) {
            perror("write");
            return 1;
        }
        /* Waiting for incoming data */
        ret_poll = poll(&input, 1, -1);
        if (ret_poll < 0) {
            break;
        }
        /* Receiving the input state */
        if ((t=recv(s, &inframe, sizeof(struct canfd_frame), 0)) <= 0) {
            if (t < 0)
                perror("recv");
            else {
                printf("Server closed connection\n");
                exit(1);
            }
        }

        /* Save the transmission end and calculate elapsed time */
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        calc_time_diff(&start_time, &end_time, &elapsed_time);
        /* Print sent frames */
        fprintf(stdout, "%07lu     %03X: ", cnt, frame.can_id & CAN_EFF_MASK);
        printf("[%d]", frame.can_dlc);
        for (i = 0; i < frame.can_dlc; i++) {
            printf(" %02X", frame.data[i]);
        }
        /* Print transmission time and received frames */
        printf("\n%lu.%06ld    ", (long int)elapsed_time.tv_sec, elapsed_time.tv_nsec / 1000);
        /* The sec range is too big for a successfull transmission */
        assert(elapsed_time.tv_sec == 0);
        cycle_times += elapsed_time.tv_nsec / 1000;
        /* The nanosec owerflows at ~2,1 sec, but it is only occurs when bus off */
        if (elapsed_time.tv_nsec > worst_cycle.tv_nsec) {
            worst_cycle.tv_nsec = elapsed_time.tv_nsec;
            worst_num = cnt;
        }

        if (elapsed_time.tv_nsec < best_cycle.tv_nsec) {
            best_cycle.tv_nsec = elapsed_time.tv_nsec;
            best_num = cnt;
        }

        printf("%03X: ", inframe.can_id & CAN_EFF_MASK);
        if (inframe.can_id & CAN_RTR_FLAG) {
            printf("remote request");
        } else {
            printf("[%d]", inframe.len);
            for (i = 0; i < inframe.len; i++) {
                printf(" %02X", inframe.data[i]);
            }
        }
        printf("\n");

        fprintf(out, "%02x\n", frame.data[1]);
        fprintf(in, "%02x\n", inframe.data[1]);

        fflush(stdout);
    }

    clock_gettime(CLOCK_MONOTONIC_RAW, &prg_end_time);
    calc_time_diff(&prg_start_time, &prg_end_time, &prg_running);

    printf("\nAverage cycle time: %llu us\n", cycle_times / TEST_CYCLE_NUM);
    printf("Best cycle time: %li us at %li\n", best_cycle.tv_nsec / 1000, best_num);
    printf("Worst cycle time: %li us at %li\n", worst_cycle.tv_nsec / 1000, worst_num);
    printf("Test running time: %li m %li s\n", prg_running.tv_sec > 59 ? prg_running.tv_sec / 60 : 0,
                                               prg_running.tv_sec > 59 ? prg_running.tv_sec % 60 :
                                               prg_running.tv_sec);

    frame.data[1] = 0x00;
    write(c, &frame, CAN_MTU);

    close(c);
    close(s);
    fclose(out);
    fclose(in);

    return 0;
}
