#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <linux/can.h>

#define SOCK_PATH "/var/run/can-server.sock"

volatile sig_atomic_t exit_flag = 0;

void
signal_handler(int s)
{
    exit_flag = 1;
}

int
main(void)
{
    int s, t, len;
    struct sockaddr_un remote;
    struct canfd_frame test;

    signal(SIGINT, signal_handler);

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    printf("Trying to connect...\n");

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, SOCK_PATH);
    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    if (connect(s, (struct sockaddr *)&remote, len) == -1) {
        perror("connect");
        exit(1);
    }

    printf("Connected.\n");

    int ret_poll;
    struct pollfd input[1]; input[0].fd = s; input[0].events = POLLIN;

    while(!exit_flag) {
        ret_poll = poll(input, 1, -1);
        if (ret_poll < 0) {
            exit_flag = 1;
            continue;
        }

        if ((t=recv(s, &test, sizeof(struct canfd_frame), 0)) > 0) {
            printf("struct test: data[0] = 0x%.2x data[1] = 0x%.2x\n", test.data[0], test.data[1]);
        } else {
            if (t < 0) perror("recv");
            else printf("Server closed connection\n");
            exit(1);
        }
    }

    close(s);

    return 0;
}
