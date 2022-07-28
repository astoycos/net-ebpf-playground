// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (c) 2020 Cloudflare */
/*
 * Inserts a socket belonging to another process, as specified by the target PID
 * and FD number, into a given BPF map.
 */

#include <error.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>


#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>



#include <linux/bpf.h>

#include "syscall.h"

#define POLLWRNORM	POLLOUT
#define POLLWRBAND	256
#define POLLMSG		512
#define POLLREMOVE	1024
#define POLLRDHUP   2048

int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

struct socket_key
{
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

int main(int argc, char **argv)
{
    // pid_t target_pid;
    int server_fd, second_connect_sock, new_socket, bind_port, map_fd, err;
    uint64_t value;
    int opt = 1;
    struct sockaddr_in address_server_host;
    struct sockaddr_in address_server_container;
    struct timeval timeout;

    int addrlen = sizeof(address_server_host);

    const char *map_path;
    union bpf_attr attr;

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <bind_port> <map path> \n", argv[0]);
        exit(EXIT_SUCCESS);
    }

    // target_pid = atoi(argv[1]);
    // target_fd = atoi(argv[2]);
    bind_port = atoi(argv[1]);
    map_path = argv[2];

    char client_message[2000];
    //char *hello = "Hello from server";

    memset(client_message, '\0', sizeof(client_message));
    // Make a socket and wait for connections

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 8789
    if (setsockopt(server_fd, SOL_SOCKET,
                   SO_REUSEADDR, &opt,
                   sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    int r = setsockopt(server_fd, SOL_TCP, 
                        TCP_NODELAY,
                        &opt, sizeof(opt));
	if (r < 0) {
		perror("setsockopt()");
	}


    // non-blocking socket
    // err = ioctl(server_fd, FIONBIO, (char *)&opt);
    // if (err < 0) {
    //     perror("ioctl s1 failed()");
    //     exit(EXIT_FAILURE);
    // }

    address_server_host.sin_family = AF_INET;
    address_server_host.sin_addr.s_addr = INADDR_ANY;
    address_server_host.sin_port = htons(bind_port);

    // Forcefully attaching socket to the port 8789
    if (bind(server_fd, (struct sockaddr *)&address_server_host,
             (socklen_t)addrlen) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    //Make new Socket to connect to Server in netns
    if ((second_connect_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }

    // Trick server in container netns into being ready for data 
    // Connect to dst Socket
    address_server_container.sin_family = AF_INET;
    address_server_container.sin_port = htons(0x1f40);
    address_server_host.sin_addr.s_addr = INADDR_ANY;

    //inet_pton(AF_INET, "192.168.10.2", &address_server_container.sin_addr.s_addr);

    // Propogate connection to client in netns
    int ret = connect(second_connect_sock, (struct sockaddr *)&address_server_container,
                      (socklen_t)addrlen);
    if (ret < 0)
    {
        perror("connect");
        printf("Couldn't connect to netns server socket: %d\n", ret);
        // return -1;
    }


    printf("\nListening for incoming connections.....\n");

    timeout.tv_sec = 10;
	timeout.tv_usec = 0;

    //while (1)
    //{   
        struct sockaddr client;
        new_socket = accept(server_fd, (struct sockaddr *)&client,
             (socklen_t*)&addrlen); 

        // Connect isn't called yet so we'll see EAGAIN since we made this non-blocking
        if (new_socket < 0)
        {   
            perror("accept");
            exit(EXIT_FAILURE);
        }; 

        printf("Client connected at IP: %x and port: %i\n", address_server_host.sin_addr, address_server_host.sin_port);

        // /* Open BPF map for loading the new socket */
        memset(&attr, 0, sizeof(attr));
        attr.pathname = (uint64_t)map_path;
        attr.bpf_fd = 0;
        attr.file_flags = 0;

        map_fd = bpf(BPF_OBJ_GET, &attr, sizeof(attr));
        if (map_fd == -1)
            error(EXIT_FAILURE, errno, "bpf(OBJ_GET)");

        /* Insert socket FD into the BPF map */
        struct socket_key key = {
            .src_ip = 0x00000000,
            // Port 8000
            .src_port = htons(0x2255),
            .dst_ip = 0x00000000,
            .dst_port = 0x0000,
        };
        
        // duplicate fd
        // int dup_new_socket; 
        // dup_new_socket = dup(new_socket);

        value = &new_socket;
        int idx = 0;
        memset(&attr, 0, sizeof(attr));
        attr.map_fd = map_fd;
        attr.key = (uint64_t)&idx;
        attr.value = (uint64_t)value;
        attr.flags = BPF_ANY;

        err = bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
        if (err)
            error(EXIT_FAILURE, errno, "bpf(MAP_UPDATE_ELEM)");

        /* [*] Wait for the socket to close. Let sockmap do the magic. */
        struct pollfd fds[1] = {
            {.fd = new_socket, .events = POLLHUP},
        };
        poll(fds, 1, -1);


        ///Receive the data from the socket which should be intercepted by the sk_skb prog
        // ret = recv(new_socket, client_message, sizeof(client_message),0);
        // if (ret < 0 ){
           
        //     perror("recv failed()\n");
        //     break;
        // }
        // printf("Msg from client: %s\n", client_message);

        // send(new_socket, hello, strlen(hello), 0);
        // printf("Hello message sent\n");
    //}
    // close(sock_fd);
}