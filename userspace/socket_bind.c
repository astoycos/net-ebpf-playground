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

#include <linux/bpf.h>

#include "syscall.h"

int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

int main(int argc, char **argv)
{
	//pid_t target_pid;
	int server_fd, new_socket, bind_port, map_fd, err;
	uint32_t key;
	uint64_t value;
    int opt = 1;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
	const char *map_path;
	union bpf_attr attr;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <bind_port> <map path> \n", argv[0]);
		exit(EXIT_SUCCESS);
	}

	//target_pid = atoi(argv[1]);
	//target_fd = atoi(argv[2]);
	bind_port = atoi(argv[1]);
    map_path = argv[2];
	key = 0;
    char client_message[2000];
    char* hello = "Hello from server";


    memset(client_message, '\0', sizeof(client_message));
    // Make a socket and wait for connections 
	
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0))
        == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
  
    // Forcefully attaching socket to the port 8789
    if (setsockopt(server_fd, SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(bind_port);
  
    // Forcefully attaching socket to the port 8789
    if (bind(server_fd, (struct sockaddr*)&address,
             sizeof(address))
        < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("\nListening for incoming connections.....\n");

    while (1) {
        if ((new_socket
            = accept(server_fd, (struct sockaddr*)&address,
                    (socklen_t*)&addrlen))
            < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        if (new_socket < 0){
            printf("Can't accept\n");
            return -1;
        }

        printf("Client connected at IP: %d and port: %i\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));

        // /* Open BPF map for storing the socket */
        // memset(&attr, 0, sizeof(attr));
        // attr.pathname = (uint64_t) map_path;
        // attr.bpf_fd = 0;
        // attr.file_flags = 0;

        // map_fd = bpf(BPF_OBJ_GET, &attr, sizeof(attr));
        // if (map_fd == -1)
        //     error(EXIT_FAILURE, errno, "bpf(OBJ_GET)");

        // /* Insert socket FD into the BPF map */
        // value = (uint64_t) new_socket;
        // memset(&attr, 0, sizeof(attr));
        // attr.map_fd = map_fd;
        // attr.key = (uint64_t) &key;
        // attr.value = (uint64_t) &value;
        // attr.flags = BPF_ANY;

        // err = bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
        // if (err)
        //     error(EXIT_FAILURE, errno, "bpf(MAP_UPDATE_ELEM)");

        // Receive the data from the socket 
        int ret = read(new_socket, client_message, sizeof(client_message));
        if (ret < 0 ){ 
            perror("read");
            printf("Couldn't receive: %d\n", ret);
            //return -1;
        }

        // printf("Msg from client: %s\n", client_message);

        // send(new_socket, hello, strlen(hello), 0);
        // printf("Hello message sent\n");
    }
	//close(sock_fd);
}