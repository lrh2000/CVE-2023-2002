// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <endian.h>
#include <sys/socket.h>

#if BYTE_ORDER == LITTLE_ENDIAN
#define __le16    short
#define __u8      char
#else
#error Unsupported endianness
#endif

#define __packed  __attribute__ ((packed))

/* proto */
#define BTPROTO_HCI	1

/* addr */
struct sockaddr_hci {
	sa_family_t    hci_family;
	unsigned short hci_dev;
	unsigned short hci_channel;
};
#define HCI_DEV_NONE	0xffff

#define HCI_CHANNEL_CONTROL	3

/* mgmt cmd */
struct mgmt_hdr {
	__le16	opcode;
	__le16	index;
	__le16	len;
} __packed;

struct mgmt_mode {
	__u8 val;
} __packed;

#define MGMT_OP_SET_POWERED		0x0005

/* mgmt evt */
#define MGMT_EV_CMD_COMPLETE		0x0001
#define MGMT_EV_CMD_STATUS		0x0002
struct mgmt_ev_cmd_status {
	__le16 opcode;
	__u8 status;
} __packed;

#define MGMT_STATUS_SUCCESS		0x00
#define MGMT_STATUS_UNKNOWN_COMMAND	0x01
#define MGMT_STATUS_NOT_CONNECTED	0x02
#define MGMT_STATUS_FAILED		0x03
#define MGMT_STATUS_CONNECT_FAILED	0x04
#define MGMT_STATUS_AUTH_FAILED		0x05
#define MGMT_STATUS_NOT_PAIRED		0x06
#define MGMT_STATUS_NO_RESOURCES	0x07
#define MGMT_STATUS_TIMEOUT		0x08
#define MGMT_STATUS_ALREADY_CONNECTED	0x09
#define MGMT_STATUS_BUSY		0x0a
#define MGMT_STATUS_REJECTED		0x0b
#define MGMT_STATUS_NOT_SUPPORTED	0x0c
#define MGMT_STATUS_INVALID_PARAMS	0x0d
#define MGMT_STATUS_DISCONNECTED	0x0e
#define MGMT_STATUS_NOT_POWERED		0x0f
#define MGMT_STATUS_CANCELLED		0x10
#define MGMT_STATUS_INVALID_INDEX	0x11
#define MGMT_STATUS_RFKILLED		0x12
#define MGMT_STATUS_ALREADY_PAIRED	0x13
#define MGMT_STATUS_PERMISSION_DENIED	0x14

static inline const char *stringify_mgmt_status(int status) {
	switch (status) {
#define CASE(s) \
	case MGMT_STATUS_##s: \
		return "MGMT_STATUS_" #s;
	CASE(SUCCESS)
	CASE(UNKNOWN_COMMAND)
	CASE(NOT_CONNECTED)
	CASE(FAILED)
	CASE(CONNECT_FAILED)
	CASE(AUTH_FAILED)
	CASE(NOT_PAIRED)
	CASE(NO_RESOURCES)
	CASE(TIMEOUT)
	CASE(ALREADY_CONNECTED)
	CASE(BUSY)
	CASE(REJECTED)
	CASE(NOT_SUPPORTED)
	CASE(INVALID_PARAMS)
	CASE(DISCONNECTED)
	CASE(NOT_POWERED)
	CASE(CANCELLED)
	CASE(INVALID_INDEX)
	CASE(RFKILLED)
	CASE(ALREADY_PAIRED)
	CASE(PERMISSION_DENIED)
#undef CASE
	default:
		return "MGMT_STATUS_ERROR_UNKNOWN";
	}
}
