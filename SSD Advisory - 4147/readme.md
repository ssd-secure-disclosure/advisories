**Vulnerability Summary**

In FreeBSD there is a cryptographic device module called `cryptodev` which is accessible by any user on the system. Due to an absence of a locking mechanism, an attacker is able to create a race condition in the device mechanism and trigger a Use After Free vulnerability. If performed correctly, an attacker is able to use this vulnerability to gain control of the kernel and gain access to the attacked machine.

**CVE**

Placeholder

**Credit**

An independent Security Researcher, Avi S., has reported this vulnerability to SSD Secure Disclosure program.

**Affected Systems**

FreeBSD 4.8

**Vendor Response**

Place Holder

**Vulnerability Details**

Since FreeBSD 4.8, an in-tree cryptographic device module was included called `cryptodev`, found in the source tree under *sys/opencrypto/cryptodev.c*. This module creates a device `/dev/crypto`, which has permissions **666**, making it globally accessible to any user.

Interaction with this driver occurs by calling the `CRIOGET` ioctl on the device. This allows users to create an instance of a `cryptof` device, which represents an instance of a device for a user, which is given back to the user as a file descriptor.

The resulting file descriptor can be used in subsequent calls, which are then handled by `cryptof_ioctl`. This ioctl handles session establishment between the hardware accelerators and the user, acting as a hardware abstraction layer (HAL) for the supported devices.

**Bug**

The bug itself has to do with the locking, or lack there of, in the ioctl handler for `cryptof_ioctl`, and similarly, `cryptof_close`. While locking exists in a few select portions of the code base, in general, most operations will occur unlocked.

This becomes an issue particularly around the session end, where operations are releasing memory. Racing a `close()` operation on a syscall with partially any other operation in the ioctl can give you the ability to trigger a use-after-free vulnerability.

**Exploitation**

The proof-of-concept exploit targets a race between `cryptof_close`, and the ioctl `CIOCFSESSION`. If the race wins then `cryptof_ioctl` should call `csedelete` on a released `struct csession`, or, `cryptof_close` will attempt to `TAILQ_REMOVE` a released `struct csession` from its linked list. There is also race a spraying thread, which sprays fake `struct csessions` using the syscall `mac_set_fd`, which will create a heap allocation and `copyin` user supplied data, then subsequent-ally error out due to invalid data being supplied and release it.

With all 3 threads going at the same time (in practice more are used to guarantee success), this allows us to get an invalid `TAILQ_REMOVE`, which we can use to overwrite the `null_cdevsw.d_ioctl`. The exploit spawn a few threads trying to trigger this `ioctl` indefinitely to gain control of the instruction pointer.

However, due to the fact that the `TAILQ_REMOVE` procedure will also attempt to write to the value which is used for the overwrite, this race usually fails and instead we get an error attempting to write to the address. This however is just used for demonstration of the bug, and in practice this demo value could be replaced with a more useful pointer that could be written to.

You can find the exploit on our Github repository:
[SSD FreeBSD Advisory Github Repository](#)

**Additional Notes/Bugs**

This race can be used to attack other commands in the `ioctl`, and while we briefly explored the possibility of attacking those commands, the double release case seemed like the path of least friction.

There is an a additional bug in cryptodev which will create a massive allocation: this is the fact that `mackeylen` in `struct session_op` is a signed integer, so if set to `0xFFFFFFFF` it will create a massive allocation, which additionally gets sign extended up to 64 bits. This triggers a bug in the large allocation function in the kernel `malloc` function, where `size = roundup(size, PAGE_SIZE);` which occurs in the large memory allocator causes it to overflow the size of the allocation.

Unfortunately this isn’t exploitable (at-least from this vector), and instead it just causes a kernel panic on a dereference to an address that can’t be allocated.

Also note, there is a provided *fake_cryptodev.h*, which can be use for linting on a non-FreeBSD platform. We need to pass a flag into the compiler in *build.sh* to switch between the real and fake *cryptodev.h* files.