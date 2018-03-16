/*
 * Implementation of FreeBSD-specific network interactions. This is how it's
 * done right, ifdef weavers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <assert.h>

#include "aw.h"

int highest_tun = -1;

/*
 * The FreeBSD tun(4) man page gives two ways to find a free tunnel device.
 * One, implemented here, is the I-can-guess-the-next-tunnel loop.  The other
 * involves devfs, is deprecated, and is said to not go away because everybody
 * is using it.  I choose the non-deprecated way, in this exciting,
 * fast-paced world of FreeBSD interface configuration code.
 */

static int
find_tun(if_info *ifd) {
	struct ifaliasreq ifalias;

	int i;
	int s;

	s = socket(AF_INET6, SOCK_RAW, 0);
	if (s < 0) {
		perror("find_tun: open socket");
		exit(90);
	}


	for (i=highest_tun+1; i<100; i++) {
		struct ifreq ifr;

		snprintf(ifd->ifname, sizeof(ifd->ifname), "tun%d", i);
		memset(&ifr, 0, sizeof(ifr));
		memcpy(&ifr.ifr_name, ifd->ifname, sizeof(ifr.ifr_name));
		
		if (ioctl(s, SIOCIFCREATE, &ifr) < 0) {
			if (errno == EEXIST)
				continue;
			perror("find_tun: opening tun devices");
			return -1;
		};
		highest_tun = i;
		return s;
	}

	fprintf(stderr, "find_tun: no available tunnel up to tun%d, aborting\n", i);
	return -1;
}

static struct sockaddr
compute_bcast(if_info *ifd) {
	struct sockaddr b;

	return b;
}

static struct sockaddr
compute_mask(if_info *ifd) {
	struct sockaddr m;

	return m;
}

void
set_tun(if_info *ifd) {
	struct ifreq ifr;

        strlcpy(ifr.ifr_name, ifd->ifname, sizeof(ifr.ifr_name));
        if (ioctl(ifd->fd, SIOCGIFFLAGS, &ifr) < 0) {
                perror("init_if, SIOCGIFFLAGS");
                exit(11);
	};

        // do we really need to do this stuff?  What does it all mean?

        strlcpy(ifr.ifr_name, ifd->ifname, sizeof(ifr.ifr_name));
        ifr.ifr_flags &= ~IFF_SMART;	// we don't manage our own routes
        ifr.ifr_flags &= ~IFF_PROMISC;
        ifr.ifr_flags &= ~IFF_BROADCAST;
        ifr.ifr_flags &= ~IFF_POINTOPOINT;
        ifr.ifr_flags &= ~IFF_ALLMULTI;
        ifr.ifr_flags &= ~IFF_MULTICAST;;
        if (ioctl(ifd->fd, SIOCSIFFLAGS, &ifr) < 0) {
                perror("settun, SIOCSIFFLAGS");
                exit(12);
	};
        if (1 || debug > 2) {
		fprintf(stderr, "tunnel %s\n", ifd->ifname);
                fprintf(stderr, "init_if: flags       %.04hx %.04hx\n",
                        ifr.ifr_flagshigh, ifr.ifr_flags);
                fprintf(stderr, "Interface: %s\n",
                        (ifr.ifr_flags & IFF_UP) ? "up" : "down");
                fprintf(stderr, "     smart: %s\n",
                        (ifr.ifr_flags & IFF_SMART) ? "yes" : "no");
                fprintf(stderr, "   running: %s\n",
                        (ifr.ifr_flags & IFF_RUNNING) ? "yes" : "no");
	}
}

void
make_if(if_info *ifd) {
	struct ifaliasreq ifa;
	struct ifreq ifr;
	char buf[1000];
	int rc;

dump_sa(SA(ifd->sa), "make_if");

	ifd->fd = find_tun(ifd);
	if (ifd->fd < 0)
		return;

	set_tun(ifd);

	memset(&ifa, 0, sizeof(ifa));
	memcpy(&ifa.ifra_name, ifd->ifname, IFNAMSIZ);
	ifa.ifra_addr = *SA(ifd->sa);
	ifa.ifra_broadaddr = *SA(ifd->sa);
	netbits_to_netmask(&ifa.ifra_mask, AF_INET6, ifd->netsize);

// The following is a shameless kludge to test and get the plumbing right.
//  It should be done with syscalls, but these work for now.

	snprintf(buf, sizeof(buf), "ifconfig %s inet6 %s",
		ifd->ifname, local_addr);

	if (debug)
		fprintf(stderr, "%s\n", buf);
	rc = system(buf);
	if (rc != 0) {
		fprintf(stderr, "failed with rc %d: %s\n", rc, buf);
		exit(10);
	}

	snprintf(buf, sizeof(buf), "route add -inet6 eeee::/16 -interface tun0");

	if (debug)
		fprintf(stderr, "%s\n", buf);
	rc = system(buf);
	if (rc != 0) {
		fprintf(stderr, "failed with rc %d: %s\n", rc, buf);
		exit(10);
	}

#ifdef notdef
	if (ioctl(ifd->fd, SIOCAIFADDR, &ifa) < 0) {
		perror("make_if: setting alias");
		return;
	}

	strlcpy(ifr.ifr_name, ifd->ifname, sizeof(ifr.ifr_name));
	if (ioctl(ifd->fd, SIOCGIFFLAGS, &ifr) < 0) {
		perror("make_if, SIOCGIFFLAGS");
		exit(11);
	};

	// do we really need to do this stuff?  What does it all mean?

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifd->ifname, sizeof(ifr.ifr_name));
	ifr.ifr_flags |= IFF_SMART;		// what does this do?
	ifr.ifr_flags &= ~IFF_PROMISC;
	ifr.ifr_flags &= ~IFF_ALLMULTI;
	ifr.ifr_flags &= ~IFF_MULTICAST;
	if (ioctl(ifd->fd, SIOCSIFFLAGS, &ifr) < 0) {
		perror("make_if, SIOCSIFFLAGS");
		exit(12);
	};
	if (debug > 2) {
		fprintf(stderr, "make_if: flags       %.04hx %.04hx\n",
			ifr.ifr_flagshigh, ifr.ifr_flags);
		fprintf(stderr, "Interface: %s\n",
			(ifr.ifr_flags & IFF_UP) ? "up" : "down");
		fprintf(stderr, "     smart: %s\n",
			(ifr.ifr_flags & IFF_SMART) ? "yes" : "no");
		fprintf(stderr, "   running: %s\n",
			(ifr.ifr_flags & IFF_RUNNING) ? "yes" : "no");
	}
#endif
}

void
close_if(if_info *ifd) {
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifd->ifname, sizeof(ifr.ifr_name));
	if (ifd->fd >= 0) {
		if (ioctl(ifd->fd, SIOCIFDESTROY, &ifr) < 0)
			perror("close_if: SIOCIFDESTROY");
	}

}
