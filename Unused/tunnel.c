/* Copyright (C) 2005 Lumeta Corp. */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <osreldate.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <netinet/in.h>

#include "gni.h"

/*
 * Find and open an available tunnel device.  This code should work
 * for both FreeBSD 5.3 and FreeBSD 4.x, i.e. with or without devfs on FreeBSD.
 * But there are confusions with devfs.
 */
static int
find_tunnel_device(void) {
        int i=0;
        int s = -1;

        if(__FreeBSD_version < 500000) {
                for (i=0; i<32; i++) {
                        char tunnel_name[100];
                        struct stat sb;
                        int rc;
        
                        snprintf(tunnel_name, sizeof(tunnel_name), "/dev/tun%d", i);
                        rc = stat(tunnel_name, &sb);
                        if (rc < 0 && errno == ENOENT)
                                break;
                        s = open(tunnel_name, O_RDWR|O_EXCL);
                        if (s >= 0)
                                return s;
                        if (errno == EBUSY)
                                continue;
                        if (errno == ENOENT)
                                break;
                        fprintf(stderr, "gni: unexpected error for %s: (%d) %s\n",
                                tunnel_name, errno, strerror(errno));
                }
                s = -1;
        } else {        // devfs
                s = open("/dev/tun", O_RDWR);   /* devfs's way to find tunnel */
                if (s < 0)
                        fprintf(stderr, "gni: tunnel device not found, aborting\n");
        }
        return s;
}

/*
 * returns an allocated copy of a string with the name of the interface, or
 * zero if an error, which should never happen.
 */
static char *
get_tunnel_name(int tun_fd) {
	struct stat sb;

	if (fstat(tun_fd, &sb) < 0) {
		perror("get_tunnel_name, fstat");
		return 0;
	}
	return strdup(devname(sb.st_rdev, S_IFCHR));
}

int
create_tunnel(struct tunnel_info *ti) {
	struct ifreq ifr;
	char *name;

	ti->tun_fd = find_tunnel_device();
	if (ti->tun_fd < 0)
		return 0;

	name = get_tunnel_name(ti->tun_fd);
	if (name == 0)
		return 0;
	ti->if_name = strdup(name);

	if (debug)
		fprintf(stderr, "create_tunnel: creating %s\n", name);

	ti->if_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ti->if_fd < 0) {
		perror("create_tunnel open socket");
		return 0;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strlcpy(ifr.ifr_name, ti->if_name, sizeof(ifr.ifr_name));

	if (ioctl(ti->if_fd, SIOCGIFCAP, &ifr) < 0) {
		perror("create_tunnel, SIOCGIFCAP");
		exit(11);
	};
	if (debug > 2) {
		fprintf(stderr, "init_if: if_reqcap   0x%.08x\n",
			ifr.ifr_reqcap);
		fprintf(stderr, "init_if: ifr_curcap  0x%.08x\n",
			ifr.ifr_curcap);
	}

	strlcpy(ifr.ifr_name, ti->if_name, sizeof(ifr.ifr_name));
	if (ioctl(ti->if_fd, SIOCGIFFLAGS, &ifr) < 0) {
		perror("init_if, SIOCGIFFLAGS");
		exit(11);
	};

	// do we really need to do this stuff?  What does it all mean?

	strlcpy(ifr.ifr_name, ti->if_name, sizeof(ifr.ifr_name));
	ifr.ifr_flags |= IFF_SMART;		// what does this do?
	ifr.ifr_flags &= ~IFF_PROMISC;
	ifr.ifr_flags &= ~IFF_ALLMULTI;
	ifr.ifr_flags &= ~IFF_MULTICAST;
	if (ioctl(ti->if_fd, SIOCSIFFLAGS, &ifr) < 0) {
		perror("init_if, SIOCSIFFLAGS");
		exit(12);
	};
	if (debug > 2) {
		fprintf(stderr, "init_if: flags       %.04hx %.04hx\n",
			ifr.ifr_flagshigh, ifr.ifr_flags);
		fprintf(stderr, "Interface: %s\n",
			(ifr.ifr_flags & IFF_UP) ? "up" : "down");
		fprintf(stderr, "     smart: %s\n",
			(ifr.ifr_flags & IFF_SMART) ? "yes" : "no");
		fprintf(stderr, "   running: %s\n",
			(ifr.ifr_flags & IFF_RUNNING) ? "yes" : "no");
	}
	return 1;
}

int
tunnel_start(struct tunnel_info *ti) {
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, ti->if_name, sizeof(ifr.ifr_name));
	if (ioctl(ti->if_fd, SIOCGIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "tunnel_start: SIOCGIFFLAGS, %s: %m\n",
			ti->if_name);
		return 0;
	}
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(ti->if_fd, SIOCSIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "tunnel_start: SIOCSIFFLAGS, %s: %m\n",
			ti->if_name);
		return 0;
	}
	return 1;
}

void
tunnel_stop(struct tunnel_info *ti) {
	struct ifreq ifr;

	if (ti == 0)
		return;
	strlcpy(ifr.ifr_name, ti->if_name, sizeof(ifr.ifr_name));
	if (ioctl(ti->if_fd, SIOCGIFFLAGS, &ifr) >= 0 &&
	    (ifr.ifr_flags & IFF_UP) != 0) {
		ifr.ifr_flags &= ~IFF_UP;
		ioctl(ti->if_fd, SIOCSIFFLAGS, &ifr);
	}
	// XXX clear the interface addresses, a la cifaddr in pppd.c
}

void
close_tunnel(struct tunnel_info *ti) {
	tunnel_stop(ti);
	if (ti->if_fd >= 0)
		close(ti->if_fd);
	if (ti->tun_fd >= 0)
		close(ti->tun_fd);
}


void
delete_route(struct cidr *cip) {
	int error;
	char buf[500];

	snprintf(buf, sizeof(buf), "/sbin/route -q delete %s %s/%d",
		(cip->su.sa.sa_family == AF_INET) ? "-inet" : "-inet6",
		sutop(&cip->su),
		cip->netbits);
	if (debug > 1)
		fprintf(stderr, "%s\n", buf);
	error = system(buf);
	if (error)
		fprintf(stderr, "error removing route: %s\n",
			buf);
}

/*
 * This should be done with system calls, not a system() call.  But this isn't what we are trying
 * to try out, so this will do for now.
 */
void
add_route_to_addr(struct cidr *cip, sockunion *su) {
	char buf[500];
	int error;
	char *dest = strdup(sutop(su));

	snprintf(buf, sizeof(buf), "/sbin/route -q add %s %s/%d %s",
		(cip->su.sa.sa_family == AF_INET) ? "-inet" : "-inet6",
		sutop(&cip->su),
		cip->netbits,
		dest);
	if (debug > 1)
		fprintf(stderr, "%s\n", buf);
	free(dest);
	error = system(buf);
	if (error) {
		fprintf(stderr, "error setting route: %s, trying delete first\n",
			buf);

		// The following is for debugging convenience.  A previous crash might
		// have left the route around.  Delete, and retry.  This would be wrong
		// in production.

		delete_route(cip);
		error = system(buf);
		if (error) {
			fprintf(stderr, "add_route failed, aborting\n");
			exit(13);
		}
	}
}

/*
 * This should be done with system calls, not a system() call.  But this isn't what we are trying
 * to try out, so this will do for now.
 */
void
add_route_to_tunnel(struct cidr *cip, struct tunnel_info *tip) {
	char buf[500];
	int error;

	snprintf(buf, sizeof(buf), "/sbin/route -q add %s %s/%d -interface %s",
		(cip->su.sa.sa_family == AF_INET) ? "-inet" : "-inet6",
		sutop(&cip->su),
		cip->netbits,
		tip->if_name);
	if (debug > 1)
		fprintf(stderr, "%s\n", buf);
	error = system(buf);
	if (error) {
		fprintf(stderr, "error setting route: %s, trying delete first\n",
			buf);

		// The following is for debugging convenience.  A previous crash might
		// have left the route around.  Delete, and retry.  This would be wrong
		// in production.

		delete_route(cip);
		error = system(buf);
		if (error) {
			fprintf(stderr, "add_route failed, aborting\n");
			exit(13);
		}
	}
#ifdef notdef
// dammit, this is just too hard for now
struct m_rtmsg *rtm = (struct m_rtmsg *)buf;
cp = &buf[sizeof(struct m_rtmsg)];
rtm->rtm_type = RTM_ADD|RTM_DELETE;
rtm->rtm_flags = RTF_STATIC|RTF_GATEWAY;
rtm->rtm_version = RTM_VERSION;
rtm->rtm_seq = 1;

ifr.ifr_index needed for 
	rtm->rtm_addrs = 
	rtm.rtm_rmx = rt_metrics;
	rtm.rtm_inits = rtm_inits;

	if (rtm_addrs & RTA_NETMASK)
		mask_addr();
	NEXTADDR(RTA_DST, so_dst);
	NEXTADDR(RTA_GATEWAY, so_gate);
	NEXTADDR(RTA_NETMASK, so_mask);
	NEXTADDR(RTA_GENMASK, so_genmask);
	NEXTADDR(RTA_IFP, so_ifp);
	NEXTADDR(RTA_IFA, so_ifa);
	rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;
#endif
}

/*
 * Read next packet from a tunnel
 */
int
read_tunnel_packet(int s, char *buf, size_t len) {
	int n = read(s, buf, len);

	if (n == 0)
		return 0;
	if (n < 0) {
		perror("read_tunnel_packet: read");
		return n;
	}

	if (debug)
		dump_packet("read_tunnel_packet", buf, len);
	return n;
}

int
set_if_addr(struct tunnel_info *tip, sockunion addr, sockunion bcast, sockunion mask) {
	struct ifaliasreq ifa;

	memset(&ifa, 0, sizeof(ifa));
	memcpy(&ifa.ifra_name, tip->if_name, IFNAMSIZ);
	ifa.ifra_addr = addr.sa;
	ifa.ifra_broadaddr = bcast.sa;
	ifa.ifra_mask = mask.sa;
	if (ioctl(tip->if_fd, SIOCAIFADDR, &ifa) < 0) {
		perror("set_if_addr");
		return 0;
	}
	return 1;
}
