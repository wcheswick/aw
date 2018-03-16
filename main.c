/* Copyright (C) 2005 Lumeta Corp. */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <osreldate.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>

#include <sys/tree.h>
#include <sha256.h>

#include <pcap/pcap.h>

#if __FreeBSD_version >= 500000
#include <sys/limits.h>
#include <sys/tree.h>		// for the splay routines
#else
#include <machine/limits.h>
#include "tree.h"		// for the splay routines
#endif

#include "arg.h"
#include "aw.h"

#define SNAPLEN	65535

int debug = 2;

char *if_inside;
char *if_white;
char *net_inside;
char *net_white;

pcap_t *p_in;
pcap_t *p_out;

struct sockaddr_in6 white_net;
struct in6_addr white_net_mask;
int white_net_size;

struct sockaddr_in6 local_net;
struct in6_addr local_net_mask;
int local_net_size;

#define TCPH(iph)	((struct tcphdr *)&iph[1])
#define UDPH(iph)	((struct udphdr *)&iph[1])
#define ICMPH(iph)	((struct icmp6_hdr *)&iph[1])

enum raw_set {
	RAW_TCP,
	RAW_UDP,
	RAW_ICMP,
};
#define N_RAW_SET	3

struct sock_types {
	int	type;
	char	*name;
} sock_types[] = {
	{IPPROTO_TCP, "TCP"},
	{IPPROTO_UDP, "UDP"},
	{IPPROTO_ICMPV6, "ICMP"},
};

struct raw_sock_set {
	int	fd[N_RAW_SET];
	u_int	interface_index;
} raw_inside, raw_white;

/*
 * NAT translation info is in two trees, one found using
 * inside packet information, the other found using
 * solely the white-side address.
 */
typedef struct nat_info {
	SPLAY_ENTRY(nat_info)	inside_next;
	SPLAY_ENTRY(nat_info)	white_next;
	struct ip6_hdr 	hdr;
	union {
		struct tcphdr thdr;
		struct udphdr uhdr;
		struct icmp6_hdr ihdr;
	};
	struct sockaddr_in6 dst;
	struct sockaddr_in6 local_src;
	struct sockaddr_in6 white_src;
} nat_info;

SPLAY_HEAD(insider_tree, nat_info) insiders;
SPLAY_HEAD(white_addr_tree, nat_info) white_addrs;

int
insider_compare(nat_info *a, nat_info *b) {
	int rc = memcmp(&a->hdr.ip6_src, &b->hdr.ip6_src, sizeof(struct in6_addr));
	if (rc) return rc;
	rc = memcmp(&a->hdr.ip6_dst, &b->hdr.ip6_dst, sizeof(struct in6_addr));
	if (rc) return rc;
	rc = a->hdr.ip6_nxt - b->hdr.ip6_nxt;	// protocol
	if (rc) return rc;
	switch (a->hdr.ip6_nxt) {
	case IPPROTO_TCP:
		rc = a->thdr.th_sport - b->thdr.th_sport;
		if (rc) return rc;
		rc = a->thdr.th_dport - b->thdr.th_dport;
		if (rc) return rc;
		return 0;
	case IPPROTO_UDP:
		rc = a->uhdr.uh_sport - b->uhdr.uh_sport;
		if (rc) return rc;
		rc = a->uhdr.uh_dport - b->uhdr.uh_dport;
		if (rc) return rc;
		return 0;
	case IPPROTO_ICMPV6:
		// XXX not handled yet
		fprintf(stderr, "insider_compare: ICMP not handled yet\n");
		return 0;
	default:
		// XXX really not handled yet
		fprintf(stderr, "unhandled proto: %d\n", a->hdr.ip6_nxt);
		exit(98);
	}
}

SPLAY_PROTOTYPE(insider_tree, nat_info, inside_next, insider_compare);
SPLAY_GENERATE(insider_tree, nat_info, inside_next, insider_compare);

int
white_addr_compare(nat_info *a, nat_info *b) {
	return memcmp(&a->white_src.sin6_addr, &b->white_src.sin6_addr,
		sizeof(struct in6_addr));
}

SPLAY_PROTOTYPE(white_addr_tree, nat_info, white_next, white_addr_compare);
SPLAY_GENERATE(white_addr_tree, nat_info, white_next, white_addr_compare);


int stat_caplen_err = 0;
int stat_enot_ip = 0;
int stat_etooshort = 0;
int stat_notipv6 = 0;
int stat_trunc = 0;
int stat_ff_inside = 0;		//filter failure, something got through
int stat_ff_outside = 0;	// ditto
int stat_ff_white = 0;
int stat_unknown_white = 0;
int stat_nonmatched_white_proto = 0;
int stat_nonmatched_white_tcp = 0;
int stat_nonmatched_white_udp = 0;
int stat_ok = 0;

void
show_stats(void) {
	fprintf(stderr, "caplen_err:		%d\n", stat_caplen_err);
	fprintf(stderr, "enot_ip:		%d\n", stat_enot_ip);
	fprintf(stderr, "etooshort:		%d\n", stat_etooshort);
	fprintf(stderr, "notipv6:		%d\n", stat_notipv6);
	fprintf(stderr, "trunc:			%d\n", stat_trunc);
	fprintf(stderr, "ff_inside:		%d\n", stat_ff_inside);
	fprintf(stderr, "ff_white:		%d\n", stat_ff_white);
	fprintf(stderr, "unknown_white:		%d\n", stat_unknown_white);
	fprintf(stderr, "nonmatched_white_proto: %d\n", stat_nonmatched_white_proto);
	fprintf(stderr, "nonmatched_white_tcp:	%d\n", stat_nonmatched_white_tcp);
	fprintf(stderr, "nonmatched_white_udp:	%d\n", stat_nonmatched_white_udp);
	fprintf(stderr, "ok:			%d\n", stat_ok);
}

u_char random_buf[256/8];
int random_fd;

void
start_random(void) {
	random_fd = open("/dev/urandom", O_RDONLY);
	if (random_fd < 0) {
		perror("opening /dev/random");
		exit(20);
	}
	read(random_fd, random_buf, sizeof(random_buf));
}

void
init_raw(struct raw_sock_set *ss, const char *interface) {
	int i;
	struct icmp6_filter icmp_filter;

	for (i=0; i<N_RAW_SET; i++) {
		int bufsize = 2000;

		ss->fd[i] = socket(PF_INET6, SOCK_RAW, sock_types[i].type);
		if (ss->fd[i] < 0) {
			perror("opening raw socket");
			fprintf(stderr, "type %s for interface %s\n",
				sock_types[i].name, interface);
			exit(10);
		}
#ifdef notdef
		if (setsockopt(ss->fd[i], SOL_SOCKET, SO_SNDBUF,
		    &bufsize, sizeof(bufsize)) < 0) {
			perror("raw socket SO_SNDBUF");
			fprintf(stderr, "type %s for interface %s\n",
				sock_types[i].name, interface);
			exit(11);
		}
#endif
	}

	/* Turn off incoming ICMP messages: these raw sockets are for output only */
	ICMP6_FILTER_SETBLOCKALL(&icmp_filter);
	if (setsockopt(ss->fd[RAW_ICMP], IPPROTO_ICMPV6, ICMP6_FILTER,
	    &icmp_filter, sizeof(icmp_filter))) {
		perror("setting ICMP filter options");
		fprintf(stderr, "for interface %s\n", interface);
		exit(12);
	}

	ss->interface_index = if_nametoindex(interface);
	if (ss->interface_index == 0) {
		fprintf(stderr, "aw: init_raw for '%s', interface not found\n",
			interface);
		exit(13);
	}
	if (debug > 1)
		fprintf(stderr, "interface %-6s  index %d\n",
			interface, ss->interface_index);
}

void
dump_bytes(u_char *buf, int n, int max) {
	int i;

	for (i=0; i<max && i < n; i++)
		fprintf(stderr, "%02x ", buf[i]);
	if (i < n)
		fprintf(stderr, " ...");
}

void
dump_msg(char *label, struct msghdr *msg) {
	struct iovec *iov;
	int niov;
	u_char *ap, *bp;
	int apl, bpl, i;

	fprintf(stderr, "dump_msg of %s\n", label);
	fprintf(stderr, "   --> %s\n",
		dump_6addr(*(struct in6_addr *)msg->msg_name));
	iov = msg->msg_iov;
	niov = msg->msg_iovlen;
	fprintf(stderr, "   iovec size: %d\n", niov);
	for (i=0; i< niov; i++) {
		struct tcphdr *tcph = (struct tcphdr *)iov;
		struct udphdr *udph = (struct udphdr *)iov;
		struct icmp6_hdr *icmph = (struct icmp6_hdr *)iov;

		u_char *pkt = (u_char *)iov->iov_base;
		fprintf(stderr, "      iov%4d  ", (int)iov->iov_len);
		dump_bytes(pkt, iov->iov_len, 32);
		fprintf(stderr, "\n");

		fprintf(stderr, "	tcp %d -> %d\n",
			ntohs(tcph->th_sport), ntohs(tcph->th_dport));
	}

	ap = msg->msg_control;
	apl = msg->msg_controllen;
	fprintf(stderr,	"   aux buf %d  ", apl);
	dump_bytes(ap, apl, 32);
	fprintf(stderr, "\n");

	fprintf(stderr, "   flags: 0x%02x\n", msg->msg_flags);
}

/*
 * See RFC 3542, section 3, for all this.  We cannot change the flow data,
 * which might be a deal-breaker for this approach.
 */

void
forward_packet_using_raw(struct raw_sock_set *ss, u_char *packet, int len,
   struct in6_addr *src, struct in6_addr *dst_addr, int proto,
   int interface_index) {
	struct sockaddr_in6 dst;
	struct msghdr msg;
	struct iovec iov[1];
	u_char *auxbuf;
	struct cmsghdr *scmsgp;
	int cmsglen = 0;
	struct in6_pktinfo *pi;
	int n, fd;

#ifdef notdef
IPPROTO_IPV6
IPV6_HOPLIMIT
first byte of integer hop limit
#endif

//dump_bytes(packet, len, 40);
//fprintf(stderr, "\n");

	dst.sin6_len = sizeof(dst);
	dst.sin6_family = AF_INET6;
	dst.sin6_flowinfo = 0;	// XXX
	dst.sin6_addr = *dst_addr;
	dst.sin6_scope_id = interface_index;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (caddr_t)&dst;
	msg.msg_namelen = sizeof(dst);

	memset(&iov, 0, sizeof(iov));
	iov[0].iov_base = (caddr_t)packet;
	iov[0].iov_len = len;

	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

//dump_bytes((u_char *)&msg.msg_iov, len, 40);
//fprintf(stderr, "\n");

	cmsglen += CMSG_SPACE(sizeof(struct in6_pktinfo));
	scmsgp = (struct cmsghdr *)calloc(1, cmsglen);
	assert(scmsgp);	// no memory for packet auxilary buffer

	msg.msg_control = scmsgp;
	msg.msg_controllen = cmsglen;

//	msg.msg_control = 0;
//	msg.msg_controllen = 0;

	pi = (struct in6_pktinfo *)(CMSG_DATA(scmsgp));
	memset(pi, 0, sizeof(struct in6_pktinfo));
	scmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	scmsgp->cmsg_level = IPPROTO_IPV6;
	scmsgp->cmsg_type = IPV6_PKTINFO;
	scmsgp = CMSG_NXTHDR(&msg, scmsgp);

	pi->ipi6_addr = *src;
memset(&pi->ipi6_addr, 0, sizeof(pi->ipi6_addr));
fprintf(stderr, "setting src to %s\n", dump_6addr(pi->ipi6_addr));
	pi->ipi6_ifindex = ss->interface_index;
fprintf(stderr, "interface index is %d\n", pi->ipi6_ifindex);
	msg.msg_flags = 0;

	switch (proto) {
	case IPPROTO_TCP:
		fd = ss->fd[RAW_TCP];
// XXX		dst.sin6_port = 
		break;
	case IPPROTO_UDP:
		fd = ss->fd[RAW_UDP];
// XXX		dst.sin6_port = 
		break;
	case IPPROTO_ICMP:
		fd = ss->fd[RAW_ICMP];
// XXX		dst.sin6_port = 
		break;
	default:
		fprintf(stderr, "aw: unexpected write protocol: %s\n",
			show_proto(proto));
		return;
	}
dump_msg("local to white", &msg);
	n = sendmsg(fd, &msg, 0);
	if (n < 0) {
		perror("forward raw write error");
	}
fprintf(stderr, "forward_packet_using_raw returned %d\n", n);
	if (scmsgp)
		free(scmsgp);
}

/*
 * Create random source host address and random source port
 */
void
create_white(struct nat_info *ni) {
	SHA256_CTX context;
	u_char more_random[256/8];
	int i;
	int r = white_net_size/8;
	u_char mask = ((1<<r) - 1) << (8-r);	// two-s complement trick to make mask
	assert(r <= 128/8);

	SHA256_Init(&context);
	SHA256_Update(&context, random_buf, sizeof(random_buf));
	read(random_fd, more_random, sizeof(more_random));
	SHA256_Final(random_buf, &context);

	ni->white_src.sin6_family = AF_INET6;
	ni->white_src.sin6_flowinfo = 0;	// XXX from source?
	ni->white_src.sin6_scope_id = raw_inside.interface_index;
	ni->white_src.sin6_len = sizeof(struct sockaddr_in6);

	for (i=0; i<r; i++)
		ni->white_src.sin6_addr.s6_addr[i] = white_net.sin6_addr.s6_addr[i];
	if (mask) {
		ni->white_src.sin6_addr.s6_addr[r] = (white_net.sin6_addr.s6_addr[i] & mask) |
			(random_buf[i] & ~mask);
		i++;
	}
	for (; i<sizeof(struct in6_addr); i++)
		ni->white_src.sin6_addr.s6_addr[i] = random_buf[i];

	ni->white_src.sin6_port = (random_buf[i] << 8) + random_buf[i+1];
	// XXX care about <= 1023?
}

struct ip6_hdr *
find_ipv6_in_ethernet(struct pcap_pkthdr *header, const u_char *packet) {
	struct ether_header *eh = (struct ether_header *) packet;
	struct ip6_hdr *iph;

	if (header->len != header->caplen) {
		stat_caplen_err++;
		return 0;
	}

	if (ntohs(eh->ether_type) != ETHERTYPE_IPV6) {
		stat_enot_ip++;
		return 0;
	}

	if (header->caplen <= ETHER_HDR_LEN) {
		stat_etooshort++;
		return 0;
	}

	iph = (struct ip6_hdr *)&packet[ETHER_HDR_LEN];
	if ((iph->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION) {
		stat_notipv6++;
		return 0;
	}

#ifdef notdef
	if (ntohs(iph->ip6_plen) > header->caplen - ETHER_HDR_LEN) {	// XXX
		fprintf(stderr, "aw: packet truncated\n", );
		stat_trunc = 0;
		return 0;
	}
#endif
	return iph;
}

int
same_network(struct in6_addr *a, struct in6_addr *b, int netbits) {
	int full_bytes = netbits/8;
	int r = (netbits % 8);
	u_char mask = ((1<<r) - 1) << (8-r);	// two-s complement trick to make mask
	return (memcmp(&a->s6_addr[0], &b->s6_addr[0], full_bytes) == 0) &&
		(mask == 0 || (a->s6_addr[full_bytes+1] & mask) == 0);
}

const u_char *packet;

void
process_inside_packet(struct pcap_pkthdr *header) {
	u_char payload[SNAPLEN];
	struct nat_info *ni, findni;
	struct ip6_hdr *iph = find_ipv6_in_ethernet(header, packet);
	if (iph == 0)
		return;

	if (!same_network(&iph->ip6_src, &local_net.sin6_addr, local_net_size)) {
		stat_ff_inside++;
		return;
	}
	if (debug > 1)
		dump_ipv6("inside	", iph);

	findni.hdr = *iph;
	switch (iph->ip6_nxt) {
	case IPPROTO_TCP:
		findni.thdr = *TCPH(iph);
		break;
	case IPPROTO_UDP:
		findni.uhdr = *UDPH(iph);
		break;
	case IPPROTO_ICMPV6:
		findni.ihdr = *ICMPH(iph);
		break;
	default:
		fprintf(stderr, "Oy! An inside proto we don't handle: %d\n",
			iph->ip6_nxt);
		return;
	}
	ni = SPLAY_FIND(insider_tree, &insiders, &findni);
	if (ni == NULL) {
		if (debug > 1)
			fprintf(stderr, "***** new NAT\n");
		ni = (struct nat_info *)malloc(sizeof(struct nat_info));
		assert(ni); //out of memory allocating inside information
		*ni = findni;
		create_white(ni);
		SPLAY_INSERT(insider_tree, &insiders, ni);
		SPLAY_INSERT(white_addr_tree, &white_addrs, ni);
	} else {
		if(debug > 1)
			fprintf(stderr, "existing NAT\n");
	}

	if (debug > 1) {
		fprintf(stderr, "	white %s", dump_6addr(ni->white_src.sin6_addr));
		fprintf(stderr, "  port %d\n", ni->white_src.sin6_port);
	}
	// XXX: assert that source port hasn't changed.

	memcpy(payload, &iph[1], ntohs(iph->ip6_plen));
	switch (iph->ip6_nxt) {
	case IPPROTO_TCP:
		ni->local_src.sin6_port = ntohs(TCPH(payload)->th_sport);
		TCPH(payload)->th_sport = htons(ni->white_src.sin6_port);
		break;
	case IPPROTO_UDP:
		ni->local_src.sin6_port = ntohs(UDPH(payload)->uh_sport);
		UDPH(payload)->uh_sport = htons(ni->white_src.sin6_port);
		break;
	case IPPROTO_ICMPV6:
		// broken
		break;
	default:
		fprintf(stderr, "Oy! An inside proto we don't handle: %d\n",
			iph->ip6_nxt);
		return;
	}
dump_bytes(payload, ntohs(iph->ip6_plen), 40);
fprintf(stderr, "\n");
	forward_packet_using_raw(&raw_white, payload, ntohs(iph->ip6_plen),
//		&ni->white_src.sin6_addr, &iph->ip6_dst, iph->ip6_nxt,
		&iph->ip6_src, &iph->ip6_dst, iph->ip6_nxt,
		raw_white.interface_index);
}

void
process_white_packet(struct pcap_pkthdr *header) {
	u_char payload[SNAPLEN];
	struct nat_info *ni, findni;
	struct ip6_hdr *iph = find_ipv6_in_ethernet(header, packet);
	if (iph == 0)
		return;

	if (same_network(&iph->ip6_src, &local_net.sin6_addr, local_net_size)) {
		stat_ff_outside++;
		return;
	}
	dump_ipv6("white	", iph);

	// find our NAT entry and make sure the response matches

	findni.white_src.sin6_addr = iph->ip6_src;
	ni = SPLAY_FIND(white_addr_tree, &white_addrs, &findni);
	if (ni == NULL) {
		if (debug)
			fprintf(stderr, "***** unknown incoming white address\n");
		stat_unknown_white++;
		return;
	}

	if (iph->ip6_nxt != ni->hdr.ip6_nxt && iph->ip6_nxt != IPPROTO_ICMPV6) {
		if (debug)
			fprintf(stderr, "white packet type doesn't match\n");
		stat_nonmatched_white_proto++;
		return;
	}

	memcpy(payload, &iph[1], ntohs(iph->ip6_plen));
	switch (iph->ip6_nxt) {
	case IPPROTO_TCP:
		if (ntohs(TCPH(payload)->th_dport) != ni->white_src.sin6_port) {
			if (debug)
				fprintf(stderr,
					"white packet TCP port doesn't match\n");
			stat_nonmatched_white_tcp++;
			return;
		}
		TCPH(payload)->th_dport = htons(ni->local_src.sin6_port);
		break;
	case IPPROTO_UDP:
		if (ntohs(UDPH(payload)->uh_dport) != ni->white_src.sin6_port) {
			if (debug)
				fprintf(stderr,
					"white packet UDP port doesn't match\n");
			stat_nonmatched_white_udp++;
			return;
		}
		UDPH(payload)->uh_dport = htons(ni->local_src.sin6_port);
		break;
	case IPPROTO_ICMPV6:
		// broken
		break;
	default:
		fprintf(stderr, "Oy! An outside proto we don't handle: %d\n",
			iph->ip6_nxt);
		return;
	}

	forward_packet_using_raw(&raw_inside, payload, ntohs(iph->ip6_plen),
		&iph->ip6_src, &ni->hdr.ip6_src, iph->ip6_nxt,
		raw_inside.interface_index);
}


pcap_t *
create_pcap(const char *interface, char *program) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *p;
	struct bpf_program *pgm =
		(struct bpf_program *)malloc(sizeof(struct bpf_program));

	errbuf[0] = '\0';
	p = pcap_create(interface, errbuf);
	if (p == NULL) {
		fprintf(stderr, "aw: error opening IF %s: %s\n",
			interface, errbuf);
		exit(10);
	}
	if (strlen(errbuf) != 0)
		fprintf(stderr, "aw: warning opening IF %s: %s\n",
			interface, errbuf);

	if (pcap_set_snaplen(p, SNAPLEN) != 0) {
		pcap_perror(p, "setting snap length");
		fprintf(stderr, "  interface %s\n", interface);
		exit(11);
	}

	if (pcap_set_timeout(p, 1) != 0) {
		pcap_perror(p, "setting read timeout");
		fprintf(stderr, "  interface %s\n", interface);
		exit(12);
	}

	// we shouldn't need to care about promiscuous mode.  We are supposed
	// to process people's packets as a default route, so they should be
	// sending to our Ethernet address(es).

	if (pcap_activate(p) != 0) {
		pcap_perror(p, "activating filter");
		fprintf(stderr, "  interface %s\n", interface);
		exit(13);
	}
	assert(pgm);	// allocating for bpf program
	if (pcap_compile(p, pgm, program, 0, 0) != 0) {
		pcap_perror(p, "aw: compiling filter");
		fprintf(stderr, "  interface %s\n", interface);
		exit(14);
	}
	if (pcap_setfilter(p, pgm) != 0) {
		pcap_perror(p, "aw: setting filter");
		fprintf(stderr, "  interface %s\n", interface);
		exit(15);
	}

	return p;
}

void
finish(void) {
	show_stats();
}

void
interrupt(int i) {
	if (debug)
		fprintf(stderr,
			"\naw interrupt %d, cleaning up and terminating\n", i);
	finish();
	exit(0);
}

int
usage(void) {
	fprintf(stderr, "aw [-d] if_inside inside_net/size if_white outside_net/size\n");
	return 1;
}

int
main(int argc, char *argv[]) {
	char *err;
	char buf[1000];
	int n;

	ARGBEGIN{
	case 'd':
		debug++;
		break;
	default:
		return usage();
	} ARGEND;

	if (argc != 4)
		return usage();

	if_inside = *argv++;
	net_inside = *argv++;
	if_white = *argv++;
	net_white = *argv++;

	err = crack_ipv6_cidr(net_white, &white_net, &white_net_size);
	if (err) {
		fprintf(stderr, "white net format error: %s\n", err);
		exit(2);
	}
	netbits6_to_netmask(&white_net_mask, white_net_size);

	err = crack_ipv6_cidr(net_inside, &local_net, &local_net_size);
	if (err) {
		fprintf(stderr, "local net format error: %s\n", err);
		exit(2);
	}
	netbits6_to_netmask(&local_net_mask, local_net_size);

	if (debug >= 2) {
		fprintf(stderr, "	white net:      %s\n",
			dump_6addr(white_net.sin6_addr));
		fprintf(stderr, "	white net mask: %s\n",
			dump_6addr(white_net_mask));
		fprintf(stderr, "	local net:      %s\n",
			dump_6addr(local_net.sin6_addr));
		fprintf(stderr, "	local net mask: %s\n",
			dump_6addr(local_net_mask));
	}

	snprintf(buf, sizeof(buf),
		"ip6 and src net %s and not dst net %s", net_inside, net_inside);
	p_in = create_pcap(if_inside, buf);
	if (debug > 1)
		fprintf(stderr, " inside filter: %s\n", buf);

	n = snprintf(buf, sizeof(buf),
		"ip6 and dst net %s and not src net %s", net_white, net_white);
	p_out = create_pcap(if_white, buf);
	if (debug > 1)
		fprintf(stderr, " outside filter: %s\n", buf);

	start_random();
	init_raw(&raw_inside, if_inside);
	init_raw(&raw_white, if_white);

	signal(SIGINT, interrupt);

	while (1) {
		int busy = 0;
		struct pcap_pkthdr header;

		packet = pcap_next(p_in, &header);
		if (packet != NULL) {
			process_inside_packet(&header);
			busy = 1;
		}

		packet = pcap_next(p_out, &header);
		if (packet != NULL) {
			process_white_packet(&header);
			busy = 1;
		}

		if (!busy) {
			usleep(1000);
		}
	}

	return 0;
}

