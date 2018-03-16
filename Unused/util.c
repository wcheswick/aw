
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <osreldate.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <sys/sockio.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/queue.h>

#include "aw.h"

#ifdef notdef
char *
satop(struct sockaddr *sa) {
	static char buf[500];

	switch (sa->sa_family) {
	case PF_INET:
		inet_ntop(PF_INET, &sa->sin.sin_addr, buf, sizeof(buf));
		break;
	case PF_INET6:
		inet_ntop(PF_INET6, &sa->sin6.sin6_addr, buf, sizeof(buf));
		break;
	default:
		fprintf(stderr, "gni: sutop, inconceivable family: %d\n",
			sa->sa_family);
		abort();
	}
	return buf;
}
#endif

/*
 * return a string containing the numeric address in the addrinfo
 */
char *
ai_ntos(struct addrinfo *ai) {
	static char buf[NI_MAXHOST];

	getnameinfo(ai->ai_addr, ai->ai_addrlen, buf, sizeof(buf), 0, 0,
		NI_NUMERICHOST);
	return buf;
}

void
dump_ai(struct addrinfo *ai) {
	fprintf(stderr, "dump_ai	flags=  0x%.08x\n", ai->ai_flags);
	fprintf(stderr, "	family= %d\n", ai->ai_family);
	fprintf(stderr, "	socktyp=%d\n", ai->ai_socktype);
	fprintf(stderr, "	proto=  %d\n", ai->ai_protocol);
	fprintf(stderr, "	addrlen=%d\n", ai->ai_addrlen);
	fprintf(stderr, "	canonnm=%s\n", ai->ai_canonname);
	fprintf(stderr, "	value=  %s\n", ai_ntos(ai));
	if (ai->ai_next)
		dump_ai(ai->ai_next);
}

char *
dump_6addr(struct in6_addr a) {
	static char buf[50];

	snprintf(buf, sizeof(buf),
		"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		a.s6_addr[0], a.s6_addr[1], a.s6_addr[2], a.s6_addr[3], 
		a.s6_addr[4], a.s6_addr[5], a.s6_addr[6], a.s6_addr[7],
		a.s6_addr[8], a.s6_addr[9], a.s6_addr[10], a.s6_addr[11], 
		a.s6_addr[12], a.s6_addr[13], a.s6_addr[14], a.s6_addr[15]);
	return buf;
}

void
dump_sin6(struct sockaddr_in6 *s) {
	fprintf(stderr, "	sin6_family = %d\n", s->sin6_family);
	fprintf(stderr, "	sin6_addr = %s\n", dump_6addr(s->sin6_addr));
	fprintf(stderr, "	sin6_port = %d\n", s->sin6_port);
	fprintf(stderr, "	sin6_flowinfo = %d\n", s->sin6_flowinfo);
	fprintf(stderr, "	sin6_scope_id = %d\n", s->sin6_scope_id);
}

char *
show_af(sa_family_t af) {
	static char buf[200];
	switch(af) {
	case AF_INET:	return "AF_INET";
	case AF_INET6:	return "AF_INET6";
	}
	snprintf(buf, sizeof(buf), "af=%d", af);
	return buf;
}

void
dump_sa(struct sockaddr *sa, char *label) {
	fprintf(stderr, "%s:	len = %d, family %s\n", label,
		sa->sa_len, show_af(sa->sa_family));
	switch (sa->sa_family) {
	case AF_INET:
		break;
	case AF_INET6:
		dump_sin6((struct sockaddr_in6 *)sa);
		break;
	default:
		fprintf(stderr, "Other\n");
		break;
	}
}

/*
 * The first parameter is a string containing an IP address.  Crack it and
 * put the results in sa.  Return a non-null error string if there is a problem.
 */
char *
crack_ip(const char *buf, struct sockaddr *sa, int numeric) {
	struct addrinfo hints, *res;
	static char errbuf[200];
	int error;

	if (debug > 1)
		fprintf(stderr, "crack_ip of %s\n", buf);

	if (buf == 0)
		return "missing: empty string";

	memset(&hints, 0, sizeof(hints));
	if (strchr(buf, ':') != 0)
		hints.ai_family = AF_INET6;
	else
		hints.ai_family = AF_INET;
	if (numeric)
		hints.ai_flags = AI_NUMERICHOST;
	hints.ai_socktype = SOCK_DGRAM;
	error = getaddrinfo(buf, 0, &hints, &res);
	if (error) {
		snprintf(errbuf, sizeof(errbuf), "bad address: %s, %s\n",
			buf, gai_strerror(error));
		return errbuf;
	}
	if (res->ai_next) {
		fprintf(stderr,
			"crack_ip: too many answers for address %s, ignoring extras:\n", buf);
		dump_ai(res);
	}
	*(struct sockaddr_storage *)sa = *(struct sockaddr_storage *)res->ai_addr;
	freeaddrinfo(res);
	return 0;
}

char *
crack_cidr(const char *cidr, struct sockaddr *sa, int *netbits) {
	struct cidr *cip;
	sa_family_t af = (strchr(cidr, ':') != 0) ? AF_INET6 : AF_INET;
	char *sp = strchr(cidr, '/');
	struct addrinfo hints, *res;
	int error;
	u_int64_t netsize;

	if (debug > 1)
		fprintf(stderr, "crack_cidr: cracking %s\n", cidr);
	if (sp)
		*sp = '\0';
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_flags = AI_NUMERICHOST;
	hints.ai_socktype = SOCK_DGRAM;		/*dummy*/
	error = getaddrinfo(cidr, 0, &hints, &res);
	if (error) {
		fprintf(stderr, "aw: bad network: %s, %s\n",
			cidr, gai_strerror(error));
		return 0;
	}
	if (res->ai_next) {
		fprintf(stderr, "aw: too many answers, ignoring extras:\n");
		dump_ai(res);
	}

	if (sp) {
		*netbits = atoi(&sp[1]);
		*sp = '/';
	} else
		*netbits = -1;
	*(struct sockaddr_storage *)sa = *(struct sockaddr_storage *)res->ai_addr;
	freeaddrinfo(res);
	return 0;
}

char *
show_ip_proto(u_char pr) {
	static char buf[100];

	switch (pr) {
	case IPPROTO_ICMP:
		return "ICMP";
	case IPPROTO_TCP:
		return "TCP";
	case IPPROTO_UDP:
		return "UDP";
	case IPPROTO_IGMP:
		return "IGMP";
	case IPPROTO_IPV4:
		return "V4overV4";
	case IPPROTO_IPV6:
		return "V6overV4";
	case IPPROTO_ROUTING:
		return "V6 routing header";
	case IPPROTO_FRAGMENT:
		return "V6 fragment";
	case IPPROTO_GRE:
		return "GRE";
	case IPPROTO_ESP:
		return "V6ESP";
	case IPPROTO_AH:
		return "V6auth";
	case IPPROTO_ICMPV6:
		return "ICMP6";
	case IPPROTO_NONE:
		return "V6none";
	case IPPROTO_DSTOPTS:
		return "V6dest";
	case IPPROTO_IPEIP:
		return "IPEIP";
	case IPPROTO_ETHERIP:
		return "IP eth encap";
	default:
		snprintf(buf, sizeof(buf), "ip proto %d", pr);
		return buf;
	}
}

void
netbits_to_netmask(struct sockaddr *sa, sa_family_t af, int netbits) {
	int i;
	u_char *cp;

	sa->sa_family = af;
	switch (af) {
	case AF_INET:
		SIN(sa)->sin_addr.s_addr = ((1LL << netbits) - 1) << (32 - netbits);
		break;
	case AF_INET6:
		cp = (u_char *)&((struct sockaddr_in6 *)sa)->sin6_addr;

		assert(netbits <= 128 && netbits >= 0);	// unexpectedly bad netsize
		for (i=0; i<sizeof(SIN6(sa)->sin6_addr); i++, netbits -= 8) {
			int mask;
			if (netbits >= 8)
				mask = 0xff;
			else if (netbits > 0)
				mask = ((1 << netbits) - 1) << (8 - netbits);
			else
				mask = 0;
			*cp++ = mask;
		}
		sa->sa_len = sizeof(struct sockaddr_in6);
		break;
	default:
		assert(0);	// unexpected address family for netbits_to_netmask
	}
}

void
dump_packet(const char *label, const char *buf, size_t len) {
	struct ip *iph = (struct ip *)buf;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)buf;
	struct sockaddr_storage src, dst;
	int i;


	switch (iph->ip_v) {
	case 4:	
		fprintf(stderr, "%s len=%u  ver=%d  proto=%s\n",
			label, len, iph->ip_v, show_ip_proto(iph->ip_p));
	
//		fprintf(stderr, "         from %s\n", satop(iph->ip_src));
//		fprintf(stderr, "           to %s\n", satop(iph->ip_dst));
		break;
	case 6:
		fprintf(stderr, "%s len=%u  ver=%d  proto=%s\n",
			label, len, iph->ip_v, show_ip_proto(iph->ip_p));
	
		fprintf(stderr, "         from %s\n", dump_6addr(ip6h->ip6_src));
		fprintf(stderr, "           to %s\n", dump_6addr(ip6h->ip6_dst));
		break;
	}


	for (i=0; i<len && i < 30; i++)
		printf("%.02x ", buf[i]&0xff);
	printf("\n");
}

/*
 *                      I N _ C K S U M
 *
 * Checksum routine for Internet Protocol family headers (C Version)
 *
 */
u_short
in_cksum(const u_short *addr, int len) {
	int    nleft = len;
	u_short *w = (u_short *)addr;
	u_short answer;
	int    sum = 0;
	u_short odd_byte = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while ( nleft > 1 )  {
		sum += ntohs(*w++);
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if ( nleft == 1 ) {
		*(u_char * )(&odd_byte) = *(u_char * )w;
		sum += odd_byte << 8;
	}

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return ntohs(answer);
}
