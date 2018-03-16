
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
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>

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

char *
show_proto(int proto) {
	static char buf[100];

	switch (proto) {
	case IPPROTO_ICMP:
		return "control message protocol";
	case IPPROTO_TCP:
		return "tcp";
	case IPPROTO_UDP:
		return "user datagram protocol";
	case IPPROTO_HOPOPTS:
		return "IP6 hop-by-hop options";
	case IPPROTO_IGMP:
		return "group mgmt protocol";
	case IPPROTO_GGP:
		return "gateway^2 (deprecated)";
	case IPPROTO_IPV4:
		return "IPv4 encapsulation";
	case IPPROTO_ST:
		return "Stream protocol II";
	case IPPROTO_EGP:
		return "exterior gateway protocol";
	case IPPROTO_PIGP:
		return "private interior gateway";
	case IPPROTO_RCCMON:
		return "BBN RCC Monitoring";
	case IPPROTO_NVPII:
		return "network voice protocol";
	case IPPROTO_PUP:
		return "pup";
	case IPPROTO_ARGUS:
		return "Argus";
	case IPPROTO_EMCON:
		return "EMCON";
	case IPPROTO_XNET:
		return "Cross Net Debugger";
	case IPPROTO_CHAOS:
		return "Chaos";
	case IPPROTO_MUX:
		return "Multiplexing";
	case IPPROTO_MEAS:
		return "DCN Measurement Subsystems";
	case IPPROTO_HMP:
		return "Host Monitoring";
	case IPPROTO_PRM:
		return "Packet Radio Measurement";
	case IPPROTO_IDP:
		return "xns idp";
	case IPPROTO_TRUNK1:
		return "Trunk-1";
	case IPPROTO_TRUNK2:
		return "Trunk-2";
	case IPPROTO_LEAF1:
		return "Leaf-1";
	case IPPROTO_LEAF2:
		return "Leaf-2";
	case IPPROTO_RDP:
		return "Reliable Data";
	case IPPROTO_IRTP:
		return "Reliable Transaction";
	case IPPROTO_TP:
		return "tp-4 w/ class negotiation";
	case IPPROTO_BLT:
		return "Bulk Data Transfer";
	case IPPROTO_NSP:
		return "Network Services";
	case IPPROTO_INP:
		return "Merit Internodal";
	case IPPROTO_SEP:
		return "Sequential Exchange";
	case IPPROTO_3PC:
		return "Third Party Connect";
	case IPPROTO_IDPR:
		return "InterDomain Policy Routing";
	case IPPROTO_XTP:
		return "XTP";
	case IPPROTO_DDP:
		return "Datagram Delivery";
	case IPPROTO_CMTP:
		return "Control Message Transport";
	case IPPROTO_TPXX:
		return "TP++ Transport";
	case IPPROTO_IL:
		return "IL transport protocol";
	case IPPROTO_IPV6:
		return "IP6 header";
	case IPPROTO_SDRP:
		return "Source Demand Routing";
	case IPPROTO_ROUTING:
		return "IP6 routing header";
	case IPPROTO_FRAGMENT:
		return "IP6 fragmentation header";
	case IPPROTO_IDRP:
		return "InterDomain Routing";
	case IPPROTO_RSVP:
		return "resource reservation";
	case IPPROTO_GRE:
		return "General Routing Encap.";
	case IPPROTO_MHRP:
		return "Mobile Host Routing";
	case IPPROTO_BHA:
		return "BHA";
	case IPPROTO_ESP:
		return "IP6 Encap Sec. Payload";
	case IPPROTO_AH:
		return "IP6 Auth Header";
	case IPPROTO_INLSP:
		return "Integ. Net Layer Security";
	case IPPROTO_SWIPE:
		return "IP with encryption";
	case IPPROTO_NHRP:
		return "Next Hop Resolution";
	case IPPROTO_MOBILE:
		return "IP Mobility";
	case IPPROTO_TLSP:
		return "Transport Layer Security";
	case IPPROTO_SKIP:
		return "SKIP";
	case IPPROTO_ICMPV6:
		return "ICMP6";
	case IPPROTO_NONE:
		return "IP6 no next header";
	case IPPROTO_DSTOPTS:
		return "IP6 destination option";
	case IPPROTO_AHIP:
		return "any host internal protocol";
	case IPPROTO_CFTP:
		return "CFTP";
	case IPPROTO_HELLO:
		return "\"hello\" routing protocol";
	case IPPROTO_SATEXPAK:
		return "SATNET/Backroom EXPAK";
	case IPPROTO_KRYPTOLAN:
		return "Kryptolan";
	case IPPROTO_RVD:
		return "Remote Virtual Disk";
	case IPPROTO_IPPC:
		return "Pluribus Packet Core";
	case IPPROTO_ADFS:
		return "Any distributed FS";
	case IPPROTO_SATMON:
		return "Satnet Monitoring";
	case IPPROTO_VISA:
		return "VISA Protocol";
	case IPPROTO_IPCV:
		return "Packet Core Utility";
	case IPPROTO_CPNX:
		return "Comp. Prot. Net. Executive";
	case IPPROTO_CPHB:
		return "Comp. Prot. HeartBeat";
	case IPPROTO_WSN:
		return "Wang Span Network";
	case IPPROTO_PVP:
		return "Packet Video Protocol";
	case IPPROTO_BRSATMON:
		return "BackRoom SATNET Monitoring";
	case IPPROTO_ND:
		return "Sun net disk proto (temp.)";
	case IPPROTO_WBMON:
		return "WIDEBAND Monitoring";
	case IPPROTO_WBEXPAK:
		return "WIDEBAND EXPAK";
	case IPPROTO_EON:
		return "ISO cnlp";
	case IPPROTO_VMTP:
		return "VMTP";
	case IPPROTO_SVMTP:
		return "Secure VMTP";
	case IPPROTO_VINES:
		return "Banyon VINES";
	case IPPROTO_TTP:
		return "TTP";
	case IPPROTO_IGP:
		return "NSFNET-IGP";
	case IPPROTO_DGP:
		return "dissimilar gateway prot.";
	case IPPROTO_TCF:
		return "TCF";
	case IPPROTO_IGRP:
		return "Cisco/GXS IGRP";
	case IPPROTO_OSPFIGP:
		return "OSPFIGP";
	case IPPROTO_SRPC:
		return "Strite RPC protocol";
	case IPPROTO_LARP:
		return "Locus Address Resoloution";
	case IPPROTO_MTP:
		return "Multicast Transport";
	case IPPROTO_AX25:
		return "AX.25 Frames";
	case IPPROTO_IPEIP:
		return "IP encapsulated in IP";
	case IPPROTO_MICP:
		return "Mobile Int.ing control";
	case IPPROTO_SCCSP:
		return "Semaphore Comm. security";
	case IPPROTO_ETHERIP:
		return "Ethernet IP encapsulation";
	case IPPROTO_ENCAP:
		return "encapsulation header";
	case IPPROTO_APES:
		return "any private encr. scheme";
	case IPPROTO_GMTP:
		return "GMTP";
	case IPPROTO_IPCOMP:
		return "payload compression (IPComp)";
	case IPPROTO_SCTP:
		return "SCTP";
	case IPPROTO_PIM:
		return "Protocol Independent Mcast";
	case IPPROTO_CARP:
		return "CARP";
	case IPPROTO_PGM:
		return "PGM";
	case IPPROTO_PFSYNC:
		return "PFSYNC";
	default:
		snprintf(buf, sizeof(buf), "unknown protocol: %d", proto);
		return buf;
	}
}

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
	static char buf[200];

	sa_family_t af = (strchr(cidr, ':') != 0) ? AF_INET6 : AF_INET;
	char *sp = strchr(cidr, '/');
	struct addrinfo hints, *res;
	int error;
	u_int64_t netsize;

	if (debug >= 3)
		fprintf(stderr, "	crack_cidr: cracking %s\n", cidr);
	if (sp)
		*sp = '\0';
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_flags = AI_NUMERICHOST;
	hints.ai_socktype = SOCK_DGRAM;		/*dummy*/
	error = getaddrinfo(cidr, 0, &hints, &res);
	if (error) {
		snprintf(buf, sizeof(buf), "aw: bad network: %s, %s\n",
			cidr, gai_strerror(error));
		return buf;
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
	*sa = *res->ai_addr;
	freeaddrinfo(res);
	return 0;
}

char *
crack_ipv6_cidr(const char *buf, struct sockaddr_in6 *in6sa, int *netbits) {
	struct sockaddr_storage ss;

	char *err = crack_cidr(buf, (struct sockaddr *)&ss, netbits);
	if (err)
		return err;
	if (ss.ss_family != AF_INET6)
		return "Not IPv6 address";
	memcpy(in6sa, &ss, sizeof(struct sockaddr_in6));
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
netbits6_to_netmask(struct in6_addr *in6a, int netbits) {
	int i;
	u_char *cp;

	cp = (u_char *)in6a;

	assert(netbits <= 128 && netbits >= 0);	// unexpectedly bad netsize
	for (i=0; i<sizeof(struct in6_addr); i++, netbits -= 8) {
		int mask;
		if (netbits >= 8)
			mask = 0xff;
		else if (netbits > 0)
			mask = ((1 << netbits) - 1) << (8 - netbits);
		else
			mask = 0;
		*cp++ = mask;
	}
}

#ifdef broken
void
netbits_to_sockaddr(struct sockaddr *sa, sa_family_t af, int netbits) {

	sa->sa_family = af;
	switch (af) {
	case AF_INET:
		SIN(sa)->sin_addr.s_addr = ((1LL << netbits) - 1) << (32 - netbits);
		break;
	case AF_INET6:
		netbits6_to_netmask(&((struct sockaddr_in6 *)sa->sin6_addr), netbits);
		sa->sa_len = sizeof(struct sockaddr_in6);
		break;
	default:
		assert(0);	// unexpected address family for netbits_to_netmask
	}
}
#endif

void
dump_packet(const char *label, const char *buf, size_t len) {
	struct ip *iph = (struct ip *)buf;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)buf;
	struct sockaddr_storage src, dst;
	int i;


	switch (iph->ip_v) {
	case 4:	
		fprintf(stderr, "%s len=%d  ver=%d  proto=%s\n",
			label, (int)len, iph->ip_v, show_ip_proto(iph->ip_p));
	
//		fprintf(stderr, "         from %s\n", satop(iph->ip_src));
//		fprintf(stderr, "           to %s\n", satop(iph->ip_dst));
		break;
	case 6:
		fprintf(stderr, "%s len=%d  ver=%d  proto=%s\n",
			label, (int)len, iph->ip_v, show_ip_proto(iph->ip_p));
	
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


void
dump_ipv6(const char *label, struct ip6_hdr *iph) {
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmp6_hdr *icmp6h;

	fprintf(stderr, "%s	payload len %4d   next hdr %d  hops %d\n",
		label, ntohs(iph->ip6_plen), iph->ip6_nxt, iph->ip6_hops);
	fprintf(stderr, "	%s -> ", dump_6addr(iph->ip6_src));
	fprintf(stderr, "%s\n", dump_6addr(iph->ip6_dst));

	switch (iph->ip6_nxt) {
	case IPPROTO_TCP:
		tcph = (struct tcphdr *)((u_char *)iph + sizeof(struct ip6_hdr));
		fprintf(stderr, "	TCP %hu -> %hu flag %.02x win %hu\n",
			ntohs(tcph->th_sport), ntohs(tcph->th_dport),
			tcph->th_flags, tcph->th_win);
		break;
	case IPPROTO_UDP:
		udph = (struct udphdr *)((u_char *)iph + sizeof(struct ip6_hdr));
		fprintf(stderr, "	UDP %hu -> %hu len %hu\n",
			ntohs(udph->uh_sport), ntohs(udph->uh_dport), ntohs(udph->uh_ulen));
		break;
	case IPPROTO_ICMPV6:
		icmp6h = (struct icmp6_hdr *)((u_char *)iph + sizeof(struct ip6_hdr));
		fprintf(stderr, "	ICMP6 %d,%d   sum %04x\n",
			icmp6h->icmp6_type, icmp6h->icmp6_code, ntohs(icmp6h->icmp6_cksum));
		break;

	case IPPROTO_HOPOPTS:
	case IPPROTO_IPV6:
	case IPPROTO_NONE:
	case IPPROTO_DSTOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_FRAGMENT:
		fprintf(stderr, "	unprocessed IPv6 proto %d\n", iph->ip6_nxt);
		return;
	case IPPROTO_ESP:
		fprintf(stderr, "	unprocessed IPv6 ESP\n");
		return;
	case IPPROTO_AH:
		fprintf(stderr, "	unprocessed IPv6 AH\n");
		return;

	default:
		fprintf(stderr, "	unprocessed other IPPROTO %d\n", iph->ip6_nxt);
		return;
	}

}
