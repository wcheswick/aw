/* Copyright (C) 2010 AT&T Corp. */

#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/queue.h>

#define SA(x) ((struct sockaddr *) &(x))
#define SIN(x) ((struct sockaddr_in *) &(x))
#define SIN6(x) ((struct sockaddr_in6 *) &(x))

struct packet_info {
	struct sockaddr_storage	src;
	struct sockaddr_storage	dst;
	int		af;
	int		ip_proto;
	int		src_port;
	int		dst_port;
} packet_info;

typedef struct if_info {
	int	fd;
	struct sockaddr_storage sa;
	int	netsize;
	char	ifname[IFNAMSIZ];
} if_info;

extern	const struct in6_addr in6mask128;
 
extern	int debug;
extern	char *local_addr;

/* in fbsd.c or linux.c */
extern	void make_if(if_info *ifd);
extern	void close_if(if_info *ifd);

/* in pkt.c */
extern	struct packet_info *get_packet_info(const char *buf, const int n);

/* in util.c */
extern	char *crack_ip(const char *buf, struct sockaddr *sa, int numeric);
extern	char *crack_cidr(const char *cidr, struct sockaddr *sa, int *netbits);
extern	char *crack_ipv6_cidr(const char *buf, struct sockaddr_in6 *in6sa,
		int *netbits);

extern	char *show_ip_proto(u_char pr);
extern	void dump_ai(struct addrinfo *ai);
extern	void dump_sa(struct sockaddr *sa, char *label);
extern	void dump_sin6(struct sockaddr_in6 *s);
extern	char *ai_ntos(struct addrinfo *ai);
extern	char * show_af(sa_family_t af);
extern	void netbits_to_netmask(struct sockaddr *sa, sa_family_t af, int netbits);
extern	void netbits6_to_netmask(struct in6_addr *in6a, int netbits);

extern	void dump_packet(const char *label, const char *buf, size_t len);
extern	u_short in_cksum(const u_short *addr, int len);
extern	char *dump_6addr(struct in6_addr a);

extern	void dump_ipv6(const char *label, struct ip6_hdr *iph);
extern	char *show_proto(int proto);
