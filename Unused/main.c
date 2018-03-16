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

int debug = 2;

if_info	local_if;
if_info white_if;

void
process_local_packet(int ifd, int ofd) {
	char buf[64000];
	int n;

	n = read(ifd, buf, sizeof(buf));
	if (n < 0) {
		perror("read local");
		fprintf(stderr, "reading packet, error %d\n", n);
		return;
	}
	dump_packet("local read", buf, n);
}

void
process_white_packet(int ifd, int ofd) {
	char buf[64000];
	int n;

	n = read(ifd, buf, sizeof(buf));
	if (n < 0) {
		fprintf(stderr, "reading packet, error %d\n", n);
		perror("read white");
		return;
	}
	dump_packet("white read", buf, n);
}

void
finish(void) {
	close_if(&local_if);
//	close_if(&white_if);
}

void
interrupt(int i) {
	if (debug)
		fprintf(stderr,
			"\naw interrupt %d, cleaning up and terminating\n", i);
	finish();
	exit(99);
}

void
do_inside_packet(struct pcap_pkthdr *header, u_char *packet) {
	fprintf(stderr, "inside %d  %d of %d\n",
		header->len, header->caplen, header->len);
}

void
do_outside_packet(struct pcap_pkthdr *header, u_char *packet) {
	fprintf(stderr, "outside %d  %d of %d\n",
		header->len, header->caplen, header->len);
}


int
usage(void) {
<<<<<<< main.c
	fprintf(stderr, "aw [-d] ext-if-addr ext-net/size int-if-addr/size\n");
=======
	fprintf(stderr, "aw [-d] if_inside if_outside inside_net/size outside_net/size\n");
>>>>>>> 1.4
	return 1;
}

char *local_addr;	// kludgy global: I am in a hurry

char *if_inside;
char *if_outside;
char *net_inside;
char *net_outside;

pcap_t *p_in;
pcap_t *p_out;

struct bpf_program i_pgm, o_pgm;

#define SNAPLEN	65535

int
main(int argc, char *argv[]) {
	char *cp;
	int highfd;
	char *err;
	int arg_errs = 0;
	char *ext_if_name = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	char buf[1000];
	int n;

	ARGBEGIN{
	case 'd':
		debug++;
		break;
	default:
		return usage();
	} ARGEND;

<<<<<<< main.c
	if (arg_errs || argc != 3)
=======
	if (arg_errs || argc != 4)
>>>>>>> 1.4
		return usage();

	if_inside = *argv++;
	if_outside = *argv++;
	net_inside = *argv++;
	net_outside = *argv++;

	errbuf[0] = '\0';
	p_in = pcap_open_live(if_inside, SNAPLEN, 0, 1, &errbuf);
	if (p_in == NULL) {
		fprintf(stderr, "aw: error opening inside IF %s: %s\n",
			if_inside, errbuf);
		exit(2);
	}
	if (strlen(errbuf) != 0)
		fprintf(stderr, "aw: warning opening inside: %s\n", errbuf);

	errbuf[0] = '\0';
	p_out = pcap_open_live(if_outside, SNAPLEN, 0, 1, &errbuf);
	if (p_in == NULL) {
		fprintf(stderr, "aw: error opening outside IF %s: %s\n",
			if_inside, errbuf);
		exit(3);
	}
	if (strlen(errbuf) != 0)
		fprintf(stderr, "aw: warning opening outside: %s\n", errbuf);

	n = snprintf(buf, sizeof(buf),
		"ip6 and src net %s and not dst net %s", net_inside, net_inside);
	if (n + 1 >= sizeof(buf)) {
		fprintf(stderr, "aw: inside filter string too long, aborted\n");
		exit(6);
	}
	if (pcap_compile(p_in, &i_pgm, buf, 0, 0) < 0) {
		pcap_perror(p_in, "aw compiling inside filter");
		exit(6);
	}
	if (pcap_setfilter(p_in, &i_pgm) == -1) {
		pcap_perror(p_in, "aw setting inside filter");
		exit(6);
	}
		
	n = snprintf(buf, sizeof(buf),
		"ip6 and dst net %s and not src net %s", net_outside, net_outside);
	if (n + 1 >= sizeof(buf)) {
		fprintf(stderr, "aw: outside filter string too long, aborted\n");
		exit(7);
	}
	if (pcap_compile(p_out, &o_pgm, buf, 0, 0) < 0) {
		pcap_perror(p_out, "aw compiling outside filter");
		exit(6);
	}
	if (pcap_setfilter(p_out, &i_pgm) == -1) {
		pcap_perror(p_out, "aw setting outside filter");
		exit(6);
	}
	

	if (pcap_activate(p_in) != 0) {
		pcap_perror(p_in, "activating inside filter");
		exit(10);
	}

	if (pcap_activate(p_out) != 0) {
		pcap_perror(p_out, "activating outside filter");
		exit(10);
	}
	
	while (1) {
		int busy = 0;
		int rc;
		struct pcap_pkthdr *header;
		u_char *packet;

		do {	rc = pcap_next_ex(p_in, &header, &packet);
			switch (rc) {
			case -1:
				pcap_perror(p_in, "reading inside packet");
				busy = 1;
				break;
			case 1:
				do_inside_packet(header, packet);
				busy = 1;
				break;
			}
		} while (rc != 0);

		do {	rc = pcap_next_ex(p_out, &header, &packet);
			switch (rc) {
			case -1:
				pcap_perror(p_out, "reading outside packet");
				busy = 1;
				break;
			case 1:
				do_outside_packet(header, packet);
				busy = 1;
				break;
			}
		} while (rc != 0);
		if (!busy)
			usleep(1000);
	}

	return 0;
}
