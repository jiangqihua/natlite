#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>
#include <pthread.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN	6
#endif

/* Distinguish data from diiferent netwok interfact for futher process */
#define FROM_INT 1 
#define FROM_EXT 2 


/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

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

/* UDP header */
struct sniff_udp {
        u_short uh_sport;               /* source port */
        u_short uh_dport;               /* destination port */
	u_short uh_len;			/* total length */
        u_short uh_sum;                 /* checksum */
};

/* ICMP */
struct sniff_icmp {
	u_char ic_type;		/* type */
	u_char ic_code;		/* code */
	u_short ic_sum;		/* checksum */
	u_short ic_id;		/* identifier */
	u_short ic_seq;		/* sequence number */
};

/* TCP/UDP pseudo header for checksum compution */
struct udp_psd_hdr {
	struct in_addr ph_src;
	struct in_addr ph_dst;
	u_char ph_zero;
	u_char ph_p;
	u_short ph_len;
};

/* NAT map table */
#define MAP_TABLE_SIZE	300
#define MAPPED_ID_OFFSET	60000
struct ip_map_table_node {
	u_char ip_prot_type;		/* TCP? UDP? ICMP? */
	u_short port_num;		/* TCP/UDP port number or ICMP identification number */
	struct in_addr ip_addr;		/* IP address */
	time_t timestamp;		/* timestamp for calculate connection timeout */
	struct hash_table_node *hash_node;
	pthread_mutex_t *hash_list_mutex;
	pthread_rwlock_t rwlock;		/* mutex for access synchronization */
};
static struct ip_map_table_node ip_map_table[MAP_TABLE_SIZE];

/* hash table for fast search ip mapping with ip/port of internal network */
#define HASH_TABLE_SIZE 500	/* the hash size */
#define HASH_DIVISOR 	499	/* a prime number not bigger than hash size, but the closest to it */
struct hash_table_node {
	struct ip_map_table_node *pointer;
	struct hash_table_node *next;
	struct hash_table_node **prev_next;
};
struct hash_table_array_node {
	struct hash_table_node *next;
	pthread_mutex_t mutex;
};
struct hash_table_array_node hash_table[HASH_TABLE_SIZE];
pthread_mutex_t heap_mutex = PTHREAD_MUTEX_INITIALIZER;

#define VSERVER_MAXSIZE	10
struct vserver_list_node {
	u_short vport;
	struct in_addr mip;
	u_short mport;
};
int vserver_size;
struct vserver_list_node vserver_list[VSERVER_MAXSIZE];

static pcap_t *int_if;
static pcap_t *ext_if;
static char *ext_ifname = "eth0";
static char *int_ifname = "vmnet8";
//static char *ext_ip = "192.168.1.102";
static struct in_addr ext_ip;
static struct in_addr int_ip;
static struct in_addr ext_mask;
static struct libnet_ether_addr ext_hwaddr;
static struct libnet_ether_addr int_hwaddr;
static struct in_addr def_gw;

int init_mapping()
{
	int i;
	for (i = 0; i < MAP_TABLE_SIZE; i++) {
		memset(&(ip_map_table[i]), 0, sizeof(struct ip_map_table_node));
		if (pthread_rwlock_init(&(ip_map_table[i].rwlock), NULL) != 0) {
			fprintf(stderr, "Error initialize mutex for map-table\n");
			return(1);
		}
	}
	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		memset(&(hash_table[i]), 0, sizeof(struct hash_table_array_node));
		if (pthread_mutex_init(&(hash_table[i].mutex), NULL) != 0) {
			fprintf(stderr, "Error initialize mutex for hash-table\n");
			return(1);
		}
	}
	for (i = 0; i < VSERVER_MAXSIZE; i++) {
		memset(&(vserver_list[i]), 0, sizeof(struct vserver_list_node));
	}
	return(0);
}

u_int hash_func(u_int ip_prot_type, u_int port_num, u_int ip_addr) 
{
	u_int hash, tmp = 0;

	printf("port_num: %d, ip_addr: %s ", ntohs(port_num), inet_ntoa(*((struct in_addr *)&ip_addr)));
	
	tmp += ip_prot_type << 8;
	tmp += port_num << 16;
	ip_addr ^= tmp;

	hash = ip_addr % HASH_DIVISOR;

	printf("hash: %d\t", hash);
	return hash;
}

int add_mapping(u_char ip_prot_type, u_short port_num, struct in_addr ip_addr, u_short *map_id)
{
	static int next_freenode = 0;

	int i;
	int hash;
	struct hash_table_array_node *hash_list;
	struct hash_table_node **current;
	struct ip_map_table_node *mapping;
	int ret;

	hash= hash_func((u_int)ip_prot_type, (u_int)port_num, *((u_int *)&ip_addr));
	hash_list = &(hash_table[hash]);

	pthread_mutex_lock(&(hash_list->mutex));
	current = &(hash_list->next);
	while (*current) {
		mapping = (*current)->pointer;
		pthread_rwlock_rdlock(&(mapping->rwlock));
		if ((mapping->ip_prot_type == ip_prot_type) &&
			(mapping->port_num == port_num) &&
			(*((u_int *)&(mapping->ip_addr)) == *((u_int *)&ip_addr))) {
			write(1,"exists\t", 7);
			*map_id = ((u_char *)mapping - (u_char *)ip_map_table) / sizeof(struct ip_map_table_node);
			pthread_rwlock_unlock(&(mapping->rwlock));
			pthread_mutex_unlock(&(hash_list->mutex));
			return(1);
		}
		pthread_rwlock_unlock(&(mapping->rwlock));
		if ((*current)->next) {
			current = &((*current)->next);
		} else {
			break;
		}
	}
	pthread_mutex_unlock(&(hash_list->mutex));

	if ((*current = malloc(sizeof(struct hash_table_node))) == NULL) {
		fprintf(stderr, "Error allocate memory, exiting\n");
		exit(0);
	}
	
	printf("create next_freenode: %d\t", next_freenode);
	(*current)->pointer = &(ip_map_table[next_freenode]);
	(*current)->next = NULL;
	(*current)->prev_next = current;
	mapping = (*current)->pointer;

	pthread_rwlock_wrlock(&(mapping->rwlock));
	mapping->ip_prot_type = ip_prot_type;
	mapping->port_num = port_num;
	mapping->ip_addr = ip_addr;
	mapping->hash_node = *current;
	mapping->hash_list_mutex = &(hash_list->mutex);
	mapping->timestamp = time(NULL);
	pthread_rwlock_unlock(&(mapping->rwlock));
	pthread_mutex_unlock(&(hash_list->mutex));
	
	*map_id = next_freenode;
	i = (next_freenode + 1) % MAP_TABLE_SIZE;
	while (1) {
		pthread_rwlock_rdlock(&(ip_map_table[i].rwlock));
		if (ip_map_table[i].ip_prot_type == 0) {
			next_freenode = i;
			pthread_rwlock_unlock(&(ip_map_table[i].rwlock));
			break;
		}
		pthread_rwlock_unlock(&(ip_map_table[i].rwlock));
		i = (i + 1) % MAP_TABLE_SIZE;
	}
	return(0);
}

static inline u_short ip_fast_csum(const void *iph, unsigned int ihl)
{
	unsigned int sum;

	__asm__ __volatile__(
	    "movl (%1), %0	;\n"
	    "subl $4, %2	;\n"
	    "jbe 2f		;\n"
	    "addl 4(%1), %0	;\n"
	    "adcl 8(%1), %0	;\n"
	    "adcl 12(%1), %0	;\n"
"1:	    adcl 16(%1), %0	;\n"
	    "lea 4(%1), %1	;\n"
	    "decl %2		;\n"
	    "jne 1b		;\n"
	    "adcl $0, %0	;\n"
	    "movl %0, %2	;\n"
	    "shrl $16, %0	;\n"
	    "addw %w2, %w0	;\n"
	    "adcl $0, %0	;\n"
	    "notl %0		;\n"
"2:				;\n"
	: "=r" (sum), "=r" (iph), "=r" (ihl)
	: "1" (iph), "2" (ihl)
	: "memory");
	return(sum);
}

static inline u_short udp_fast_csum(const void *phdr, const void *iph, unsigned int ihl)
{
	unsigned int sum;
	int i;
	u_short tmp = 0;

	sum = 0;
	sum += ntohs(*((u_short *)phdr));
	sum += ntohs(*((u_short *)(phdr + 2)));
	sum += ntohs(*((u_short *)(phdr + 4)));
	sum += ntohs(*((u_short *)(phdr + 6)));
	sum += ntohs(*((u_short *)(phdr + 8)));
	sum += ntohs(*((u_short *)(phdr + 10)));
	while (1) {
		sum += ntohs(*((u_short *)iph));
		iph += 2;
		if ((ihl -= 2) == 1) {
			memcpy((u_char *)&tmp, (u_char *)iph, sizeof(u_char));
			sum += ntohs(tmp);
			break;
		} else if (ihl == 0) {
			break;
		}
	}
	sum = *((u_short *)&sum) + *((u_short *)((u_char *)&sum + 2));
	sum = ~sum;
//	printf("fsum: %x\t", sum);
	sum = htons(*((u_short *)&sum));
	return(sum);
}

int get_default_gateway(struct in_addr *gateway)
{
	char line[256];
	int count = 0;
	int best_count = 0;
	u_int lowest_metric = ~0;
	struct in_addr best_gw;
	int np;
	struct in_addr net, mask, gw;
	u_int net_x = 0;
	u_int mask_x = 0;
	u_int gw_x = 0;
	u_int metric = 0;
	
	FILE *fp;
	if ((fp = fopen("/proc/net/route", "r")) == NULL) {
		fprintf(stderr, "Coundn't open route table\n");
		return(1);
	}

	*((u_int *)&best_gw) = 0;
	
	while (fgets(line, sizeof (line), fp) != NULL) {
		if (count) {
		np = sscanf(line, "%*s\t%x\t%x\t%*s\t%*s\t%*s\t%d\t%x",
					&net_x,
					&gw_x,
					&metric,
					&mask_x);
			if (np == 4) {
				*((u_int *)&net) = net_x;
				*((u_int *)&mask) = mask_x;
				*((u_int *)&gw) = gw_x;

	  			if (!(*((u_int *)&net)) && 
					!(*((u_int *)&mask)) &&
					metric < lowest_metric) {
					best_gw = gw;
					lowest_metric = metric;
					best_count = count;
	    			}
			}
		}
		++count;
	}
	fclose (fp);
						
	if (*((u_int *)&best_gw)) { 
		*gateway = best_gw;
		return(0);
	}
	return(1);
}

int get_netmask(char *if_name, struct in_addr *mask)
{
	int sock;
	struct ifconf ifc;
	struct ifreq ifr;
	
	memset((char *)&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		fprintf(stderr, "Error create socket on interface %s\n", if_name);
		return(-1);
	}
	if (ioctl(sock, SIOCGIFNETMASK, &ifr) == -1) {
		fprintf(stderr, "Error ioctl on interface %s\n", if_name);
		close(sock);
		return(-1);
	}
	close(sock);
	memcpy(mask, &(((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr), sizeof(struct in_addr));
	
	return 0;

}

int arp_cache_lookup(struct in_addr *ip, struct ether_addr *ether, char *net_ifname)
{
	int sock;
	struct arpreq ar;
	struct sockaddr_in *sin;
	
	memset((char *)&ar, 0, sizeof(ar));
	strncpy(ar.arp_dev, net_ifname, sizeof(ar.arp_dev));   /* XXX - *sigh* */
	sin = (struct sockaddr_in *)&ar.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = ip->s_addr;
	
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		return (-1);
	}
	if (ioctl(sock, SIOCGARP, (caddr_t)&ar) == -1) {
		close(sock);
		return (-1);
	}
	close(sock);
	memcpy(ether->ether_addr_octet, ar.arp_ha.sa_data, ETHER_ADDR_LEN);
	
	return (0);
}

int arp_force(struct in_addr *dst)
{
	struct sockaddr_in sin;
	int i, fd;
	
	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		return (0);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = dst->s_addr;
	sin.sin_port = htons(67);
	
	i = sendto(fd, NULL, 0, 0, (struct sockaddr *)&sin, sizeof(sin));
	
	close(fd);
	
	return (i == 0);
}

int arp_find(struct in_addr *ip, struct ether_addr *mac, char* net_ifname)
{
	int i = 0;
	int result;
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
		
	do {
	//	if(pthread_mutex_trylock(&mutex) == EBUSY)
	//		goto sleep;
		result = arp_cache_lookup(ip, mac, net_ifname);
		if (result == 0)
			return (1);


	//	pthread_mutex_unlock(&mutex);
		arp_force(ip);

sleep:		sleep(1);
	} while (i++ < 3);

	return (0);
}



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

//	static int count = 1;                   /* packet counter */
	char errbuf[PCAP_ERRBUF_SIZE];
	/* declare pointers to packet headers */
	struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	struct sniff_ip *ip;              /* The IP header */
	struct sniff_tcp *tcp;            /* The TCP header */
	struct sniff_udp *udp;		  /* The UDP header */
	struct sniff_icmp *icmp;	  /* The ICMP payload */
	char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_udp;
	int size_payload;
	int size_icmp;

	u_short mapped_id;
	u_short net_mapped_id;
	int has_mapped;

	struct udp_psd_hdr phdr_buf;
	u_short t_sum;
	int num;

	pcap_t *to_if;
	char *net_ifname;
	struct ether_addr dst_hwaddr, src_hwaddr;
	struct in_addr *real_dst;
	u_short *sport, *dport;

	int i;
	int vserver_flag;
	struct vserver_list_node *vserver_entry;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
//		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	
	/* define interface ip address and hardware address */
	if (args == (void *)FROM_EXT) {
		to_if = int_if;
		net_ifname = int_ifname;
		memcpy((u_char *)&src_hwaddr, (u_char *)&int_hwaddr, ETHER_ADDR_LEN);
		write(1, "EXT\t", 4);
	} else if (args == (void *)FROM_INT) {
		to_if = ext_if;
		net_ifname = ext_ifname;
		memcpy((u_char *)&src_hwaddr, (u_char *)&ext_hwaddr, ETHER_ADDR_LEN);
		write(1, "INT\t", 4);
	}

	/* does this packet need to be NATed */
	if ((args == (void *)FROM_INT) && (*((u_int *)&(ip->ip_dst)) == *((u_int *)&(int_ip)))) {
		write(1, "terminated\n", 11);
		return;
	} 

	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			write(1, "tcp\t", 4);
			tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = ntohs(ip->ip_len) - size_ip;
			sport = &(tcp->th_sport);
			dport = &(tcp->th_dport);
			break;
		case IPPROTO_UDP:
			write(1, "udp\t", 4);
			udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
			size_udp = ntohs(udp->uh_len);
			sport = &(udp->uh_sport);
			dport = &(udp->uh_dport);
			break;
		case IPPROTO_ICMP:
			write(1, "icm\t", 4);
			icmp = (struct sniff_icmp *)(packet + SIZE_ETHERNET + size_ip);
			size_icmp = ntohs(ip->ip_len) - size_ip;
			sport = dport = &(icmp->ic_id);
			if ((icmp->ic_type != (u_char)0) && (icmp->ic_type != (u_char)8)) {
				printf("terminated\n");
				return;
			}
			break;	
		case IPPROTO_IP:
			return;
		default:
			return;
	}

	
	/* does this packet need to be NATed */
	vserver_flag = 0;
	if (args == (void *)FROM_INT) {
		for (i = 0; i < vserver_size; i++) {
			if ((*sport == vserver_list[i].mport) &&
				(*((u_int *)&(ip->ip_src)) == *((u_int *)&(vserver_list[i].mip)))) {
				vserver_flag = FROM_INT;
				vserver_entry = &(vserver_list[i]);
				goto mapping;
			}
		}	
	} else if (args == (void *)FROM_EXT)  {
		for (i = 0; i < vserver_size; i++) {
			if ((*dport == vserver_list[i].vport) && 
				(*((u_int *)&(ip->ip_dst)) == *((u_int *)&ext_ip))) {
				vserver_flag = FROM_EXT;
				vserver_entry = &(vserver_list[i]);
				goto mapping;
			}
		}	
		if ((ntohs(*dport) < MAPPED_ID_OFFSET)) {
			write(1, "Terminated\n", 11);
			return;
		}
		pthread_rwlock_rdlock(&(ip_map_table[ntohs(*dport) - MAPPED_ID_OFFSET].rwlock));
		if (ip_map_table[ntohs(*dport) - MAPPED_ID_OFFSET].ip_prot_type == 0) {
			pthread_rwlock_unlock(&(ip_map_table[ntohs(*dport) - MAPPED_ID_OFFSET].rwlock));
			write(1, "terminated\n", 11);
			return;
		}
		pthread_rwlock_unlock(&(ip_map_table[ntohs(*dport) - MAPPED_ID_OFFSET].rwlock));
	}

	/* mapping work */
mapping:if (args == (void *)FROM_INT) {
		if (vserver_flag == FROM_INT) {
			printf("Isz:%d,sport:%d,sip:%s\t", vserver_size, ntohs(*sport), inet_ntoa(ip->ip_src));
			memcpy(sport, &(vserver_entry->vport), sizeof(u_short));
		} else {
			has_mapped = add_mapping(ip->ip_p, *sport, ip->ip_src, &mapped_id);
			net_mapped_id = htons(mapped_id + MAPPED_ID_OFFSET);
			printf("mapped_id: %d, net_mapped_id %d\n", mapped_id, net_mapped_id);
			memcpy(sport, &net_mapped_id, sizeof(u_short));
		}
	} else if (args == (void *)FROM_EXT) {
		if (vserver_flag == FROM_EXT) {
			printf("Esz:%d,sport:%d,sip:%s\t", vserver_size, ntohs(*dport), inet_ntoa(ip->ip_dst));
			memcpy(dport, &(vserver_entry->mport), sizeof(u_short));
		} else {
			mapped_id = ntohs(*dport) - MAPPED_ID_OFFSET;
			pthread_rwlock_rdlock(&(ip_map_table[mapped_id].rwlock));
			net_mapped_id = ip_map_table[mapped_id].port_num;
			pthread_rwlock_unlock(&(ip_map_table[mapped_id].rwlock));
			memcpy((dport), &net_mapped_id, sizeof(u_short));
			printf("mapped_id: %d, net_mapped_id %d\n", mapped_id, net_mapped_id);
		}
	}

	
	/* modify src/dst IP address and re-compute IP checksum */
	if (args == (void *)FROM_EXT) {
		if (vserver_flag == FROM_EXT) {
			printf("Emodip:%s\n", inet_ntoa(vserver_entry->mip));
			ip->ip_dst = vserver_entry->mip;	
		} else {
			/*
			 * Why using read lock ? 
			 * This section only touch timestamp, internal interface sniffer thread
			 * wouldn't read or modify it, so no synchronization problem here.
			 * The cleaning thread use "trylock" so it would skip if the mutex is locked.
			 */
			pthread_rwlock_rdlock(&(ip_map_table[mapped_id].rwlock));
			ip->ip_dst = ip_map_table[mapped_id].ip_addr;
			ip_map_table[mapped_id].timestamp = time(NULL);
			if ((ip->ip_p == IPPROTO_TCP) && ((tcp->th_flags & TH_FIN) == TH_FIN)) {
				ip_map_table[mapped_id].timestamp = ~0;
			}
			pthread_rwlock_unlock(&(ip_map_table[mapped_id].rwlock));
		}
	} else if (args == (void *)FROM_INT) {
		memcpy((struct in_addr *)&(ip->ip_src), &ext_ip, sizeof(struct in_addr));
	}
	ip->ip_sum = 0;
	t_sum = ip_fast_csum(ip, IP_HL(ip));
	ip->ip_sum = t_sum;


	/* compute tcp/udp or icmp check sum */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			*((u_int *)&(phdr_buf.ph_src)) = *((u_int *)&(ip->ip_src));	
			*((u_int *)&(phdr_buf.ph_dst)) = *((u_int *)&(ip->ip_dst));	
			phdr_buf.ph_zero = 0;
			phdr_buf.ph_p = ip->ip_p;
			phdr_buf.ph_len = htons(size_tcp);
			tcp->th_sum = 0;
//			printf("len: %d\t", size_udp);
			t_sum = udp_fast_csum(&phdr_buf, tcp, size_tcp);
			tcp->th_sum = t_sum;
			break;
		case IPPROTO_UDP:
			*((u_int *)&(phdr_buf.ph_src)) = *((u_int *)&(ip->ip_src));	
			*((u_int *)&(phdr_buf.ph_dst)) = *((u_int *)&(ip->ip_dst));	
			phdr_buf.ph_zero = 0;
			phdr_buf.ph_p = ip->ip_p;
			phdr_buf.ph_len = udp->uh_len;
			udp->uh_sum = 0;
//			printf("len: %d\t", size_udp);
			t_sum = udp_fast_csum(&phdr_buf, udp, size_udp);
			udp->uh_sum = t_sum;
			break;
		case IPPROTO_ICMP:
			icmp->ic_sum = 0;
			t_sum = ip_fast_csum(icmp, size_icmp / 4 + ((size_icmp % 4) ? 1 : 0));
			icmp->ic_sum = t_sum;
			break;	
		case IPPROTO_IP:
			return;
		default:
			return;
	}
	
	/* modify src/dst ethernet hardware address */
	if (args == (void *)FROM_EXT) {
		real_dst = &(ip->ip_dst);
	} else if (args == (void *)FROM_INT) {
		/* determine whether the destination host in local network */
		if((*((u_int *)&(ip->ip_dst)) & *((u_int *)&(ext_mask))) == 
			(*((u_int *)&(ext_ip)) & *((u_int *)&(ext_mask)))) {
			real_dst = &(ip->ip_dst);
		} else {
			real_dst = &def_gw;
		}
	}
	if (arp_find(real_dst, &dst_hwaddr, net_ifname) == 0) {
		fprintf(stderr, "Couldn't find MAC address for host %s\n", inet_ntoa(ip->ip_dst));
		return;
	}
	memcpy((u_char *)(&(ethernet->ether_dhost)), (u_char *)&dst_hwaddr, ETHER_ADDR_LEN); 	
	memcpy((u_char *)(&(ethernet->ether_shost)), (u_char *)&src_hwaddr, ETHER_ADDR_LEN);


	if ((num = pcap_inject(to_if, packet, header->len)) == 0) {
		fprintf(stderr, "Couldn't send packet");
		return;
	}
	return;
	
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	return;
}


int main(int argc, char *argv[])
{


//	find_alldev();
 
	if (init_mapping() == 1) {
		fprintf(stderr, "Couldn't initialize port mapping table\n");
		exit(0);
	}
	if (virtual_server() == 1) {
		fprintf(stderr, "Couldn't initialize virtual server table\n");
		exit(0);
	}
	packet_filter();


}

int find_alldev()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *if_p, *cur_if;
	int i;
	
	if (pcap_findalldevs(&if_p, errbuf) == -1) {
		fprintf(stderr, "Couldn't find all devices: %s\n", errbuf);
		return(2);
	}
	

	printf("%x\n", &i);
	cur_if = if_p;
	while (cur_if != NULL) {	
		printf("%s, %x\n", cur_if->name, cur_if);
		cur_if = cur_if->next;
	}
	
	pcap_freealldevs(if_p);

	return(0);
}

int virtual_server()
{
#define MAXLINE 80
	FILE *fp;
	char *file = "virtualserver.list";
	char buf[MAXLINE];
	int i;
	char vport[5];
	char mip[15];
	char mport[5];
	if ((fp = fopen(file , "r")) == NULL)
		return(1);
	i = 0;
	while (fgets(buf, MAXLINE, fp) != NULL && i < VSERVER_MAXSIZE) {
		sscanf(buf, "%s\t%s\t%s", vport, mip, mport);
		vserver_list[i].vport = htons((u_short)atoi(vport));
		inet_aton(mip, &(vserver_list[i].mip));
		vserver_list[i].mport = htons((u_short)atoi(mport));
		printf("vserver: %d\t%s\t%d\t\n", ntohs(vserver_list[i].vport), 
							inet_ntoa(vserver_list[i].mip),
							ntohs(vserver_list[i].mport));
		i++;
	}	
	fclose(fp);
	vserver_size = i;
	return(0);
}


void *ext_thread(void *arg) 
{
	char filter_exp[40];
	memset(filter_exp, 0, 40);
	strcat(filter_exp, "ip and dst host ");
	strcat(filter_exp, inet_ntoa(ext_ip));


//	char filter_exp[] = "ip and dst host 192.168.1.102";
	
	if(pcap_loop(ext_if, -1, got_packet, (u_char *)FROM_EXT) == -1) {
		fprintf(stderr, "Couldn't  filte packet %s: %s\n", filter_exp, pcap_geterr(ext_if));
	}
	
	pcap_close(ext_if);
}

void *clean_thread(void *arg)
{
#define TIME_OUT	100	
	int i;


	struct hash_table_node *tmp;
	
	while (1) {
		sleep(30);
		printf("sleep_end\n");

		for (i = 0; i < MAP_TABLE_SIZE; ) {
			if (pthread_rwlock_trywrlock(&(ip_map_table[i].rwlock)) == EBUSY) 
				goto next;
			if (ip_map_table[i].ip_prot_type ==  0) 
				goto unlocknext;
			if (((ip_map_table[i].ip_prot_type !=  IPPROTO_TCP) && 
				((time(NULL) -  ip_map_table[i].timestamp) > TIME_OUT)) ||
				 ((ip_map_table[i].ip_prot_type ==  IPPROTO_TCP) && 
				(ip_map_table[i].timestamp == ~0))) {
	
				if (pthread_mutex_trylock(ip_map_table[i].hash_list_mutex) == EBUSY) 
					goto unlocknext;
				tmp = ip_map_table[i].hash_node;
				*(tmp->prev_next) = tmp->next;
				if (tmp->next) {
					tmp->next->prev_next = tmp->prev_next;
				}
				free(tmp);
				pthread_mutex_unlock(ip_map_table[i].hash_list_mutex);
				
				ip_map_table[i].ip_prot_type = 0;
				ip_map_table[i].port_num = 0;
				memset(&(ip_map_table[i].ip_addr), 0, sizeof(struct in_addr));
				ip_map_table[i].hash_node = 0;
				ip_map_table[i].hash_list_mutex = 0;
				ip_map_table[i].timestamp = 0;
				printf("\nremoved an entry %d\n", i);
			}
unlocknext:		pthread_rwlock_unlock(&(ip_map_table[i].rwlock));
next:			i++;
		}	
	}		
}

int packet_filter()
{
	char *dev, *nextdev;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct bpf_program fp;
	char filter_exp[] = "ip and not dst host 172.16.205.1";
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	const u_char *packet;
	libnet_t *int_llif, *ext_llif;
	struct ether_addr *t_hwaddr;
	pthread_t ntid;


/*	if ((dev = pcap_lookupdev(errbuf)) == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);
*/

	if (get_default_gateway(&def_gw) != 0) {
		fprintf(stderr, "Couldn't get default gateway\n");
		return(2);
	}
	printf("gw: %s\n", inet_ntoa(def_gw));

	/* initialize handler/filter for external network interface */
	dev = ext_ifname;
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for the device %s\n", dev);
		return(2);
	}
	printf("net: %s, mask %s\n", inet_ntoa(*(struct in_addr *)&net), inet_ntoa(*(struct in_addr *)&mask));
	if ((ext_if = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev,errbuf);
		return(2);
	}

	if(pcap_compile(ext_if, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(ext_if));
		return(2);
	}
	if(pcap_setfilter(ext_if, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(ext_if));
		return(2);
	}
	if ((ext_llif = libnet_init(LIBNET_LINK, ext_ifname, errbuf)) == 0) {
		fprintf(stderr, "Couldn't open local network interface %s: %s\n", ext_ifname, errbuf);
		return(2);
	}
	if ((*((u_int *)&ext_ip) = libnet_get_ipaddr4(ext_llif)) == -1) {
		fprintf(stderr, "Couldn't get local ip address for %s \n", ext_ifname);
		return(2);
	}
	if ((t_hwaddr = (struct ether_addr *)libnet_get_hwaddr(ext_llif)) == NULL) {
		fprintf(stderr, "Couldn't get local network interface address for %s \n", ext_ifname);
		return(2);
	}
	memcpy((u_char *)&ext_hwaddr, (u_char *)t_hwaddr, ETHER_ADDR_LEN);
	libnet_destroy(ext_llif);
	if (get_netmask(ext_ifname, &ext_mask) == -1) {
		fprintf(stderr, "Couldn't get local netmask for %s \n", ext_ifname);
		return(2);
	}
	printf("ext_ip : %s ", inet_ntoa(ext_ip) );
	printf("ext_ip : %s\n", inet_ntoa(ext_mask));
	
	/* initialize handler/filter for internal network interface */
	dev = int_ifname;
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for the device %s\n", dev);
		return(2);
	}
	printf("net: %s, mask %s\n", inet_ntoa(*(struct in_addr *)&net), inet_ntoa(*(struct in_addr *)&mask));
	if ((int_if = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev,errbuf);
		return(2);
	}

	if(pcap_compile(int_if, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(int_if));
		return(2);
	}
	if(pcap_setfilter(int_if, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(int_if));
		return(2);
	}
	if ((int_llif = libnet_init(LIBNET_LINK, int_ifname, errbuf)) == 0) {
		fprintf(stderr, "Couldn't open local network interface %s: %s\n", int_ifname, errbuf);
		return(2);
	}
	if ((*((u_int *)&int_ip) = libnet_get_ipaddr4(int_llif)) == -1) {
		fprintf(stderr, "Couldn't get local ip address for %s \n", int_ifname);
		return(2);
	}
	if ((t_hwaddr = (struct ether_addr *)libnet_get_hwaddr(int_llif)) == NULL) {
		fprintf(stderr, "Couldn't get local network interface address for %s \n", int_ifname);
		return(2);
	}
	memcpy((u_char *)&int_hwaddr, (u_char *)t_hwaddr, ETHER_ADDR_LEN);
	libnet_destroy(int_llif);

	if (pthread_create(&ntid, NULL, clean_thread, NULL) != 0) {
		fprintf(stderr, "Couldn't create thread\n");
	}
	if (pthread_create(&ntid, NULL, ext_thread, NULL) != 0) {
		fprintf(stderr, "Couldn't create thread\n");
	}
	if(pcap_loop(int_if, -1, got_packet, (void *)FROM_INT) == -1) {
		fprintf(stderr, "Couldn't  filte packet %s: %s\n", filter_exp, pcap_geterr(int_if));
	}

	pcap_close(int_if);
	return(0);
}
