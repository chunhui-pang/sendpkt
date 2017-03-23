#include <stdio.h>
#include<stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include<errno.h>
#include<netinet/udp.h>
#include<netinet/ip.h>
#include <argp.h>
#include <unistd.h>	   

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

enum iter_mode
    {
		ITERATE_CONTINUOUS,
		ITERATE_RANDOM
    };

enum iter_behaviour_mode
    {
		ITERATE_FOREVER,
		ITERATE_ONE_OFF
    };
struct iterator
{
    int cur;
    int size;
    int* item_seq;
    enum iter_mode mode;
    enum iter_behaviour_mode behaviour;
    enum {PORT, IN_ADDR} name; 
    union
	{
	    u_int16_t port;
	    struct in_addr* dst;
	} start;
};

static inline void shuffle(int *array, size_t n)
{
    if (n > 1) 
		{
			size_t i;
			for (i = 0; i < n - 1; i++) 
				{
					size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
					int t = array[j];
					array[j] = array[i];
					array[i] = t;
				}
		}
}
static inline void  INIT_PORT_ITERATOR(struct iterator* it, u_int16_t start, u_int16_t end, enum iter_mode mode, enum iter_behaviour_mode behaviour)
{
    it->cur = 0;
    it->size = end - start;
    it->mode = mode;
    it->behaviour = behaviour;
    it->name = PORT;
    it->start.port = start;
    it->item_seq = (int*)malloc(sizeof(int)*it->size);
    int i =0;
    for(; i < it->size; i++)
		it->item_seq[i] = i;
    if(mode == ITERATE_RANDOM)
		shuffle(it->item_seq, it->size);
}

static inline void INIT_ADDR_ITERATOR(struct iterator* it, struct in_addr* start, int size, enum iter_mode mode, enum iter_behaviour_mode behaviour)
{
    it->cur = 0;
    it->size = size;
    it->mode = mode;
    it->behaviour = behaviour;
    it-> name = IN_ADDR;
    it->start.dst = start;
    it->item_seq = (int*)malloc(sizeof(int)*it->size);
    int i =0;
    for(; i < it->size; i++)
		it->item_seq[i] = i;
    if(mode == ITERATE_RANDOM)
		shuffle(it->item_seq, it->size);
}
#define NEXT_ITEM(it) (it.cur = (++it.cur >= it.size ? (it.behaviour == ITERATE_FOREVER ? (it.mode == ITERATE_RANDOM ? shuffle(it.item_seq, it.size), 0 : 0) : -1) : it.cur))
#define ITEM_VALUE(it) (it.cur == -1 ? 0 : (it.name == PORT ? (it.start.port + it.item_seq[it.cur]) : (it.start.dst + it.item_seq[it.cur])))
#define FREE_ITERATOR(it) (free(it.item_seq))

struct string_list
{
    struct string_list* next;
    char* str;
};

struct send_options
{
    char* interface;
	/* interface would be set to NULL if we need to free src */
	struct in_addr* src;
    unsigned short sport[2];
    enum iter_mode sport_iter;
    unsigned short dport[2];
    enum iter_mode dport_iter;
    struct in_addr* dsts;
    int dst_count;
    enum iter_mode dst_iter;
    char* data;
    unsigned long total_count;
    enum {DELAY_IN_US, DELAY_IN_SECONDS} delay_unit;
    unsigned long delay;
    struct string_list tmp_dsts;
};

static unsigned short csum(unsigned short *ptr,int nbytes);
static int get_ip_addr(char* ifname, struct in_addr* addr);
static error_t parse_opt (int key, char *arg, struct argp_state *state);
static int parse_pair_ushort(char* arg, unsigned short *pair);
static struct string_list* parse_dst_addr(char* arg);

int main(int argc, char* argv[])
{
    /* sendpkt -i eth0 -g a-b -p c-d -d 127.0.0.1 -c total --ga random --pa random --da random */
    static struct argp_option opts_desc[] =
		{
			{"interface", 'i', "eth0", 0, "select an interface"},
			{"ip-source", 'u', "ip source", 0, "the packet's source ip address"},
			{"sports", 'g', "sport", 0, "the source ports. Port ranges like a-b is allowed"},
			{"dports", 'p', "dports", 0, "destination ports. Port ranges like a-b is allowed"},
			{"count",  'c', "count", 0, "the number of packets should be sent"},
			{"delay", 'w', "interval", 0, "the interval between the sending of two packets, suffix us (microseconds), ms (milliseconds), s (seconds), m (minutes), h (hours) are allowed, and default is microseconds"},
			{"sport-select", 's', "continuous", 0, "the selection mode of source ports, continuous or random"},
			{"dport-select", 'd', "random", 0, "the selection mode of destination ports, continous or random"},
			{"dst-select", 't', "random", 0, "the selection mode of destination, continous or random"},
			{"data", 'a', "attached data", 0, "the data content to be sent"},
			{0}
		};
    static char args_doc[] = "destination1 destination2 ...";
    static char doc[] =	"sendpkt -- An utility to send UDP traffic to other hosts";
    static struct argp argp = {opts_desc, parse_opt, args_doc, doc};
    struct send_options options = {
		"eth0",
		NULL,
		{3000, 3001},
		ITERATE_CONTINUOUS,
		{4000, 4001},
		ITERATE_RANDOM,
		NULL,
		0,
		ITERATE_RANDOM,
		"sendpkt program",
		5,
		DELAY_IN_SECONDS,
		1,
		{NULL, NULL}
    };
	argp_parse (&argp, argc, argv, 0, 0, &options);
	fprintf(stdout, "-------options------------\n");
	if(NULL != options.interface){ fprintf(stdout, "  interface: %s\n", options.interface); }
	if(NULL != options.src){       fprintf(stdout, "  ip sources: %s\n", inet_ntoa(*options.src)); }
	fprintf(stdout, "  sports: [%d, %d)\n", options.sport[0], options.sport[1]);
	fprintf(stdout, "  sports mode: %s\n", options.sport_iter == ITERATE_CONTINUOUS ? "continuous":"random");
	fprintf(stdout, "  dports: [%d, %d)\n", options.dport[0], options.dport[1]);
	fprintf(stdout, "  dports mode: %s\n", options.dport_iter == ITERATE_CONTINUOUS ? "continuous":"random");
	fprintf(stdout, "  dst amount: %d\n", options.dst_count);
	int i =0;
	for(i = 0;i < options.dst_count; i++)
		{
			fprintf(stdout, "    %s\n", inet_ntoa(options.dsts[i]));
		}
	fprintf(stdout, "  dst mode: %s\n", options.dst_iter == ITERATE_CONTINUOUS ? "continuous":"random");
	fprintf(stdout, "  send interval: %d %s\n", options.data, options.delay_unit == DELAY_IN_US ? "us" : "s");
	fprintf(stdout, "  payload data: %s\n", options.data);
	fprintf(stdout, "  total amount: %d\n", options.total_count);
    

	struct in_addr ip_src;
	if(NULL == options.src)
		{
			if(get_ip_addr(options.interface, &ip_src) != 1)
				{
					fprintf(stderr, "cannot get the ip address of interface %s!", options.interface);
					exit(1);
				}
			options.src = &ip_src;
		}
    int fd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(fd == -1)
		{
			perror("Failed to create raw socket");
			exit(1);
		}
    
    
    char datagram[4096] , source_ip[32] , *data , *pseudogram;
    memset (datagram, 0, 4096);
    struct iphdr *iph = (struct iphdr *) datagram;
    struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;
    // Initialization
    struct timeval time; 
    gettimeofday(&time,NULL);
    srand((time.tv_sec * 1000) + time.tv_usec);
    data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
    strcpy(data , options.data);
    sin.sin_family = AF_INET;
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
    iph->id = htonl (54321); //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;    
    iph->saddr = options.src->s_addr;
    /* iph->daddr */
    /* udp->source */
    /* udp->dest */
    udph->len = htons(8 + strlen(data)); //tcp header size
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );
    psh.source_address = options.src->s_addr;
    
    int count = 10;
    struct iterator sport_it, dport_it, dst_it;
    long send_count = 0;
    unsigned int (*sleep_fn)(unsigned int) = (options.delay_unit == DELAY_IN_SECONDS ? sleep : usleep);
    for(INIT_PORT_ITERATOR(&sport_it, options.sport[0], options.sport[1], options.sport_iter, ITERATE_FOREVER); send_count < options.total_count; NEXT_ITEM(sport_it))
		{
			u_int16_t sport = ITEM_VALUE(sport_it);
			for(INIT_PORT_ITERATOR(&dport_it, options.dport[0], options.dport[1], options.dport_iter, ITERATE_ONE_OFF); send_count < options.total_count; NEXT_ITEM(dport_it))
				{
					u_int16_t dport = ITEM_VALUE(dport_it);
					if(dport == 0)
						break;
					for(INIT_ADDR_ITERATOR(&dst_it, options.dsts, options.dst_count, options.dst_iter, ITERATE_ONE_OFF); send_count < options.total_count; NEXT_ITEM(dst_it))
						{
							struct in_addr* dest = ITEM_VALUE(dst_it);
							if(dest == NULL)
								break;
							iph->check = 0;      //Set to 0 before calculating checksum
							udph->check = 0; //leave checksum 0 now, filled later by pseudo header
							sin.sin_port = htons(88);
							sin.sin_addr = *dest;
							iph->daddr = sin.sin_addr.s_addr;
							iph->check = csum ((unsigned short *) datagram, iph->tot_len);
							udph->source = htons (sport);
							udph->dest = htons (dport);
							psh.dest_address = sin.sin_addr.s_addr;
							psh.placeholder = 0;
     
							int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
							pseudogram = malloc(psize);
	
							memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
							memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));
	
							udph->check = csum( (unsigned short*) pseudogram , psize);
							if (sendto (fd, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
								{
									perror("sendto failed");
								}
							send_count++;
							sleep_fn(options.delay);
						}
				}
		}
    FREE_ITERATOR(sport_it);
    FREE_ITERATOR(dport_it);
    FREE_ITERATOR(dst_it);
    free(options.dsts);
	if(NULL == options.interface)
		{
			free(options.src);
		}
    return 0;
}

static unsigned short csum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}

static int get_ip_addr(char* ifname, struct in_addr* addr)
{
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if(ioctl(fd, SIOCGIFADDR, &ifr) != 0)
		return 0;
    close(fd);
    *addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
    return 1;
}

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
    struct send_options *opts = state->input;
    int parse_rs;
    char* last;
    enum iter_mode iter_mode;
    struct string_list *node, *tmp;
    int list_length;
    switch ( key )
		{
		case 'i':
			opts->interface = arg;
			break;
		case 'u':
			opts->src = (struct in_addr*)malloc(sizeof(struct in_addr));
			if(-1 == inet_aton(arg, opts->src))
				{
					free(opts->src);
					return ARGP_ERR_UNKNOWN;
				}
			opts->interface = NULL;
			break;
		case 'g':
		case 'p':
			if(key == 'g')
				parse_rs = parse_pair_ushort(arg, opts->sport);
			else
				parse_rs = parse_pair_ushort(arg, opts->dport);
			if(parse_rs == 1)
				{
					return ARGP_ERR_UNKNOWN;
				}
			else if(parse_rs == 2)
				{
					return ARGP_ERR_UNKNOWN;   
				}
			break;
		case 's':
		case 'd':
		case 't':
			if(strcmp(arg, "continuous") == 0)
				iter_mode = ITERATE_CONTINUOUS;
			else if(strcmp(arg, "random") == 0)
				iter_mode = ITERATE_RANDOM;
			else
				return ARGP_ERR_UNKNOWN;
			if(key == 's')
				opts->sport_iter = iter_mode;
			else if(key == 'd')
				opts->dport_iter = iter_mode;
			else if(key == 't')
				opts->dst_iter = iter_mode;
			break;
		case 'c':
			opts->total_count = strtol(arg, &last, 10);
			if(errno == ERANGE || *last != '\0' )
				return ARGP_ERR_UNKNOWN;
			break;
		case 'w':
			opts->delay = strtol(arg, &last, 10);
			if(errno == ERANGE || (*last != '\0' && *last !='u' && *last != 'm' && *last != 's' && *last != 'h'))
				return ARGP_ERR_UNKNOWN;
			if(*last == '\0' || strcmp(last, "us") == 0)
				opts->delay_unit = DELAY_IN_US;
			else if(strcmp(last, "ms") == 0)
				{
					opts->delay *= 1000L;
					opts->delay_unit = DELAY_IN_US;
				}
			else if(strcmp(last, "s") == 0)
				{
					opts->delay_unit = DELAY_IN_SECONDS;
				}
			else if(strcmp(last, "m"))
				{
					opts->delay *= (60L);
					opts->delay_unit = DELAY_IN_SECONDS;
				}
			else if(strcmp(last, "h") == 0)
				{
					opts->delay *= (60L*60L);
					opts->delay_unit = DELAY_IN_SECONDS;
				}
			else
				return ARGP_ERR_UNKNOWN;
			break;
		case 'a':
			opts->data = arg;
			break;
		case ARGP_KEY_NO_ARGS:
			argp_usage (state);
			break;
		case ARGP_KEY_ARG:
			if((node = parse_dst_addr(arg)) != NULL)
				{
					tmp = &(opts->tmp_dsts);
					while(tmp->next != NULL)
						tmp = tmp->next;
					tmp->next = node;
				}
			else
				{
					argp_usage(state);
					return ARGP_ERR_UNKNOWN;
				}
			break;
		case ARGP_KEY_END:
			list_length = 0;
			tmp = &(opts->tmp_dsts);
			while(tmp->next != NULL)
				{
					list_length++;
					tmp = tmp->next;
				}
			opts->dsts = (struct in_addr*)malloc(sizeof(struct in_addr)*list_length);
			list_length = 0;
			tmp = &(opts->tmp_dsts);
			while(tmp->next != NULL)
				{
					opts->dsts[list_length++].s_addr = inet_addr(tmp->next->str);
					tmp = tmp->next;
				}
			tmp = opts->tmp_dsts.next;
			while(tmp != NULL)
				{
					node = tmp;
					tmp = tmp->next;
					free(node->str);
					free(node);
				}
			opts->dst_count = list_length;
			break;
		default:
			return ARGP_ERR_UNKNOWN;
		}
    return 0;
}

static int parse_pair_ushort(char* arg, unsigned short *pair)
{
    char *sep_pos;
    char* last = arg;
    long int r;
    if((sep_pos = strchr(arg, '-')) != NULL)
		{
			r = strtol(arg, &last, 10);
			if(errno == ERANGE || r > 65535 )
				{
					return 1;
				}
			else if(last != sep_pos)
				{
					return 2;
				}
			else
				pair[0] = (unsigned short)r;
			last++;
		}
    r = strtol(last, &last, 10);
    if(errno == ERANGE || r > 65535 )
		{
			return 1;
		}
    else if(*last != '\0')
		{
			return 2;
		}
    else
		pair[1] = (unsigned short)r;
    if(sep_pos == NULL)
	    pair[0] = pair[1];
    pair[1] ++;
    return 0;
}
static struct string_list* parse_dst_addr(char* arg)
{
    unsigned short field[4][2];
    char* p = strtok (arg, ".");
    int i = 0;
    while(p != NULL)
		{
			if(strchr(p, '/') == NULL){
				if(parse_pair_ushort(p, field[i]) != 0)
					return NULL;
				if(field[i][0] > 256 || field[i][0] < 0 || field[i][1] > 256 || field[i][1] < 0)
					return NULL;
			}else{
				if(i != 3)
					return NULL;
				char *start = strchr(p, '/'),
					*last;
				int val = strtol(p, &last, 10);
				if(val < 0 || val > 255 || errno == ERANGE || *last != '/')
					return NULL;
				int prefix = strtol(start+1, &last, 10);
				if(prefix < 0 || prefix > 32 || errno == ERANGE || *last != '\0')
					return NULL;
				if(prefix >= 24)
					{
						field[3][0] = val & (-1 << (32-prefix));
						field[3][1] = (val | (~(-1 << (32-prefix))))+1;
					}
				else if(prefix >= 16)
					{
						field[3][0] = 1, field[3][1] = 256;
						val = field[2][0];
						field[2][0] = val & (-1 << (24-prefix));
						field[2][1] = (val | (~(-1 << (24-prefix))))+1;
					}
				else if(prefix >= 8 )
					{
						field[3][0] = 1, field[3][1] = 256;
						field[2][0] = 1, field[2][1] = 256;
						val = field[1][0];
						field[1][0] = val & (-1 << (16-prefix));
						field[1][1] = (val | (~(-1 << (16-prefix))))+1;
					}
				else
					{
						field[3][0] = 1, field[3][1] = 256;
						field[2][0] = 1, field[2][1] = 256;
						field[1][0] = 1, field[1][1] = 256;
						val = field[0][0];
						field[0][0] = val & (-1 << (8-prefix));
						field[0][1] = (val | (~(-1 << (8-prefix))))+1;
					}
			}
			i++;
			p = strtok(NULL, ".");
		}
    if(i != 4)
		return NULL;
    fprintf(stdout, "[%d, %d).[%d, %d).[%d, %d).[%d, %d)\n", field[0][0], field[0][1],
			field[1][0],field[1][1], field[2][0], field[2][1], field[3][0], field[3][1]);
    int j,k,l;
    struct string_list *node = NULL,
		*head = NULL,
		*tmp = NULL;
    for(i = field[0][0]; i < field[0][1]; i++)
		{
			for(j = field[1][0]; j < field[1][1]; j++)
				{
					for(k = field[2][0]; k < field[2][1]; k++)
						{
							for (l = field[3][0]; l < field[3][1]; l++)
								{
									if(l == 0)
										continue;
									tmp = (struct string_list*)malloc(sizeof(struct string_list));
									tmp->next = NULL;
									tmp->str = (char*)malloc(16);
									sprintf(tmp->str, "%d.%d.%d.%d", i, j, k, l);
									if(node == NULL)
										{
											head = node = tmp;
											node = tmp;					    					}
									else
										{
											node->next = tmp;
											node = tmp;
										}
								}
						}
				}
		}
    return head;
}
