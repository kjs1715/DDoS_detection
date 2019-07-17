#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <signal.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <net/ethernet.h>

#include <linux/if_ether.h>
// #include <linux/tcp.h>

#define IP_HDR_LEN sizeof(struct iphdr)
#define TIME_INTERVAL 10 // 10 seconds
#define BETA 0.90000
#define ALPHA 0.500000
#define K 3
#define HOST_IP "127.0.0.1"
#define PORT 22

struct data {
    float ewma;
    int packet_count;
} *cur_data, *prev_data;

static int signal_sum = 0;
static int timer = -1;
static unsigned int packet_count = 0;

struct detection {
    void (*_init)();
    void (*_run)();
    void (*_detect)();
};
