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

#define IP_HDR_LEN sizeof(struct iphdr) // Length of ip header
#define TIME_INTERVAL 10                
#define BETA 0.98000
#define ALPHA 0.500000
#define K 4                            
#define HOST_IP "127.0.0.1"
#define PORT 22
#define H 9                             // threshold for CUSUM

// data structure for EWMA algorithm
// Each data is based on Nth time interval 
struct data {
    float ewma;                         // value of EWMA alogorithm
    int packet_count;                   // number of SYN packets
} *cur_data, *prev_data;                // 2 temp data, cuurent and previous

// data structure for CUSUM algorithm, based on EWMA data
struct CUSUM_data{
    float cond;                         // alarm condition
} *cur_cusum_data, *prev_cusum_data;

static int signal_sum = 0;              // alarm condition for EWMA algorithm
static int timer = -1;                  // count of time interval
static unsigned int packet_count = 0;   // SYN packet counts in each time interval

const float var = 5;

pthread_mutex_t lock;

struct detection {
    void (*_init) ();                   // initialize
    void (*_run) ();                    // main function
    void (*_detect) ();                 // detection with EWMA
    void (*_cusum_detect) ();           // detection with CUSUM
};
