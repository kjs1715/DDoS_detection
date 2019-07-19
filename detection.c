#include "detection.h"

void init() {
    cur_data= (struct data*) malloc(sizeof(struct data));
    prev_data= (struct data*) malloc(sizeof(struct data));
    cur_cusum_data = (struct CUSUM_data*) malloc(sizeof(struct CUSUM_data));
    prev_cusum_data = (struct CUSUM_data*) malloc(sizeof(struct CUSUM_data));

    printf("Initialized..\n");

    // init data
    cur_data->ewma = 0;
    cur_data->packet_count = 0;
    prev_data->ewma = 0;
    prev_data->packet_count = 0;

    cur_cusum_data->cond = 0;
    prev_cusum_data->cond = 0;

    // init mutex
    if (pthread_mutex_init(&lock, NULL)) {
        perror("Mutex init failed...\n");
    }
}

/*
    @usage : analyse all packets which are sent to this host
 */
void *receive() {
    printf("Start receiving...\n");
    int recvfd = -1, recvlen = 0;
    char skbuf[1514];
    struct tcphdr *tcp_recvpkt;    

    memset(skbuf, 0 ,sizeof(skbuf));
    tcp_recvpkt = (struct tcphdr*) malloc(sizeof(struct tcphdr));

    // create socket, cast datagram into tcp header
    if ((recvfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
        perror("Error with recvfd...\n");
    }
    while (1) {
        // receivde packets
        recvlen = recv(recvfd, skbuf, sizeof(skbuf), 0);
        if (recvlen > 0) {
            tcp_recvpkt = (struct tcphdr*) (skbuf + ETHER_HDR_LEN + IP_HDR_LEN);
            // judge syn packet
            if (tcp_recvpkt->syn == 1) {
                pthread_mutex_lock(&lock);
                packet_count++;
                pthread_mutex_unlock(&lock);
            }  
        }
    }
}

/*
    @usage : calculation based on EWMA algorithm
 */
void detect() {
    timer++;
    assert(cur_data);
    assert(prev_data);
    cur_data->packet_count = packet_count;

    // initialize first EWMA variable for accuracy of result
    if (timer == 1) {
        prev_data->ewma = packet_count;
    }

    // bzero count
    packet_count = 0;

    // calculate
    cur_data->ewma = BETA * prev_data->ewma + (1 - BETA) * cur_data->packet_count;
    int signal = cur_data->packet_count >= (ALPHA + 1) * prev_data->ewma ? 1 : 0;
    prev_data->ewma = cur_data->ewma;
    // assert(signal);
    printf("prev_ewma : %f\n", prev_data->ewma);
    printf("Signal : %d\n", signal);
    if (signal) {
        signal_sum += 1;
    } else {
        signal_sum = 0;
    }
    if (timer - K + 1 < 0) {
        printf("Time interval : %d / Signal Sum : %d / Status : Pass\n", timer, signal_sum);
        return ;
    }
    if (signal_sum >= K) {
        printf("Time interval : %d / Signal Sum : %d / Status : SYN Flood Detected\n", timer, signal_sum);
    } else {
        printf("Time interval : %d / Signal Sum : %d / Status : OK\n", timer, signal_sum);
    }
    // printf("%f %d\n", cur_data->ewma, cur_data->packet_count);
}

void run() {
    int seconds = 0, s = -1, recvfd = -1, pd;
    struct sockaddr_in *sa;

    // thread is needed for receiving packets asynchronously
    pthread_t tid;
    pd = pthread_create(&tid, NULL, receive, NULL);
    while(1) {
        // receive();
        sleep(1);
        seconds += 1;
        if (seconds % TIME_INTERVAL == 0) {
            // detect(); 
            cusum_detect();
        }
    }
}

void cusum_detect() {
    timer++;
    assert(cur_data);
    assert(prev_data);
    assert(cur_cusum_data);
    assert(prev_cusum_data);

    cur_data->packet_count = packet_count;

    // initialize first EWMA variable for accuracy of result
    if (timer == 1) {
        prev_data->ewma = packet_count;
    }

    // bzero count
    printf("packet_count : %d\n", cur_data->packet_count);
    packet_count = 0;
    
    // calculate
    cur_data->ewma = BETA * prev_data->ewma + (1 - BETA) * cur_data->packet_count;
    prev_data->ewma = cur_data->ewma;

    cur_cusum_data->cond = prev_cusum_data->cond + (((ALPHA * prev_data->ewma) / var) * (cur_data->packet_count - prev_data->ewma - ALPHA * prev_data->ewma / 2));
    if (cur_cusum_data->cond >= H ) {
        printf("Time interval : %d / Current cusum data : %f / Status : SYN Flood Detected\n", timer, cur_cusum_data->cond);
    } else {
        printf("Time interval : %d / Current cusum data : %f / Status : OK\n", timer, cur_cusum_data->cond);
    }
}

struct detection default_detection = {
    ._init = init,
    ._run = run,
    ._detect = detect,
    ._cusum_detect = cusum_detect,
};


int main(int argc, char const *argv[])
{
    default_detection._init();
    default_detection._run();
}
