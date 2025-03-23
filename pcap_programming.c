#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"
#include <stdlib.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        printf("Packet Captured!\n");

        // Ethernet Header 정보 출력
        printf("Ethernet Header:\n");
        printf("Source MAC: ");
        for (int i = 0; i < 6; i++) {
            printf("%02x:", eth->ether_shost[i]);
        }
        printf("\n");
        printf("Destination MAC: ");
        for (int i = 0; i < 6; i++) {
            printf("%02x:", eth->ether_dhost[i]);
        }
        printf("\n");

        // IP Header 정보 출력
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->iph_sourceip), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->iph_destip), dst_ip, INET_ADDRSTRLEN);
        printf("IP Header:\n");
        printf("Source IP: %s\n", src_ip);
        printf("Destination IP: %s\n", dst_ip);

        // TCP Header 정보 출력
        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));

            printf("TCP Header:\n");
            printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
            printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));

            // Message 출력 (적당한 길이로)
            int payload_len = ntohs(ip->iph_len) - (sizeof(struct ethheader) + (ip->iph_ihl * 4) + TH_OFF(tcp) * 4);
            if (payload_len > 0) {
                printf("Got the TCP Packet\n");
                for (int i = 0; i < payload_len && i < 100; i++) {
                    printf("%c", *(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4) + TH_OFF(tcp) * 4 + i));
                }
                printf("\n");
            }
        }
    }
}


int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0)
    {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // Close the handle
    return 0;
}
