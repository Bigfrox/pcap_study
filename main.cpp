#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>

int main(){

    pcap_if_t *alldevs;
    pcap_if_t * dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle;

    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    struct in_addr addr;
    char *net;
    struct ip *iph;



    int ret = pcap_findalldevs(&alldevs, errbuf);
    printf("return value : %d\n",ret);
    if(alldevs == NULL){
        fprintf(stderr, "can't find default device : %s\n", errbuf);
        return 2;
    }


    printf("device : %s\n", alldevs->name);
    dev = alldevs;

    handle = pcap_open_live(dev->name, BUFSIZ,1,1000,errbuf);
    if(handle == NULL){
        fprintf(stderr, "Could not open device %s: %s\n", dev->name, errbuf);
        return 2;
    }
    if(pcap_datalink(handle) != DLT_EN10MB){
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev->name);
    }

    int ret2;
    ret2 = pcap_lookupnet(dev->name,&netp,&maskp,errbuf);

    if(ret2 == -1){
        printf("%s\n", errbuf);
        return 2;
    }
    addr.s_addr = netp;
    net = inet_ntoa(addr);
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res == 0)    continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            printf("pcap_next_ex return %d(%s)\n",res,pcap_geterr(handle));
            break;
        }
        printf("[%s]\n", net);
        iph = (struct ip *)packet;

        printf("[src addr] %s\n", inet_ntoa(iph->ip_src));
        printf("[dest addr] %s\n", inet_ntoa(iph->ip_dst));
        printf("%u bytes captured\n", header->caplen);
    }
    pcap_close(handle);

    return 0;
}
