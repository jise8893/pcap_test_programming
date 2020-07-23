#include <pcap.h>
#include <stdio.h>
#include <libnet.h>

void print_payload(pcap_pkthdr * header,const u_char *packet){
    struct payload_data
    {
        uint8_t data[16];
    };

    payload_data * pacdata;
    pacdata=(struct payload_data *)(packet+sizeof(libnet_ethernet_hdr)+sizeof(libnet_ipv4_hdr)+sizeof(libnet_tcp_hdr));
    printf("\n");

int k=sizeof(libnet_ethernet_hdr)+sizeof(libnet_ipv4_hdr)+sizeof(libnet_tcp_hdr);
k=-k+(header->caplen);

//print payload data maximum 16bytes
if(k<16)
{
for(int i=0;i<k;i++){
printf("%02x ",pacdata->data[i]);
}
}
else
    for(int i=0;i<16;i++)
    {
        printf("%02x ",pacdata->data[i]);
    }
};



void print_iphdr(const u_char *packet)
{
struct libnet_ipv4_hdr *iphdr;
iphdr=(struct libnet_ipv4_hdr *)(packet+sizeof(libnet_ethernet_hdr));
printf("\nsource ip address %s",inet_ntoa(iphdr->ip_src));
printf("\ndestination ip address %s",inet_ntoa(iphdr->ip_dst));
};


void print_tcphdr(const u_char *packet)
{
struct libnet_tcp_hdr *tcphdr;
tcphdr=(libnet_tcp_hdr *)(packet+sizeof(libnet_ethernet_hdr)+sizeof(libnet_ipv4_hdr));
printf("\ndestination port : %d source port : %d",ntohs(tcphdr->th_dport),ntohs(tcphdr->th_sport));
};


void print_ethhdr(const u_char * packet)
{
struct libnet_ethernet_hdr *ethhdr;
ethhdr=(struct libnet_ethernet_hdr *)(packet);
printf("destination mac address: ");

for(int i=0; i<ETHER_ADDR_LEN; i++)
{
    printf("%02x ",ethhdr->ether_dhost[i]);
}
printf("\nsorce mac address:");
for(int i=0; i<ETHER_ADDR_LEN; i++)
{
    printf("%02x ",ethhdr->ether_shost[i]);
}

};


int main(int argc, char *argv[])
{
    pcap_t * handle;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[]="tcp";
    bpf_u_int32 net; //ip
    bpf_u_int32 mask;//netmask
    const u_char *packet;
    dev=argv[1];

    //define the device
    if (dev == NULL)
    {
        fprintf(stderr,"Couldn't find network device : %s\n",dev);
        return 2;
    }

    // find the properies for the device
    if (pcap_lookupnet(dev,&net,&mask,errbuf)==-1)
    {
        fprintf(stderr,"Couldn't get netmask for device %s : %s \n",dev,errbuf);
        return 2;
    }
    //handle open
    handle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf);

    // compile and apply filter
    if(pcap_compile(handle,&fp,filter_exp,0,net)==-1)
    {
        fprintf(stderr,"Couldn't parse filter %s :%s",filter_exp,pcap_geterr(handle));
        return 2;
    }
    if(pcap_setfilter(handle,&fp))
    {
            fprintf(stderr,"Couldn't install filter %s: %s",filter_exp,pcap_geterr(handle));
            return 2;
    }


    int res;

    while(true){

      struct pcap_pkthdr * header;
        res = pcap_next_ex(handle,&header,&packet);
        if(res==0) continue;
        if(res ==-1 && res==-2)
        {
            break;
        }
        printf("jacked a packet with length of [%d]\n",header->caplen);

        print_ethhdr(packet); //print ethhdr

        print_iphdr(packet); //print ipheader

        print_tcphdr(packet); //print packet

        print_payload(header,packet); //print payload

        printf("\n\n\n\n\n");

    }


    pcap_close(handle);


}


