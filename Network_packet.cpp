 /*

Author : Sakar Koot

TE-A (computer)



 */




 #include<iostream>
 #include<pcap.h>
 #include<netinet/ip.h>
 #include<netinet/tcp.h>
 #include<netinet/in.h>
 #include<net/ethernet.h>
 #include<arpa/inet.h>
 int  choice;
 using namespace std;
 void packet_handler(u_char *userData, const struct pcap_pkthdr * pkthdr, const u_char *packet) {

const struct ether_header* ethernetHeader;
const struct ip* ipHeader;
const struct tcphdr* tcpHeader;
char sourceIp[INET_ADDRSTRLEN];
char destIp[INET_ADDRSTRLEN];
u_int srcport,destport;
u_int len,version,ttl;

ethernetHeader = (struct ether_header*)packet;
if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
    ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    tcpHeader = (struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof(struct ip));
    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
    srcport = ntohs((tcpHeader)->source);
    destport = ntohs((tcpHeader)->dest);

    len = (ipHeader)->ip_hl;
    version= (ipHeader)->ip_v;
    ttl= (ipHeader)->ip_ttl;

    if (ipHeader->ip_p == IPPROTO_TCP) {
        cout << sourceIp <<  " --------------> " << destIp<<":"<<srcport<<"		\t"<<len<<"\t"<<" TCP\t"<<version<<"\t"<<ttl<<endl;
    }

    else if (ipHeader->ip_p == IPPROTO_UDP	) {
        cout << sourceIp <<  " --------------> " << destIp<<":"<<destport<<"	\t"<<len<<"\t"<<" UDP\t"<<version<<"\t"<<ttl<<endl;

}

 }
}
/////////   MAIN METHOD ///////////////
 int main(int argc,char **argv) {
   char *dev;
   pcap_t *descr;
   char errbuf[PCAP_ERRBUF_SIZE];


   dev = pcap_lookupdev(errbuf);

   if (dev == NULL) {
    cout << "pcap_lookupdev() failed: " << errbuf << endl;
    return 1;
  }

   descr=pcap_open_live(dev,BUFSIZ,0,1000, errbuf);

   if (descr == NULL) {
     cout << "pcap_open_live() failed: " << errbuf << endl;

     return 1;
   }else{
   	cout<<"operation sucessful....!";
   }
   cout<<"-----------------------------------------------------------------------------------------------------------------------------------------------------\n\n";
  if (pcap_loop(descr ,-1,packet_handler,NULL) < 0) {
     cout << "Error..!" << endl;
   }
}
