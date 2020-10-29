/**
 * @brief Implementace projektu do ISA
 * @file sslsniff.cpp
 *
 * @author Alexandr Chalupnik <xchalu15@stud.fit.vutbr.cz>
 * @date 20.10 2020
 */

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <getopt.h>
#include <ifaddrs.h>
#include <iostream>
#include <linux/if_ether.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <new>
#include <pcap/pcap.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <vector>

#include "sslsniff.h"

using namespace std;

int main(int argc, char *argv[])
{

    Params par = {.file = nullptr, .interface = nullptr, .help = false};

    if(arg_process(argc, argv, par) == ERR)
        return EXIT_FAILURE;

    if(par.help)
        return EXIT_SUCCESS;
    
    if(sniff(par) == ERR)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

int arg_process(int argc, char** argv, Params &params)
{
    int opt = 0;

    if(argc < 2){
        cerr << "invalid combination of command parameters" << endl;
        return ERR;
    }

    while(1){

        if((opt = getopt(argc, argv, ":r:i:h")) == -1)
            break;

        switch(opt){
            case 'r':
                if(params.file != nullptr || params.interface != nullptr){
                    cerr << "invalid combination of command parameters" << endl;
                    return ERR;
                }
                params.file = optarg;
                break;
            case 'i':
                if(params.interface != nullptr || params.file != nullptr){
                    cerr << "invalid combination of command parameters" << endl;
                    return ERR;
                }
                params.interface = optarg;
                break;
            case 'h':
                if(argc > 2){
                    cerr << "invalid combination of command parameters" << endl;
                    return ERR;
                }

                params.help = true;
                cout << "sudo ./sslsniff [-r <file>] [-i interface] interface [-h]" << endl;
                cout << "-h             help" << endl;
                cout << "-r <file>      pcapng file" << endl;
                cout << "-i interace    active network interface for sniffing" << endl;
                break;
            case ':':
            case '?':
                cerr << "invalid argument" << endl;
                return ERR;
        }
    }

    if(optind < argc){
        cerr << "invalid argument" << endl;
        return ERR;
    }

    return SUCC;
}

int sniff(Params &params)
{

    /***************************************************************************************
     *    Inspirováno z:
     *    Title: Programming with pcap
     *    Author: Tim Carstens
     *    Date: 2020
     *    Availability: https://www.tcpdump.org/pcap.html
     *
    ***************************************************************************************/

    pcap_t* pcap_handle;  // packet capture handle
    char errbuf[PCAP_ERRBUF_SIZE];  // chybovy vystup
    bpf_program fp{};
    bpf_u_int32 netmask = 0;
    bpf_u_int32 ipaddr = 0;
    char *capture_filter = (char*)"tcp port 443";

    if(params.interface){

        // zjisteni masky site
        if (pcap_lookupnet(params.interface, &ipaddr, &netmask, errbuf) == -1) {
            cerr << "Can't get netmask for device" << endl;
            netmask = ipaddr = 0;
        }

        // otevreni zarizeni pro zachytavani
        if((pcap_handle = pcap_open_live(params.interface, BUFSIZ, 1, 1000, errbuf)) == nullptr){
            cerr << errbuf << endl;
            return ERR;
        }

    }else if(params.file){

        // otevreni souboru
        if((pcap_handle = pcap_open_offline(params.file, errbuf)) == nullptr){
            cerr << "Can't open file " << params.file << endl;
            return ERR;
        }
    }

    // zpracovani a overeni filteru
    if(pcap_compile(pcap_handle, &fp, capture_filter, 0, netmask) == PCAP_ERROR){
        cerr << "Couldn't parse filter: " << capture_filter << endl;
        return ERR;
    }

    // nastaveni filteru
    if(pcap_setfilter(pcap_handle, &fp) == PCAP_ERROR){
        cerr << "Couldn't set filter: " << capture_filter << endl;
        return ERR;
    }

    // zachytavani paketu
    if(pcap_loop(pcap_handle, -1, process_packet, nullptr) < 0){
        cerr << "error occured while sniffing packet" << endl;
        return ERR;
    }

    // zavreni zarizeni
    pcap_close(pcap_handle);

    return SUCC;
}

void process_packet(u_char* user, const pcap_pkthdr* header, const u_char* packet)
{
    unsigned header_len = 0;  // celkova velikost hlavicky

    udphdr *udp_h{};  // hlavicka UDP
    tcphdr *tcp_h{};  // hlavicka TCP
    iphdr *ip4_h{};  // hlavicka IPv4 datagramu
    ip6_hdr *ip6_h{};  // hlavicka IPv6 datagramu
    ether_header* eth_h{};  // hlavicka ethernetoveho ramce

    u_int16_t dport = 0;  // cilovy port
    u_int16_t sport = 0;  // zdrojovy port

    hostent *dest_addr = nullptr;  // cilova adresa
    hostent *src_addr = nullptr; // zrojova adresa

    in_addr_t ip = 0;  // pomocna promenna pro vyhodnoceni domenoveho jmena

    eth_h = (ether_header*) (packet);

    if(ntohs(eth_h->ether_type) == ETHERTYPE_IPV6){
        ip6_h = (ip6_hdr*) (packet + ETH_HLEN);

        if(ip6_h->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP){
            tcp_h = (tcphdr*) (packet + ETH_HLEN + IPV6_HLEN);
            sport = ntohs(tcp_h->th_sport);
            dport = ntohs(tcp_h->th_dport);

            if(tcp_h->syn && !tcp_h->ack){             
                init_conn(header->ts.tv_sec, header->ts.tv_usec, ip6_h->ip6_src, sport, ip6_h->ip6_dst, dport);
            }else if(tcp_h->fin && tcp_h->ack){         
                print_conn(header->ts.tv_sec, header->ts.tv_usec, ip6_h->ip6_src, sport, ip6_h->ip6_dst, dport);
            }
        }

        // IPv4
    }else if(ntohs(eth_h->ether_type) == ETHERTYPE_IP){
        ip4_h = (iphdr*) (packet + ETH_HLEN);

        if(ip4_h->protocol == IPPROTO_TCP){
            tcp_h = (tcphdr*) (packet + ETH_HLEN + ip4_h->ihl*4);
            sport = ntohs(tcp_h->th_sport);  // host port 
            dport = ntohs(tcp_h->th_dport);  // server port

            if(tcp_h->syn && !tcp_h->ack){             
                init_conn(header->ts.tv_sec, header->ts.tv_usec, ip4_h->saddr, sport, ip4_h->daddr, dport);
            }else if(tcp_h->fin && tcp_h->ack){         
                print_conn(header->ts.tv_sec, header->ts.tv_usec, ip4_h->saddr, sport, ip4_h->daddr, dport);
            }
        }
    }

}

int find_data(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport)
{
    Data c;
    for(int i = 0; i < conn.size(); i++){
        c = conn[i];
        if(c.client_ip == sip && c.client_port == sport && c.server_ip == dip && c.server_port == dport){
            return i;
        }
    }

    return -1;
}

void delete_conn(uint index)
{
    conn.erase(conn.begin()+index);
}

void print_conn(time_t sec, time_t usec, uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport)
{
    int conn_index = 0;

    if((conn_index = find_data(sip, sport, dip, dport)) > -1){
        char src[16];
        char dest[16];
        
        Data c = conn[conn_index];

        const tm *p_time = localtime(&c.sec);  // cas paketu
        char timestr[20];  // cas paketu v retezci
        strftime(timestr, sizeof(timestr),"%F %H:%M:%S", p_time);
        printf("%s.%03ld,", timestr, c.usec);

        inet_ntop(AF_INET, &c.client_ip, src, 16);
        inet_ntop(AF_INET, &c.server_ip, dest, 16);

        cout << src << ","
             << c.client_port << ","
             << dest << ","
             << c.sni << ","
             << c.bytes << ","
             << c.packets << ",";
            
        if(sec - c.sec == 0) cout << "0";
        else  cout << sec - c.sec;

        cout << "." << usec - c.usec << endl;

        delete_conn(conn_index);
    }
}

void init_conn(time_t sec, time_t usec, uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport)
{
    int conn_index = 0;

    if((conn_index = find_data(sip, sport, dip, dport)) == -1){
        conn.push_back({.sec = sec,
                        .usec = usec, 
                        .client_ip = sip, 
                        .client_port = sport,
                        .server_ip = dip,
                        .server_port = dport, 
                        .sni = "",
                        .bytes = 0,
                        .packets = 0});
    }else{
        conn[conn_index].sec = sec;
        conn[conn_index].usec = usec;
    }
}