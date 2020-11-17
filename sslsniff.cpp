/**
 * @brief Implementace projektu do ISA
 * @file sslsniff.cpp
 *
 * @author Alexandr Chalupnik <xchalu15@stud.fit.vutbr.cz>
 * @date 29.10 2020
 */

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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
    /**************************************************************************
     *    Inspirováno z:
     *    Title: Programming with pcap
     *    Author: Tim Carstens
     *    Date: 2020
     *    Availability: https://www.tcpdump.org/pcap.html
     *
    **************************************************************************/

    pcap_t* pcap_handle;  // packet capture handle
    char errbuf[PCAP_ERRBUF_SIZE];  // chybovy vystup
    bpf_program fp{};
    bpf_u_int32 netmask = 0;
    bpf_u_int32 ipaddr = 0;
    char *capture_filter = (char*)"tcp";

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
    pcap_freecode(&fp);

    return SUCC;
}

void process_packet(u_char* user, const pcap_pkthdr* header, const u_char* packet)
{
    tcphdr *tcp_h{};  // hlavicka TCP
    iphdr *ip4_h{};  // hlavicka IPv4 datagramu
    ip6_hdr *ip6_h{};  // hlavicka IPv6 datagramu
    ether_header* eth_h{};  // hlavicka ethernetoveho ramce

    string src_ip;  // zdrojova ip adresa
    string dest_ip;  // cilova ip adresa

    eth_h = (ether_header*)packet;

    // IPv6
    if(ntohs(eth_h->ether_type) == ETHERTYPE_IPV6){
        ip6_h = (ip6_hdr*) (packet + ETH_HLEN);

        char ip[40];
        inet_ntop(AF_INET6, &ip6_h->ip6_src, ip, 40); src_ip = ip;  // zdrojova adresa
        inet_ntop(AF_INET6, &ip6_h->ip6_dst, ip, 40); dest_ip = ip;  // cilova adresa 

        if(ip6_h->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP){
            tcp_h = (tcphdr*) (packet + ETH_HLEN + IPV6_HLEN);
            packet_analyzer(src_ip, dest_ip, tcp_h, header, packet, ETH_HLEN + IPV6_HLEN + tcp_h->doff*4);
        }
    // IPv4
    }else if(ntohs(eth_h->ether_type) == ETHERTYPE_IP){
        ip4_h = (iphdr*) (packet + ETH_HLEN);

        char ip[16];
        inet_ntop(AF_INET, &ip4_h->saddr, ip,16); src_ip = ip;  // zdrojova adresa
        inet_ntop(AF_INET, &ip4_h->daddr, ip,16); dest_ip = ip;  // cilova adresa 

        if(ip4_h->protocol == IPPROTO_TCP){
            tcp_h = (tcphdr*) (packet + ETH_HLEN + ip4_h->ihl*4);
            packet_analyzer(src_ip, dest_ip, tcp_h, header, packet, ETH_HLEN + ip4_h->ihl*4 + tcp_h->doff*4);
        }
    }
}

void packet_analyzer(string src_ip, string dest_ip, tcphdr* tcp, const pcap_pkthdr* header, const u_char* packet, uint8_t payload_offset)
{
    bool FIN_STATE = false;  // pocitadlo FIN flagu, false = nebyl zadny prijat
    
    uint16_t src_port = 0;  // cilovy port
    uint16_t dest_port = 0;  // zdrojovy port

    src_port = ntohs(tcp->th_sport);  // host port 
    dest_port = ntohs(tcp->th_dport);  // server port

    // identifikace spojeni 
    Connection c{.src_ip = src_ip, .dest_ip = dest_ip, .src_port = src_port, .dest_port = dest_port};
            
    if(tcp->syn && !tcp->ack){             
        init_conn(header->ts.tv_sec, header->ts.tv_usec, c);
    }else if(tcp->fin && tcp->ack || tcp->rst){
        FIN_STATE = fin_test(c);

        if(FIN_STATE == true || tcp->rst){
            inc_packet(c);
            print_conn(header->ts.tv_sec, header->ts.tv_usec, c);
        }

    }
    
    if(header->len > ETH_ZLEN && payload_offset != header->len){
        parse_ssl(c, &packet[payload_offset], header->len - payload_offset);
    }
    inc_packet(c);  
}

int find_data(Connection conn)
{
    for(int i = 0; i < active_conns.size(); i++){
        Data c = active_conns[i];
        
        // vyhledani spojeni v aktivnich spojenich (src -> dest)
        if(c.conn.src_ip == conn.src_ip && c.conn.src_port == conn.src_port 
            && c.conn.dest_ip == conn.dest_ip && c.conn.dest_port == conn.dest_port)
                return i;
        // vyhledani spojeni prichazejiciho z dest: (dest -> src)
        if(c.conn.src_ip == conn.dest_ip && c.conn.src_port == conn.dest_port 
            && c.conn.dest_ip == conn.src_ip && c.conn.dest_port == conn.src_port)
                return i;
    }

    return -1;  // nebylo nalezeno zadne odpovidajici spojeni
}

void print_conn(time_t sec, time_t usec, Connection conn)
{
    int active_conn_index = 0;

    if((active_conn_index = find_data(conn)) > -1){

        Data c = active_conns[active_conn_index];

        if(c.TLS_STATE == 2){  // pokud probehlo tls spojeni 
            const tm *p_time = localtime(&c.sec);  // cas paketu
            char timestr[65];  // cas paketu v retezci
            strftime(timestr, sizeof(timestr),"%F %H:%M:%S", p_time);
            printf("%s.%06ld,", timestr, c.usec);
            double time_diff = ((sec - c.sec) * 1000000.0 + (usec - c.usec)) / 1000000.0;

            cout << c.conn.src_ip << ","
                << c.conn.src_port << ","
                << c.conn.dest_ip << ","
                << c.sni << ","
                << c.bytes << ","
                << c.packets << ",";
            
            printf("%06f\n", time_diff);
        }

        active_conns.erase(active_conns.begin()+active_conn_index);  // smazani komunikace ze seznamu
    }
}

void init_conn(time_t sec, time_t usec, Connection conn)
{
    int active_conn_index = 0;

    // pokud spojeni neni mezi aktivnimi, ulozi se 
    if((active_conn_index = find_data(conn)) == -1){
        active_conns.push_back({.sec = sec,
                        .usec = usec, 
                        .conn = conn,
                        .sni = "",
                        .bytes = 0,
                        .packets = 0,
                        .FIN_received = false});
    }else{  // pokud dojde znovu k SYN flagu
        active_conns[active_conn_index].sec = sec;
        active_conns[active_conn_index].usec = usec;
    }
}

void parse_ssl(Connection conn, const u_char *packet, int size)
{
    enum ctype_values : uint8_t { 
        CHANGE_CIPHER_SPEC = 20, ALERT = 21, HANDSHAKE = 22, APPLICATION_DATA = 23
    }; 

    const uint8_t LENGHT_INDEX = 3;
    const uint8_t HANDSHAKE_TYPE_INDEX = 5;

    uint16_t lenght;  // delka v bytech 
    ctype_values content_type;  // typ obsahu (handshake, app. data, alert, ...)
    uint16_t sni_lenght;  // delka sni
    char *sni = nullptr;  // server name indication
    unsigned index = 43;  // index kde je session ID 
    int active_conn_index = 0;  // index do seznamu spojeni
    unsigned handshake_type = 0;
    unsigned extension_lenght = 0;  // delka extension casti
    unsigned extension_type = 0;

    content_type = ctype_values(packet[0]);
    lenght = get_number(packet[LENGHT_INDEX], packet[LENGHT_INDEX+1]);
    if(content_type == HANDSHAKE){
        handshake_type = uint8_t(packet[HANDSHAKE_TYPE_INDEX]);
        if(handshake_type == CLIENT_HELLO){
            index += uint8_t(packet[index]) + UINT8_BYTE;  // + delka session id lenght + byte kde lezi delka
            index += get_number(packet[index], packet[index+1]) + UINT16_BYTE;  // + delka cypher suit lenght + byty kde delka lezi
            index += uint8_t(packet[index]) + UINT8_BYTE;  // + comparison method lenght
            
            extension_lenght = get_number(packet[index], packet[index+1]);
            index += UINT16_BYTE;  // + 2 bajty, kde lezi extension lenght
            while(extension_lenght != 0){
                extension_type = get_number(packet[index], packet[index+1]);
                
                if(extension_type == SERVER_NAME){  // pokud je extension type == server_name
                    index += 7;  // posunuti o 7B z extension type na sni lenght
                    
                    sni_lenght = get_number(packet[index], packet[index+1]);
                    index += UINT16_BYTE;  // posuniti za sni lenght
                    sni = new char[sni_lenght+1];
                    memcpy(sni, &packet[index], sni_lenght);
                    sni[sni_lenght] = '\0';

                    if((active_conn_index = find_data(conn)) > -1){
                        active_conns[active_conn_index].sni = string(sni);
                    }

                    delete [] sni;
                    break;
                }

                index += UINT16_BYTE;  // pokud extension_type != server_name posun na delku dalsiho extenstion
                index += get_number(packet[index], packet[index+1]) + UINT16_BYTE;  // posun o delku extension + 2B na kterych je delka ulozena
                extension_lenght -= (get_number(packet[index], packet[index+1])+4);
            }


        }else if(handshake_type == SERVER_HELLO){
            if((active_conn_index = find_data(conn)) > -1){
                active_conns[active_conn_index].TLS_STATE = 2;
            }
        }
    }else if(content_type == ALERT){
        if((active_conn_index = find_data(conn)) > -1){
            active_conns[active_conn_index].TLS_STATE = 2;
        }
    }

    do{ 
        content_type = ctype_values(packet[0]);
        lenght = get_number(packet[LENGHT_INDEX], packet[LENGHT_INDEX+1]);
        if(content_type < 20 || content_type > 23) break;
        if((active_conn_index = find_data(conn)) > -1){
            active_conns[active_conn_index].bytes += lenght;
        }

        packet = (packet + lenght + 5);  // posunuti se v paketu za zpracovany tls
        size -= (lenght + 5);
    }while(size > 0);

}

void inc_packet(Connection conn)
{
    int active_conn_index = 0;

    if((active_conn_index = find_data(conn)) > -1){
        active_conns[active_conn_index].packets += 1;
    }
}

bool fin_test(Connection conn)
{
    int active_conn_index = 0;
    bool state = false;

    if((active_conn_index = find_data(conn)) > -1){
            state = active_conns[active_conn_index].FIN_received;
            
            // pokud byl odrzen druhy fin, vraci se true 
            if(state == true) return true;
            // pokud byl obdrzen prvni fin, meni se stav
            active_conns[active_conn_index].FIN_received = !state;
    }

    return state;
}

inline int get_number(u_char B1, u_char B2){
    return uint16_t(B1 << 8 | B2);
}