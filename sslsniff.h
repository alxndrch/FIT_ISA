/**
 * @brief Implementace projektu do ISA
 * @file sslsniff.h
 *
 * @author Alexandr Chalupnik <xchalu15@stud.fit.vutbr.cz>
 * @date 20.10 2020
 */

#ifndef FIT_ISA_SSLSNIFFER_H
#define FIT_ISA_SSLSNIFFER_H

#define SUCC 0
#define ERR -1
#define PORT_MAX 65535  //!< maximalni hodnota portu
#define IPV6_HLEN 40  //!< velikost IPv6 hlavicky

typedef enum { IPV4, IPV6 } ip_type;

struct Params{
    char *file;
    char *interface;
    bool help;
};

struct IPs{
    uint32_t ipv4;
    in6_addr ipv6;
};

struct Data{
    time_t sec;
    time_t usec;
    IPs client_ip;
    IPs server_ip;
    uint16_t client_port;
    uint16_t server_port;
    ip_type version;
    std::string sni;
    uint bytes;
    uint packets;
};

std::vector<Data> conn;

/**
 * @brief zpracovani argmumentu
 *
 * @param argc pocet argumentu
 * @param argv argumenty
 * @param params parametry pro beh programu
 * @return ERR v pripade chyby, jinak SUCC
 */
int arg_process(int argc, char** argv, Params &params);

/**
 * @brief zachytavani paketu
 *
 * @param params parametry pro beh
 * @return ERR v pripade chyby, jinak SUCC
 */
int sniff(Params &params);

/**
 * @brief zpracovani paktu a vypis informaci
 *
 * @param user nevyuzite! (nullptr)
 * @param header hlavicka
 * @param packet paket
 */
void process_packet(u_char* user, const pcap_pkthdr* header, const u_char* packet);

/**
 * @brief vypis obsahu paketu
 *
 * @param packet paket
 * @param begin pocatecni byte paketu
 * @param end koncovy byte paketu
 */
void print_packet(const u_char* packet, unsigned begin, unsigned end);

void delete_conn(uint index);

int find_data(in6_addr sip, uint16_t sport, in6_addr dip, uint16_t dport);

void print_conn(time_t sec, time_t usec, uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport);

void print_conn(time_t sec, time_t usec, in6_addr sip, uint16_t sport, in6_addr dip, uint16_t dport);

void init_conn(time_t sec, time_t usec, uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport);

void init_conn(time_t sec, time_t usec, in6_addr sip, uint16_t sport, in6_addr dip, uint16_t dport);



#endif