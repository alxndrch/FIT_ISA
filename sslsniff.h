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
#define UINT8_BYTE 1
#define UINT16_BYTE 2
#define UINT32_BYTE 4

/**
 * @brief parametry z prikazove radky
 */
struct Params{
    char *file;
    char *interface;
    bool help;
};

/**
 * @brief data pro vypis 
 */
struct Data{
    time_t sec;  //!< cas v sekundach
    time_t usec;  //!< milisekundy 
    std::string client_ip;  //!< ip adresa klienta
    std::string server_ip; //!< ip adresa serveru
    uint16_t client_port;  //!< port klienta
    uint16_t server_port;  //!< port serveru
    std::string sni;  //!< server name indication
    uint bytes;  //!< pocet poslanych bytu
    uint packets;  //!< pocet poslanych paketu
};

std::vector<Data> conn;  //!< seznam vsech bezicich spojeni

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

int find_data(std::string sip, uint16_t sport, std::string dip, uint16_t dport);

void print_conn(time_t sec, time_t usec, std::string sip, uint16_t sport, std::string dip, uint16_t dport);

void init_conn(time_t sec, time_t usec, std::string sip, uint16_t sport, std::string dip, uint16_t dport);

void parse_ssl(std::string sip, uint16_t sport, std::string dip, uint16_t dport, const u_char *packet, unsigned size);


#endif