/**
 * @brief Implementace projektu do ISA
 * @file sslsniff.h
 *
 * @author Alexandr Chalupnik <xchalu15@stud.fit.vutbr.cz>
 * @date 29.10 2020
 */

#ifndef FIT_ISA_SSLSNIFFER_H
#define FIT_ISA_SSLSNIFFER_H

#define SUCC 0
#define ERR -1
#define PORT_MAX 65535  //!< maximalni hodnota portu
#define IPV6_HLEN 40  //!< velikost IPv6 hlavicky

#define UINT8_BYTE 1  //!< pocet bajtu v uint8
#define UINT16_BYTE 2  //!< pocet bajtu v uint16
#define UINT32_BYTE 4  //!< pocet bajtu v uint32

#define SERVER_NAME 0  //!< extension type, server_name
#define CLIENT_HELLO 1  //!< tls handshake type, client_hello
#define SERVER_HELLO 2  //!< tls handshake type, server_hello

/**
 * @brief parametry z prikazove radky
 */
struct Params{
    char *file;
    char *interface;
    bool help;
};

/**
 * @brief identifikace spojeni
 */
struct Connection{
    std::string src_ip;  //!< ip adresa klienta
    std::string dest_ip; //!< ip adresa serveru
    uint16_t src_port;  //!< port klienta
    uint16_t dest_port;  //!< port serveru
};

/**
 * @brief data pro vypis 
 */
struct Data{
    time_t sec;  //!< cas v sekundach
    time_t usec;  //!< milisekundy 
    Connection conn;
    std::string sni;  //!< server name indication
    uint bytes;  //!< pocet poslanych bytu
    uint packets;  //!< pocet poslanych paketu
    bool FIN_received;  //! < flag pro obdrzeny FIN flag od serveru
    uint TLS_STATE;  //!< informace o tom v jakem se nachazi TLS handshake dane komunikace
};

std::vector<Data> active_conns;  //!< seznam vsech bezicich spojeni

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
 * @brief analyza tcp segmentu
 * 
 * @param src_ip zdrojova ip adresa
 * @param dest_ip cilova ip adresa
 * @param tcp tcp segment
 * @param header pcap_phthdr hlavicka 
 * @param packet paket
 * @param payload_offset index do dat v tcp segmentu
 */
void packet_analyzer(std::string src_ip, std::string dest_ip, tcphdr* tcp, const pcap_pkthdr* header, const u_char* packet, uint8_t payload_offset);

/**
 * @brief 
 * 
 * @param conn spojeni
 * @return int index do vektoru aktivnich spojeni
 */
int find_data(Connection conn);

/**
 * @brief vypis informaci o ukoncenem spojeni
 * 
 * @param sec sekundy
 * @param usec milisekundy 
 * @param conn spojeni
 */
void print_conn(time_t sec, time_t usec, Connection conn);

/**
 * @brief inicializace spojeni ktere bylo zahajeno
 * 
 * @param sec sekundy
 * @param usec milisekundy
 * @param conn spojeni
 */
void init_conn(time_t sec, time_t usec, Connection conn);

/**
 * @brief zpracovani tls/ssl
 * 
 * @param conn spojeni 
 * @param packet paket
 * @param size velikost dat
 */
void parse_ssl(Connection conn, const u_char *packet, int size);

/**
 * @brief inkrementuje pocet paketu v informaci o spojeni
 * 
 * @param conn spojeni
 */
void inc_packet(Connection conn);

/**
 * @brief testovani fin flagu
 * 
 * @param conn spojeni
 * @return true bylo obdrzeno potvrzeni fin flagu 
 * @return false bly obdrzen prvni fin flag
 */
bool fin_test(Connection conn);

/**
 * @brief prevadi
 * 
 * @param B1 prvni bajt
 * @param B2 druhy bajt
 * @return int cislo
 */
inline int get_number(u_char B1, u_char B2);

#endif