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
#define PORT_MAX 65535

struct Params{
    char *file;
    char *interface;
    bool help;
};

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

#endif
