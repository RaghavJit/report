# report

# NFTABLES

[resources](https://wiki.nftables.org/wiki-nftables/index.php/What_is_nftables%3F)
## Defination
nftables is the successor to iptables, designed to improve Linux firewall management by simplifying rule syntax, reducing code redundancy, and enhancing flexibility. It provides advanced features like better packet classification and dual-stack IPv4/IPv6 support.

### Vs iptables
- **Consolidation of extensions**: Avoids code duplication by providing a unified syntax for all protocols.
- **Efficient Rule Matching**: Faster packet classification with enhanced set/map infrastructure.
- **Dual-Stack Support**: Supports IPv4 and IPv6 in a single table (inet family).
- **Dynamic Ruleset Updates**: Easier to modify rules dynamically.
- **Netlink API**: Enables third-party application integration with Linux networking.

### Demo
Creating **inet** table and **input** chain
```
sudo nft add table inet filter
sudo nft add chain inet filter input { type filter hook input priority 0\; }
```

Adding rules
```
sudo nft add rule inet filter input tcp dport 22 accept # accept ssh traffic
sudo nft add rule inet filter input drop # drop all traffic
```

Usage with nfqueues
```
sudo nft add rule inet filter input ip protocol tcp counter nfqueue num 1
```

## NFQUEUES 

[resources](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/)
### Defination
NFQUEUE is a feature in Linux's netfilter subsystem that allows user-space applications to inspect, modify, or make decisions about network packets. Packets that match specific firewall rules can be sent to a NFQUEUE for user-space processing.

### Use-cases
- **Packet Modification**: Modify packet headers or payloads dynamically.
- **Logging**: Collect detailed packet information without interrupting normal traffic flow.

### lib
```
// Accept packet
nfq_set_verdict(qhandle, packet_id, NF_ACCEPT, 0, nullptr);

// Drop packet
nfq_set_verdict(qhandle, packet_id, NF_DROP, 0, nullptr);
```

## PCAP

### Defination
pcap files store packet capture data, typically from network traffic monitored by tools like Wireshark or tcpdump. The data includes packet-level details, such as source/destination IPs, ports, protocols, and payloads.

### Data Format
Global Header: Metadata about the capture file.
Packet Records: Each packet record includes a timestamp, packet length, and the actual packet data.

### Small Sample
```
d4 c3 b2 a1 02 00 04 00 00 00 00 00 00 00 00 00
ff ff 00 00 01 00 00 00 <... packet data ...>
```

```
#include <pcap.h>

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline("sample.pcap", errbuf);
    struct pcap_pkthdr* header;
    const u_char* packet;

    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        printf("Packet length: %d\n", header->len);
        // Process packet data...
    }

    pcap_close(handle);
    return 0;
}

```
