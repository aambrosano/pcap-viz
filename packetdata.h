#ifndef PACKETDATA_H
#define PACKETDATA_H

#pragma pack(1)

#include <cstdint>
#include <iostream>
#include <iomanip>      // std::setw
#include <arpa/inet.h>
#include <QString>

typedef struct _L2_MACAddress {
    uint8_t b0, b1, b2, b3, b4, b5;

    char* getVendor() {
        return nullptr;
    }

    void print();
} L2_MACAddress;

enum L2_EtherType : uint16_t {
    IPv4            = 0x0800,
    ARP             = 0x0806,
    WakeOnLan       = 0x0842,
    IETFTrillProto  = 0x22FE,
    // TODO: continue
};

typedef struct _L2_EtherTypeEnumStruct {
    L2_EtherType type;

    void print() {
        std::cout << std::setw(4) << std::setfill('0') << std::hex << htons(type);
    }

    operator L2_EtherType() const {
        return (L2_EtherType)htons(type);
    }
} L2_EtherTypeEnumStruct;

typedef struct _L2_EthernetFrame {
    L2_MACAddress src;
    L2_MACAddress dst;
    L2_EtherTypeEnumStruct type;

    void print();
} L2_EthernetFrame;

typedef struct _L3_IPv4Address {
    uint8_t b0, b1, b2, b3;

    void print();
    bool operator==(const _L3_IPv4Address& other) {
        return b0 == other.b0 && b1 == other.b1 && b2 == other.b2 && b3 == other.b3;
    }
    operator uint32_t() const {
        return ((uint32_t)(b0) << 24) + ((uint32_t)(b1) << 16) + ((uint32_t)(b2) << 8) + b3;
    }

    QString toString() {
        return QString::number(b0) + "." + QString::number(b1) + "." + QString::number(b2) + "." + QString::number(b3);
    }
} L3_IPv4Address;

enum L3_IPv4ProtocolType : uint8_t {
    HOPOPT        = 0x00,
    ICMP          = 0x01,
    // TODO: continue
    TCP           = 0x06,
    UDP           = 0x11,
};

typedef struct _L3_IPv4ProtocolTypeStruct {
    L3_IPv4ProtocolType type;

    void print() {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << type;
    }

    operator L3_IPv4ProtocolType() const {
        return type;
    }
} L3_IPv4ProtocolTypeStruct;

typedef struct _L3_IPv4Packet {
    uint8_t version: 4;
    uint8_t IHL: 4;
    uint8_t DSCP: 6;
    uint8_t ECN: 2;
    uint16_t total_length;
    uint16_t identification;
    uint8_t flags: 3;
    uint16_t fragment_offset: 13;
    uint8_t TTL;
    L3_IPv4ProtocolTypeStruct protocol;
    uint16_t header_checksum;
    L3_IPv4Address src;
    L3_IPv4Address dst;

    void print();
} L3_IPv4Packet;

typedef struct _L3_IPv4PacketOption {
    uint8_t copied: 1;
    uint8_t opt_class: 2;
    uint8_t number: 5;
    uint8_t length;
} L3_IPv4PacketOption;

typedef struct _L4_TCPSegment {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset: 4;
    uint8_t reserved: 3;
    uint8_t flags_NS: 1;
    uint8_t flags_CWR: 1;
    uint8_t flags_ECE: 1;
    uint8_t flags_URG: 1;
    uint8_t flags_ACK: 1;
    uint8_t flags_PSH: 1;
    uint8_t flags_RST: 1;
    uint8_t flags_SYN: 1;
    uint8_t flags_FIN: 1;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;

    void print() {
        std::cout << "L4_TCPSegment::print()" << std::endl;
        std::cout << "    Source port: " << htons(src_port) << std::endl;
        std::cout << "    Destination port: " << htons(dst_port) << std::endl;
        std::cout << "    Seq: " << htonl(seq) << std::endl;
        std::cout << "    Ack: " << htonl(ack) << std::endl;
        std::cout << "    Data offset: " << +data_offset << std::endl;
        std::cout << "    Reserved: " << +reserved << std::endl;
        std::cout << "    Flags: " << (flags_NS ? 'N' : 'n')
                                   << (flags_CWR ? 'C' : 'c')
                                   << (flags_ECE ? 'E' : 'e')
                                   << (flags_URG ? 'U' : 'u')
                                   << (flags_ACK ? 'A' : 'a')
                                   << (flags_PSH ? 'P' : 'p')
                                   << (flags_RST ? 'R' : 'r')
                                   << (flags_SYN ? 'S' : 's')
                                   << (flags_FIN ? 'F' : 'f')
                                   << std::endl;
        std::cout << "    Window size: " << htons(window_size) << std::endl;
        std::cout << "    Checksum: " << std::setw(4) << std::setfill('0') << std::hex << htons(checksum) << std::dec << std::endl;
        std::cout << "    Urgent ptr: " << htons(urgent_ptr) << std::endl;
    };
} L4_TCPSegment;

#endif // PACKETDATA_H
