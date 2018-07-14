#include "packetdata.h"
#include <iostream>

void L2_MACAddress::print()
{
    std::cout << std::setw(2) << std::setfill('0') << std::hex
              << (int)(unsigned char)b0 << ":"
              << (int)(unsigned char)b1 << ":"
              << (int)(unsigned char)b2 << ":"
              << (int)(unsigned char)b3 << ":"
              << (int)(unsigned char)b4 << ":"
              << (int)(unsigned char)b5;
}

void L2_EthernetFrame::print()
{
    std::cout << "Ethernet frame:" << std::endl;
    std::cout << "   Source MAC: ";
    src.print();
    std::cout << std::endl;
    std::cout << "   Destination MAC: ";
    dst.print();
    std::cout << std::endl;
    std::cout << "   Type: ";
    type.print();
    std::cout << std::endl;
}

void _L3_IPv4Address::print()
{
    std::cout << std::dec << +b0 << "." << +b1 << "." << +b2 << "." << +b3;
}

void L3_IPv4Packet::print()
{
    std::cout << "L3_IPv4Packet::print()" << std::dec << std::endl;
    std::cout << "    Version: " << (unsigned int)(version) << std::endl;
    std::cout << "    IHL: " << (unsigned int)IHL << std::endl;
    std::cout << "    DSCP: " << (unsigned int)DSCP << std::endl;
    std::cout << "    ECN: " << (unsigned int)ECN << std::endl;
    std::cout << "    Total length: " << (unsigned int)total_length << std::endl;
    std::cout << "    Identification: " << (unsigned int)identification << std::endl;
    std::cout << "    Flags: " << (unsigned int)flags << std::endl;
    std::cout << "    Fragment offset: " << (unsigned int)fragment_offset << std::endl;
    std::cout << "    TTL: " << (unsigned int)TTL << std::endl;
    std::cout << "    Protocol: " << "0x" << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)protocol.type << std::dec << std::endl;
    std::cout << "    Checksum: " << "0x" << std::hex << std::setw(4) << std::setfill('0') << header_checksum << std::dec << std::endl;

    std::cout << "    Source address: ";
    src.print();
    std::cout << std::endl;
    std::cout << "    Destination address: ";
    dst.print();
    std::cout << std::endl;
}
