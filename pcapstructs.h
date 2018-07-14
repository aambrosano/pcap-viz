#ifndef PCAPSTRUCTS_H
#define PCAPSTRUCTS_H

#pragma pack(1)

#include <cstdint>
#include <cassert>
#include <ctime>
#include <iostream>
#include <cstring>
#include <cctype>
#include <iomanip>      // std::setw

enum PcapBlockType : int32_t {
    InterfaceDescriptionBlock     = 0x00000001,
    PacketBlock                   = 0x00000002,
    SimplePacketBlock             = 0x00000003,
    NameResolutionBlock           = 0x00000004,
    InterfaceStatisticsBlock      = 0x00000005,
    EnhancedPacketBlock           = 0x00000006,
    IRIGTimestampBlock            = 0x00000007,
    ARINC429Block                 = 0x00000008,
    HPMachineInfoBlock            = 0x00000101,
    // TODO: continue ...
    SectionHeaderBlock            = 0x0A0D0D0A
};

typedef struct PcapBlockHeader {
    PcapBlockType block_type;
    uint32_t block_total_length;

    bool is_local_use() {
        return block_type & 0x80000000;
    }

    void print() {
        std::cout << "- Block type: ";
        switch (block_type) {
        case InterfaceDescriptionBlock:
            std::cout << "Interface description block";
            break;
        case PacketBlock:
            std::cout << "Packet block";
            break;
        case SimplePacketBlock:
            std::cout << "Simple packet block";
            break;
        case NameResolutionBlock:
            std::cout << "Name resolution block";
            break;
        case InterfaceStatisticsBlock:
            std::cout << "Interface statistics block";
            break;
        case EnhancedPacketBlock:
            std::cout << "Enhanced packet block";
            break;
        case IRIGTimestampBlock:
            std::cout << "IRIG timestamp block";
            break;
        case ARINC429Block:
            std::cout << "ARINC 429 in AFDX Encapsulation Information block";
            break;
        case HPMachineInfoBlock:
            std::cout << "Hone Project Machine Info block";
            break;
        case SectionHeaderBlock:
            std::cout << "Section header block";
            break;
        default:
        break;
        }
        std::cout << " (" << std::hex << block_type << ")" <<   std::endl;
        std::cout << std::dec << "    - Block total length " << block_total_length << " bytes" << std::endl;
    }
} PcapHeader;

typedef struct PcapSectionHeaderBlockHeader {
    int32_t byte_order_magic;
    int16_t major_version;
    int16_t minor_version;
    int32_t section_length;

    void print() {
        std::cout << "    PcapSectionHeaderBlock::print()" << std::endl;
        std::cout << "    - BOM: " << std::hex << byte_order_magic << std::endl;
        std::cout << "    - Major version: " << major_version << std::endl;
        std::cout << "    - Minor version: " << minor_version << std::endl;
        std::cout << "    - Section length: " << section_length << std::endl;
    }
} PcapSectionHeaderBlockHeader;

struct PcapSectionHeaderBlock {
    PcapSectionHeaderBlockHeader* header;
    char* block_data;

    void print() {
        header->print();
        // TODO: print data
    }
};

typedef struct PcapBlockOptionHeader {
    int16_t option_code;
    int16_t option_length;

    void print() {
        std::cout << "    PcapBlockOptionHeader::print()" << std::endl;
        std::cout << "    - Option code " << option_code << std::endl;
        std::cout << "    - Option length " << option_length << std::endl;
    }
} PcapBlockOptionHeader;

typedef struct PcapBlockOption {
    PcapBlockOptionHeader* header;
    char* option_data;

    void print() {
        header->print();
    }

    static PcapBlockOption* parseBlockOption(char* &buffer) {
        PcapBlockOption* opt = new PcapBlockOption;
        opt->header = (PcapBlockOptionHeader*)buffer;
        opt->option_data = buffer + sizeof(PcapBlockHeader);
        buffer += sizeof(PcapBlockHeader) + opt->header->option_length;
        return opt;
    }
} PcapBlockOption;

typedef struct PcapInterfaceDescriptionBlockHeader {
    int16_t link_type;
    int16_t reserved;
    int32_t snap_len;

    void print() {
        std::cout << "    PcapInterfaceDescriptionBlockHeader::print()" << std::endl;
        std::cout << "    - Link type: " << link_type << std::endl;
        std::cout << "    - Reserved: " << reserved << std::endl;
        std::cout << "    - Snap len: " << snap_len << std::endl;
    }
} PcapInterfaceDescriptionBlockHeader;

typedef struct PcapInterfaceDescriptionBlock {
    PcapInterfaceDescriptionBlockHeader* header;
    char* block_data;

    void print() {
        header->print();
        // TODO: print data
    }
} PcapInterfaceDescriptionBlock;

typedef struct PcapSimplePacketBlockHeader {
    int32_t original_packet_length;

    void print() {
        std::cout << "    PcapSimplePacketBlockHeader::print()" << std::endl;
        std::cout << "    - Original packet length " << original_packet_length << std::endl;
    }
} PcapSimplePacketBlockHeader;

typedef struct PcapSimplePacketBlock {
    PcapSimplePacketBlockHeader* header;
    char* block_data;

    void print() {
        header->print();
    }
} PcapSimplePacketBlock;

typedef struct PcapEnhancedPacketBlockHeader {
    int32_t interface_id;
    int32_t timestamp_high;
    int32_t timestamp_low;
    int32_t captured_packet_len;
    int32_t original_packet_len;

    void print() {
        int64_t timestamp = (((int64_t)(timestamp_high)) << 32) + timestamp_low;
        std::cout << "    PcapEnhancedPacketBlockHeader::print()" << std::endl;
        std::cout << "    - Interface ID: " << interface_id << std::endl;
        std::cout << "    - Timestamp: " << /* std::asctime(std::localtime((time_t*)(&timestamp))) << */ "(" << timestamp << ")" << std::endl;
        std::cout << "    - Captured packet len: " << captured_packet_len << std::endl;
        std::cout << "    - Original packet len: " << original_packet_len << std::endl;
    }
} PcapEnhancedPacketBlockHeader;

typedef struct PcapEnhancedPacketBlock {
    PcapBlockHeader* parentHeader;
    PcapEnhancedPacketBlockHeader* header;
    char* block_data;

    void print() {
        header->print();
        std::cout << "    PcapEnhancedPacketBlock::print()" << std::endl;
        std::cout << "    - Raw data:" << std::endl;

        std::cout << "        " << std::hex;
        for (int i = 0; i < header->captured_packet_len / 16 + ((header->captured_packet_len % 16) ? 1 : 0); ++i) {
            int j = 0;
            for (j = 0; j < 16 && i * 16 + j < header->captured_packet_len; j++) {
                std::cout << std::setw(2) << std::setfill('0') << (int)(unsigned char)block_data[i * 16 + j] << " ";
            }
            for (; j < 16; j++) {
                std::cout << "   ";
            }

            std::cout << "        ";

            for (j = 0; j < 16 && i * 16 + j < header->captured_packet_len; j++) {
                if (isprint(block_data[i * 16 + j]))
                    std::cout << block_data[i * 16 + j] << " ";
                else
                    std::cout << "  ";
            }

            std::cout << std::endl << "        ";
        }
        std::cout << std::endl << std::dec;

        char* buffer = block_data + (size_t)(header->captured_packet_len + ((header->captured_packet_len % 4) ? 4 - header->captured_packet_len % 4 : 0));
        /* std::cout << std::hex << (void*)buffer << " "
                  << (void*)(block_data + (size_t)(parentHeader->block_total_length - sizeof(PcapBlockHeader) - sizeof(PcapEnhancedPacketBlockHeader) - 4)) << " "
                  << (void*)(block_data + header->captured_packet_len) << std::endl; */
        if (buffer != block_data + (size_t)(parentHeader->block_total_length - sizeof(PcapBlockHeader) - sizeof(PcapEnhancedPacketBlockHeader) - 4)) {
            std::cout << "    - Options:" << std::endl;
            while (buffer < block_data + (size_t)(parentHeader->block_total_length - sizeof(PcapBlockHeader) - sizeof(PcapEnhancedPacketBlockHeader) - 4)) {
                auto option_block = PcapBlockOption::parseBlockOption(buffer);
                option_block->print();
            }
        }
    }
} PcapEnhancedPacketBlock;

typedef struct PcapBlock {
    PcapBlockHeader* header;
    void* block_data;
    uint32_t block_total_length_check;

    bool check_length() {
        return header->block_total_length == block_total_length_check;
    }

    void print() {
        header->print();
        switch (header->block_type) {
        case InterfaceDescriptionBlock:
            Q_ASSERT(static_cast<PcapInterfaceDescriptionBlock*>(block_data));
            static_cast<PcapInterfaceDescriptionBlock*>(block_data)->print();
            break;
        /* case PacketBlock:
            Q_ASSERT(static_cast<PcapPacketBlock*>(block_data));
            static_cast<PcapPacketBlock*>(block_data)->print();
            break;*/
        case SimplePacketBlock:
            Q_ASSERT(static_cast<PcapSimplePacketBlock*>(block_data));
            static_cast<PcapSimplePacketBlock*>(block_data)->print();
            break;
        /* case NameResolutionBlock:
            Q_ASSERT(static_cast<PcapNameResolutionBlock*>(block_data));
            static_cast<PcapNameResolutionBlock*>(block_data)->print();
            break; */
        /* case InterfaceStatisticsBlock:
            Q_ASSERT(static_cast<PcapInterfaceStatisticsBlock*>(block_data));
            static_cast<PcapInterfaceStatisticsBlock*>(block_data)->print();
            break; */
        case EnhancedPacketBlock:
            Q_ASSERT(static_cast<PcapEnhancedPacketBlock*>(block_data));
            static_cast<PcapEnhancedPacketBlock*>(block_data)->print();
            break;
        /* case IRIGTimestampBlock:
            Q_ASSERT(static_cast<PcapInterfaceDecriptionBlock*>(block_data));
            static_cast<PcapInterfaceDecriptionBlock*>(block_data)->print();
            break; */
        case SectionHeaderBlock:
            Q_ASSERT(static_cast<PcapSectionHeaderBlock*>(block_data));
            static_cast<PcapSectionHeaderBlock*>(block_data)->print();
            break;
        default:
            std::cout << "Unimplemented block type " << header->block_type << std::endl;
            break;
        }

        std::cout << std::endl;
    }

    static void parseInterfaceDescriptionBlock(PcapBlock* block, char* &buffer) {
        block->block_data = new PcapInterfaceDescriptionBlock;
        auto local_block = static_cast<PcapInterfaceDescriptionBlock*>(block->block_data);
        Q_ASSERT(local_block);

        // Read specialized block header
        local_block->header = new PcapInterfaceDescriptionBlockHeader;
        std::memcpy(local_block->header, buffer, sizeof(PcapInterfaceDescriptionBlockHeader));
        buffer += sizeof(PcapInterfaceDescriptionBlockHeader);

        // Read specialized block data
        size_t data_size = block->header->block_total_length - sizeof(PcapBlockHeader) - sizeof(PcapInterfaceDescriptionBlockHeader) - sizeof(block->block_total_length_check);
        local_block->block_data = new char[data_size];
        std::memcpy(local_block->block_data, buffer, data_size);
        buffer += data_size;
    }

    static void parseSectionHeaderBlock(PcapBlock* block, char* &buffer) {
        block->block_data = new PcapSectionHeaderBlock;
        auto local_block = static_cast<PcapSectionHeaderBlock*>(block->block_data);
        Q_ASSERT(local_block);

        // Read specialized block header
        local_block->header = new PcapSectionHeaderBlockHeader;
        std::memcpy(local_block->header, buffer, sizeof(PcapSectionHeaderBlockHeader));
        buffer += sizeof(PcapSectionHeaderBlockHeader);

        // Read specialized block data
        size_t data_size = block->header->block_total_length - sizeof(PcapBlockHeader) - sizeof(PcapSectionHeaderBlockHeader) - sizeof(block->block_total_length_check);
        local_block->block_data = new char[data_size];
        std::memcpy(local_block->block_data, buffer, data_size);
        buffer += data_size;
    }

    static void parseEnhancedPacketBlock(PcapBlock* block, char* &buffer) {
        block->block_data = new PcapEnhancedPacketBlock;
        auto local_block = static_cast<PcapEnhancedPacketBlock*>(block->block_data);
        Q_ASSERT(local_block);

        local_block->parentHeader = block->header;

        // Read specialized block header
        local_block->header = new PcapEnhancedPacketBlockHeader;
        std::memcpy(local_block->header, buffer, sizeof(PcapEnhancedPacketBlockHeader));
        buffer += sizeof(PcapEnhancedPacketBlockHeader);

        // Read specialized block data
        size_t data_size = block->header->block_total_length - sizeof(PcapBlockHeader) - sizeof(PcapEnhancedPacketBlockHeader) - sizeof(block->block_total_length_check);
        local_block->block_data = new char[data_size];
        std::memcpy(local_block->block_data, buffer, data_size);
        buffer += data_size;
    }
} PcapBlock;

#endif // PCAPSTRUCTS_H
