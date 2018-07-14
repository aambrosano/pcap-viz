#include "pcapparser.h"
#include "pcapstructs.h"
#include <iostream>
#include <cstring>

PcapParser::PcapParser(QObject *parent) : QThread(parent)
{
    m_buffer = new char[4 * 1024 * 1024]; // 4MB or more should be more than enough for a single block
}

void PcapParser::parse() {
    std::cout << "Parsing..." << std::endl;

    while (!m_stop) {
        std::cin.read(m_buffer, sizeof(PcapBlockHeader));
        std::cin.read(m_buffer + sizeof(PcapBlockHeader), ((PcapBlockHeader*)m_buffer)->block_total_length - sizeof(PcapBlockHeader));

        auto buffer_ptr = m_buffer;
        while (buffer_ptr < m_buffer + std::cin.gcount()) {
            PcapBlock* block = new PcapBlock;
            block->header = new PcapBlockHeader;
            std::memcpy(block->header, buffer_ptr, sizeof(PcapBlockHeader));
            buffer_ptr += sizeof(PcapBlockHeader);
            /*
             * enum PcapBlockType : int32_t {
                    InterfaceDescriptionBlock     = 0x00000001,
                    PacketBlock                   = 0x00000002,
                    SimplePacketBlock             = 0x00000003,
                    NameResolutionBlock           = 0x00000004,
                    InterfaceStatisticsBlock      = 0x00000005,
                    EnhancedPacketBlock           = 0x00000006,
                    IRIGTimestampBlock            = 0x00000007,
                    ARINC429Block                 = 0x00000008,
                    HPMachineInfoBlock            = 0x00000101
                    // TODO: continue
                }; */

            switch (block->header->block_type) {
            case InterfaceDescriptionBlock:
                PcapBlock::parseInterfaceDescriptionBlock(block, buffer_ptr);
                break;

            case EnhancedPacketBlock:
                PcapBlock::parseEnhancedPacketBlock(block, buffer_ptr);
                break;

            case SectionHeaderBlock:
                PcapBlock::parseSectionHeaderBlock(block, buffer_ptr);
                break;
            }

            std::memcpy(&(block->block_total_length_check), buffer_ptr, sizeof(block->block_total_length_check));
            buffer_ptr += sizeof(block->block_total_length_check);

            newData(block);
        }
    }
}
