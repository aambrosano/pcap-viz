#include "pcapmodel.h"
#include "packetdata.h"

PcapModel::PcapModel()
{

}

void PcapModel::addBlock(PcapBlock* block)
{
    m_data.push_back(block);
    // block->print();

    if (block->header->block_type == EnhancedPacketBlock) {
        void* ptr = ((PcapEnhancedPacketBlock*)block->block_data)->block_data;
        // ((L2_EthernetFrame*)ptr)->print();
        auto eth_frame = (L2_EthernetFrame*)ptr;
        if (eth_frame->type != IPv4)
            return;

        ptr += sizeof(L2_EthernetFrame);
        auto ipv4_pack = (L3_IPv4Packet*)ptr;
        // ((L3_IPv4Packet*)ptr)->print();
        if (ipv4_pack->protocol != TCP)
            return;

        ptr += sizeof(L3_IPv4Packet);
        // ((L4_TCPSegment*)ptr)->print();

        auto tcp_seg = (L4_TCPSegment*)ptr;
        std::cout << tcp_seg->src_port << " " << tcp_seg->dst_port << std::endl;

        QPair<QPair<L3_IPv4Address, uint16_t>, QPair<L3_IPv4Address, uint16_t>> toAdd;
        if (ipv4_pack->src.b0 == 192 && ipv4_pack->src.b1 == 168) {
            toAdd = {
                QPair<L3_IPv4Address, uint16_t>(ipv4_pack->src, htons(tcp_seg->src_port)),
                QPair<L3_IPv4Address, uint16_t>(ipv4_pack->dst, htons(tcp_seg->dst_port))
            };
        }
        else {
            toAdd = {
                QPair<L3_IPv4Address, uint16_t>(ipv4_pack->dst, htons(tcp_seg->dst_port)),
                QPair<L3_IPv4Address, uint16_t>(ipv4_pack->src, htons(tcp_seg->src_port))
            };
        }


        if (m_segments.find(toAdd) != m_segments.end()) {
            m_segments[toAdd]++;
        }
        else {
            beginInsertRows({}, m_segments.size() - 1, m_segments.size() - 1);
            m_segments[toAdd] = 1;
            endInsertRows();
        }
        dataChanged(this->index(0, 0), this->index(m_segments.size() - 1, 4));
    }
}


int PcapModel::rowCount(const QModelIndex &parent) const
{
    return m_segments.size();
}

int PcapModel::columnCount(const QModelIndex &parent) const
{
    return 5;
}

QVariant PcapModel::data(const QModelIndex &index, int role) const
{
    if (role != Qt::DisplayRole) return {};
    if (index.isValid() && index.row() < m_segments.size() && index.column() < 5) {
        switch (index.column()) {
        case 0:
            return m_segments.keys()[index.row()].first.first.toString();
        case 1:
            return m_segments.keys()[index.row()].first.second;
        case 2:
            return m_segments.keys()[index.row()].second.first.toString();
        case 3:
            return m_segments.keys()[index.row()].second.second;
        case 4:
            return m_segments[m_segments.keys()[index.row()]];
        }
    }
}
