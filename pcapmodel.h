#ifndef PCAPMODEL_H
#define PCAPMODEL_H

#include <QAbstractItemModel>
#include <QVector>
#include "pcapstructs.h"
#include "packetdata.h"

class PcapModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum PcapModelRole {
        L2_EthernetRole = Qt::UserRole + 1,

        L3_IPv4Role,

        L4_TCPRole
    };

    PcapModel();

    void addBlock(PcapBlock* block);

private:
    QVector<PcapBlock*> m_data;

    QHash<QPair<QPair<L3_IPv4Address, uint16_t>, QPair<L3_IPv4Address, uint16_t>>, int> m_segments;
    // QAbstractItemModel interface
public:
    int rowCount(const QModelIndex &parent) const override;
    int columnCount(const QModelIndex &parent) const override;
    QVariant data(const QModelIndex &index, int role) const override;
};

#endif // PCAPMODEL_H
