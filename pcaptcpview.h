#ifndef PCAPVIEW_H
#define PCAPVIEW_H

#include <QObject>
#include <QWidget>
#include <QTableView>

class PcapTCPView : public QTableView
{
    Q_OBJECT
public:
    explicit PcapTCPView(QWidget *parent = nullptr);

signals:

public slots:
};

#endif // PCAPVIEW_H
