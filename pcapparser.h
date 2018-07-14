#ifndef PCAPPARSER_H
#define PCAPPARSER_H

#include <QObject>
#include "pcapstructs.h"
#include <QThread>

class PcapParser : public QThread
{
    Q_OBJECT

public:
    explicit PcapParser(QObject *parent = nullptr);

    void parse();
    void halt() { m_stop = true; }
    void run() {
        parse();
    }
signals:
    void newData(PcapBlock*);

public slots:

private:
    char* m_buffer;
    bool m_stop = false;
};

#endif // PCAPPARSER_H
