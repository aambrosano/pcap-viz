#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "pcapmodel.h"
#include <QThread>
#include "packetdata.h"
#include "pcaptcpview.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    PcapParser* parser = new PcapParser;
    parser->moveToThread(&m_parserThread);
    PcapModel* model = new PcapModel;
    //connect(parser, &PcapParser::newData, this, &MainWindow::readBlock);
    connect(parser, &PcapParser::newData, model, &PcapModel::addBlock);
    parser->start();
    //parser->parse();
    connect(this, &QMainWindow::destroyed, this, [parser]() {
        parser->halt();
    });
    auto view = new PcapTCPView(this);
    view->setModel(model);
    setCentralWidget(view);
}

void MainWindow::readBlock(PcapBlock* block)
{
    block->print();
    Q_ASSERT(block->header->block_total_length == block->block_total_length_check);

    if (block->header->block_type == EnhancedPacketBlock) {
        void* ptr = ((PcapEnhancedPacketBlock*)block->block_data)->block_data;
        ((L2_EthernetFrame*)ptr)->print();
        if (((L2_EthernetFrame*)ptr)->type != IPv4)
            return;

        ptr += sizeof(L2_EthernetFrame);
        ((L3_IPv4Packet*)ptr)->print();
        if (((L3_IPv4Packet*)ptr)->protocol != TCP)
            return;

        ptr += sizeof(L3_IPv4Packet);
        ((L4_TCPSegment*)ptr)->print();
    }
    std::cout << std::endl;
}

MainWindow::~MainWindow()
{
    delete ui;
}
