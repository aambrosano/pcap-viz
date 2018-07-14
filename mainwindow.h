#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pcapparser.h"
#include <QThread>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

public slots:
    void readBlock(PcapBlock* block);

private:
    Ui::MainWindow *ui;
    QThread m_parserThread;
};

#endif // MAINWINDOW_H
