// Task.h Copyright 2013 Owen Lynn <owen.lynn@gmail.com>
// Released under the GNU Public License V3

#ifndef TASK_H
#define TASK_H

#include <QtCore>

class Task : public QObject
{
    Q_OBJECT
public:
    Task(QObject *parent = 0) : QObject(parent) { m_keeprunning = true; }

public slots:
    virtual void run();

    void stop() { m_keeprunning = false; }

private:
    bool m_keeprunning;
    QString  m_user;
    QString  m_pass;
    QString  m_host;
    int      m_port;

    void doServer();
    void initWalletConnectionInfo();

    void doWalletClientTest();
    void doCardCryptoTest1();
    void doCardCryptoTest2();
    void doCardCryptoTest3();
    void doCardCryptoTest4();
};


#endif // TASK_H
