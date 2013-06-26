#ifndef CONNECTIONHANDLER_H
#define CONNECTIONHANDLER_H

#include <QObject>

class ConnectionHandler : public QObject
{
    Q_OBJECT
public:
    explicit ConnectionHandler(QObject *parent = 0);
    ~ConnectionHandler();

    void setWalletCred(QString &host, int port, QString &user, QString &pass);
    void setConnection(int sock);
    void run();

signals:
    
public slots:

private:
    int         m_conn_sock;
    QString     m_host;
    QString     m_user;
    QString     m_pass;
    int         m_port;

    bool SetNonblocking();
    int  Read(void *buf, unsigned long len);
    int  Read(QByteArray &buf, unsigned long len);
    int  Write(const QByteArray &buf);
};

#endif // CONNECTIONHANDLER_H
