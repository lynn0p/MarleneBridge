// WalletClient.h Copyright 2013 Owen Lynn <owen.lynn@gmail.com>
// Released under the GNU Public License V3

#ifndef WALLETCLIENT_H
#define WALLETCLIENT_H
#include <QtCore>

class WalletClient : public QObject
{
    Q_OBJECT
public:
    WalletClient(QString &user, QString &pass, QString &host, quint32 port, QObject *parent);
    ~WalletClient();

    bool Init();
    bool Term();
    bool GetInfo(QJsonDocument &out);
    bool GetNewAccountAddress(QString &accountname, QJsonDocument &out);
    bool GetAccountAddresses(QString &accountname, QJsonDocument &out);
    bool GetBalance(QString &accountname, QJsonDocument &out);
    bool WalletPassphrase(QString &passphrase, int duration, QJsonDocument &out);
    bool WalletLock(QJsonDocument &out);
    bool SendFrom(QString &accountname, unsigned long long amount, QString &recipient, QJsonDocument &out);

protected:
    virtual bool HTTPClientInit() = 0;
    virtual bool HTTPClientSetupPostRequest(struct HTTPClientSessionInfo *&session) = 0;
    virtual bool HTTPClientDoPost(struct HTTPClientSessionInfo *session, QByteArray &json_in, QByteArray &json_out) = 0;
    virtual bool HTTPClientTeardownPostRequest(struct HTTPClientSessionInfo *&session) = 0;
    virtual bool HTTPClientTerm() = 0;

    QString m_user;
    QString m_pass;
    QString m_host;
    quint32 m_port;

private:
    bool TalkToWallet(QJsonDocument &in,QJsonDocument &out);
};

#endif // WALLETCLIENT_H
