// packetmachine.h Copyright 2013 Owen Lynn <owen.lynn@gmail.com>
// Released under the GNU Public License V3

#ifndef PACKETMACHINE_H
#define PACKETMACHINE_H

#include <QObject>
#include "cardcrypto.h"
#include "WalletClient.h"

class PacketMachine : public QObject
{
    Q_OBJECT
public:
    explicit PacketMachine(QObject *parent, QString &host, int port, QString &user, QString &pass);
    ~PacketMachine();

    int gobble(bool &keepgoing,QByteArray &in,QByteArray &out);

signals:
    
public slots:
    
private:
    CardCrypto     *m_crypto;
    WalletClient   *m_wallet;
    unsigned short  m_state;
    QByteArray      m_cardid;
    unsigned char   m_cipher;
    QByteArray      m_aes256_iv;
    QByteArray      m_aes256_key;

    QByteArray wrapPacket(QByteArray &in);
    int doCardSecrets(QByteArray &in,QByteArray &out);
    int doCommand(bool &keepgoing, QByteArray &in, QByteArray &out);
    int doPayment(QByteArray &in, QByteArray &out);
    void doError(int reason, QByteArray &out);

    int GetNewAddress(QString &acctname,QString &addr);
    int GetExistingAddresses(QString &acctname,QVector<QString> &addrs);
    int GetBalance(QString &acctname,double &amount);
    int GetTxFee(double &amount);
    int UnlockWallet(QString &passphrase);
    int LockWallet();
    int SendFrom(QString &acctname, unsigned long long amt, QString &destaddr, QByteArray &txid_out);
};

#endif // PACKETMACHINE_H
