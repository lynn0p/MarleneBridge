// QtWalletClient.h Copyright 2013 Owen Lynn <owen.lynn@gmail.com>
// Released under the GNU Public License V3

#ifndef QTWALLETCLIENT_H
#define QTWALLETCLIENT_H
#include "WalletClient.h"
#include <QtNetwork/QNetworkAccessManager>

class QtWalletClient : public WalletClient
{
    Q_OBJECT
public:
    QtWalletClient(QString &user, QString &pass, QString &host, quint32 port=8332, QObject *parent=0);
    ~QtWalletClient();

public slots:
    void authenticationRequired(QNetworkReply *,QAuthenticator *);

private:
    QNetworkAccessManager *m_qnam;
    bool m_finished;

    virtual bool HTTPClientInit();
    virtual bool HTTPClientSetupPostRequest(struct HTTPClientSessionInfo *&session);
    virtual bool HTTPClientDoPost(struct HTTPClientSessionInfo *session, QByteArray &json_in, QByteArray &json_out);
    virtual bool HTTPClientTeardownPostRequest(struct HTTPClientSessionInfo *&session);
    virtual bool HTTPClientTerm();
};

#endif // QTWALLETCLIENT_H
