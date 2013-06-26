// QtWalletClient.cpp Copyright 2013 Owen Lynn <owen.lynn@gmail.com>
// Released under the GNU Public License V3

#include "QtWalletClient.h"
#include <QUrl>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>
#include <QtNetwork/QAuthenticator>

struct HTTPClientSessionInfo {
    QUrl            * url;
    QNetworkRequest * http_req;
    QNetworkReply   * http_resp;
};

QtWalletClient::QtWalletClient(QString &user, QString &pass, QString &host, quint32 port, QObject *parent) :
    WalletClient(user,pass,host,port,parent), m_qnam(0), m_finished(false)
{
}

QtWalletClient::~QtWalletClient()
{
}

void QtWalletClient::authenticationRequired(QNetworkReply *resp, QAuthenticator *auth)
{
    auth->setUser(m_user);
    auth->setPassword(m_pass);
}

bool QtWalletClient::HTTPClientInit()
{
    bool rc = false;
    m_qnam = new QNetworkAccessManager(this);
    if (m_qnam) {
        connect(m_qnam, SIGNAL(authenticationRequired(QNetworkReply*,QAuthenticator*)),
                this, SLOT(authenticationRequired(QNetworkReply*,QAuthenticator*)));
        rc = true;
    }
    return rc;
}

bool QtWalletClient::HTTPClientSetupPostRequest(struct HTTPClientSessionInfo *&session)
{
    bool rc = false;
    session = new struct HTTPClientSessionInfo;
    if (session) {
        QByteArray urlbuf;
        urlbuf = "http://";
        urlbuf += m_host;
        urlbuf += ":";
        urlbuf += QString().setNum(m_port);
        QString urlstr(urlbuf);
        session->url = new QUrl(urlstr);
        session->http_req = new QNetworkRequest(*(session->url));
        session->http_req->setHeader(QNetworkRequest::ContentTypeHeader,"application/json");
        session->http_resp = 0;
        rc = true;
    }
    return rc;
}

bool QtWalletClient::HTTPClientDoPost(struct HTTPClientSessionInfo *session, QByteArray &json_in, QByteArray &json_out)
{
    bool rc = false;
    if (session) {
        session->http_resp = m_qnam->post(*(session->http_req),json_in);
        QEventLoop loop;
        connect(m_qnam, SIGNAL(finished(QNetworkReply*)), &loop, SLOT(quit()));
        loop.exec();
        QVariant status = session->http_resp->attribute(QNetworkRequest::HttpStatusCodeAttribute);
        if (status.toInt() == 200) {
            json_out = session->http_resp->readAll();
            rc = true;
        }
    }
    return rc;
}

bool QtWalletClient::HTTPClientTeardownPostRequest(struct HTTPClientSessionInfo *&session)
{
    bool rc = false;
    if (session) {
        if (session->url) {
            delete session->url;
            session->url = 0;
        }
        if (session->http_req) {
            delete session->http_req;
            session->http_req = 0;
        }
        if (session->http_resp) {
            delete session->http_resp;
            session->http_resp = 0;
        }
        delete session;
        session = 0;
        rc = true;
    }
    return rc;
}

bool QtWalletClient::HTTPClientTerm()
{
    bool rc = false;
    if (m_qnam) {
        disconnect(m_qnam, SIGNAL(authenticationRequired(QNetworkReply*,QAuthenticator*)),
                   this, SLOT(authenticationRequired(QNetworkReply*,QAuthenticator*)));
        delete m_qnam;
        m_qnam = 0;
        rc = true;
    }\
    return rc;
}
