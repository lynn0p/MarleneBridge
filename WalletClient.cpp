#include "WalletClient.h"
#include "util.h"

WalletClient::WalletClient(QString &user, QString &pass, QString &host, quint32 port, QObject *parent) :
    QObject(parent), m_user(user), m_pass(pass), m_host(host), m_port(port)
{
}

WalletClient::~WalletClient()
{
}

bool
WalletClient::Init()
{
    return HTTPClientInit();
}

bool
WalletClient::Term()
{
    return HTTPClientTerm();
}

bool
WalletClient::GetInfo(QJsonDocument &out)
{
    bool rc = false;
    QJsonObject method;
    method.insert("method",QJsonValue(QString("getinfo")));
    QJsonDocument jsonreq;
    jsonreq.setObject(method);

    rc = TalkToWallet(jsonreq,out);
    return rc;
}

bool
WalletClient::GetNewAccountAddress(QString &accountname, QJsonDocument &out)
{
    bool rc = false;
    QJsonObject method;
    method.insert("method",QJsonValue(QString("getaccountaddress")));
    QJsonArray parms;
    parms.append(QJsonValue(accountname));
    method.insert("params",parms);

    QJsonDocument jsonreq;
    jsonreq.setObject(method);

    rc = TalkToWallet(jsonreq,out);
    return rc;
}

bool
WalletClient::GetAccountAddresses(QString &accountname, QJsonDocument &out)
{
    bool rc = false;
    QJsonObject method;
    method.insert("method",QJsonValue(QString("getaddressesbyaccount")));
    QJsonArray parms;
    parms.append(QJsonValue(accountname));
    method.insert("params",parms);

    QJsonDocument jsonreq;
    jsonreq.setObject(method);

    rc = TalkToWallet(jsonreq,out);
    return rc;
}

bool
WalletClient::GetBalance(QString &accountname, QJsonDocument &out)
{
    bool rc=false;
    QJsonObject method;
    method.insert("method",QJsonValue(QString("getbalance")));
    QJsonArray parms;
    parms.append(QJsonValue(accountname));
    method.insert("params",parms);

    QJsonDocument jsonreq;
    jsonreq.setObject(method);

    rc = TalkToWallet(jsonreq,out);
    return rc;
}

bool
WalletClient::WalletPassphrase(QString &passphrase, int duration, QJsonDocument &out)
{
    bool rc=false;
    QJsonObject method;
    method.insert("method",QJsonValue(QString("walletpassphrase")));
    QJsonArray parms;
    parms.append(QJsonValue(passphrase));
    parms.append(QJsonValue(duration));
    method.insert("params", parms);

    QJsonDocument jsonreq;
    jsonreq.setObject(method);

    rc = TalkToWallet(jsonreq,out);
    return rc;
}

bool
WalletClient::WalletLock(QJsonDocument &out)
{
    bool rc=false;
    QJsonObject method;
    method.insert("method",QJsonValue(QString("walletlock")));

    QJsonDocument jsonreq;
    jsonreq.setObject(method);

    rc = TalkToWallet(jsonreq,out);
    return rc;
}

bool
WalletClient::SendFrom(QString &accountname, unsigned long long amount, QString &recipient, QJsonDocument &out)
{
    bool rc=false;
    QJsonObject method;
    method.insert("method",QJsonValue(QString("sendfrom")));
    QJsonArray parms;
    parms.append(QJsonValue(accountname));
    parms.append(QJsonValue(recipient));
    parms.append(QJsonValue(Utility::FromSatoshis(amount)));
    method.insert("params", parms);

    QJsonDocument jsonreq;
    jsonreq.setObject(method);

    rc = TalkToWallet(jsonreq,out);
    return rc;
}

bool
WalletClient::TalkToWallet(QJsonDocument &in,QJsonDocument &out)
{
    bool rc = false;
    QByteArray rawreq = in.toJson();
    QByteArray rawresp;
    struct HTTPClientSessionInfo * session;
    if (HTTPClientSetupPostRequest(session)) {
        rc = HTTPClientDoPost(session,rawreq,rawresp) && HTTPClientTeardownPostRequest(session);
    }
    if (rc) {
        out = QJsonDocument::fromJson(rawresp);
    }
    return rc;
}
