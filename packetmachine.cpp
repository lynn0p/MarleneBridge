#include "packetmachine.h"
#include "QtWalletClient.h"
#include "util.h"
#include <iostream>

// TODO: move these into a header all their own
#define SUCCESS                                  0x00000000
#define ERROR_CARDSECRETS_RSA_DECRYPT_FAIL       0x80000001
#define ERROR_CARDSECRETS_MAGIC_FAIL             0x80000002
#define ERROR_CARDSECRETS_UNKNOWN_CIPHER1        0x80000003
#define ERROR_CARDSECRETS_AES_ENCRYPT_FAIL       0x80000004
#define ERROR_CARDSECRETS_UNKNOWN_CIPHER2        0x80000005
#define ERROR_GOBBLE_VERY_BAD_STATE              0x80000006
#define ERROR_DOCOMMAND_UNKNOWN_CIPHER1          0x80000007
#define ERROR_DOCOMMAND_AES_DECRYPT_FAIL         0x80000008
#define ERROR_DOCOMMAND_MAGIC_FAIL               0x80000009
#define ERROR_DOCOMMAND_UNKNOWN_COMMAND_CODE     0x8000000a
#define ERROR_DOCOMMAND_PACKET_TOO_SHORT         0x8000000b
#define ERROR_DOCOMMAND_SWITCH_STATEMENT_BUG     0x8000000c
#define ERROR_CARDSECRETS_WALLET_GETBALANCE_FAIL 0x8000000d
#define ERROR_CARDSECRETS_WALLET_JSON_ERROR1     0x8000000e
#define ERROR_WALLET_NEWADDR_FAIL                0x8000000f
#define ERROR_WALLET_NEWADDR_JSON_ERROR          0x80000010
#define ERROR_WALLET_EXISTINGADDR_FAIL           0x80000011
#define ERROR_WALLET_EXISTINGADDR_JSON_ERROR     0x80000012
#define ERROR_WALLET_GETBALANCE_FAIL             0x80000013
#define ERROR_WALLET_GETBALANCE_JSON_ERROR       0x80000014
#define ERROR_WALLET_GETTXFEE_FAIL               0x80000015
#define ERROR_WALLET_GETTXFEE_JSON_ERROR         0x80000016
#define ERROR_DOPAYMENT_AES_ENCRYPT_FAIL         0x80000017
#define ERROR_DOPAYMENT_UNKNOWN_CIPHER           0x80000018
#define ERROR_UNLOCKWALLET_FAIL                  0x80000019
#define ERROR_UNLOCKWALLET_JSON_FAIL             0x8000001a
#define ERROR_LOCKWALLET_FAIL                    0x8000001b
#define ERROR_LOCKWALLET_JSON_FAIL               0x8000001c
#define ERROR_SENDFROM_FAIL                      0x8000001d
#define ERROR_SENDFROM_JSON_FAIL                 0x8000001e

#define AES256IV_LENGTH   16
#define AES256KEY_LENGTH  32

#define SERVER_KEY_FILE   "server_key.pem"
#define CARD_MAGIC        0xdeadbeef
#define SERVER_MAGIC      0xfeedface
#define PACKET_VERSION    0x00000001

#define CIPHER_UNKNOWN      0x00
#define CIPHER_AES256       0x01

#define STATE_CARDSECRETS   0x0001
#define STATE_COMMAND       0x0002

#define RESPONSE_CODE_HELLO   0x0001
#define RESPONSE_CODE_PAYMENT 0x0002
#define RESPONSE_CODE_ERROR   0x8000

#define COMMAND_CODE_PAYMENT  0x0001
#define COMMAND_CODE_GOODBYE  0x0002

struct CardSecrets {
    unsigned long magic;
    unsigned long version;
    unsigned char cardid[32];
    unsigned char cipher;
    unsigned char cipherdata[1];
};

struct CardCommand {
    unsigned long  magic;
    unsigned long  version;
    unsigned short code;
    unsigned char  data[1];
};

PacketMachine::PacketMachine(QObject *parent, QString &host, int port, QString &user, QString &pass) :
    QObject(parent), m_crypto(0), m_wallet(0), m_state(STATE_CARDSECRETS),
    m_cardid(), m_cipher(CIPHER_UNKNOWN), m_aes256_iv(), m_aes256_key()
{
    // TODO: fix this so it uses a good RNG
    QFile random_seed_file("/dev/urandom");
    random_seed_file.open(QIODevice::ReadOnly);
    QByteArray rnd_seed_data = random_seed_file.read(32);
    random_seed_file.close();

    m_crypto = new CardCrypto(rnd_seed_data);
    Q_ASSERT(m_crypto->RSALoadKeyPEM(SERVER_KEY_FILE));

    m_wallet = new QtWalletClient(user,pass,host,port,this);
    Q_ASSERT(m_wallet->Init());
}

PacketMachine::~PacketMachine()
{
    if (m_wallet) {
        Q_ASSERT(m_wallet->Term());
        delete m_wallet;
        m_wallet = 0;
    }
    if (m_crypto) {
        delete m_crypto;
        m_crypto = 0;
    }
}

int
PacketMachine::gobble(bool &keepgoing, QByteArray &in, QByteArray &out)
{
    int rc=0;
     switch (m_state) {
        case STATE_CARDSECRETS: {
            QByteArray pre_out;
            rc = doCardSecrets(in,pre_out);
            if (rc == SUCCESS) {
                out = pre_out;
                keepgoing = true;
                m_state = STATE_COMMAND;
            } else {
                doError(rc,out);
                keepgoing = false;
            }
        }
        break;

        case STATE_COMMAND: {
            QByteArray pre_out;
            rc = doCommand(keepgoing,in,pre_out);
            if (rc == SUCCESS) {
                out = pre_out;
            } else {
                doError(rc,out);
            }
        }
        break;

        // if you get to here, something very bad has happened
        default: {
            rc = ERROR_GOBBLE_VERY_BAD_STATE;
            keepgoing = false;
            doError(ERROR_GOBBLE_VERY_BAD_STATE,out);
            m_state = STATE_CARDSECRETS;
        }
        break;
    }
    return rc;
}

QByteArray
PacketMachine::wrapPacket(QByteArray &in)
{
    QByteArray out;
    unsigned short len = in.length();
    long checksum = CardCrypto::CheckSum(in);
    out.append((char *)&len, sizeof(len));
    out.append((char *)&checksum, sizeof(checksum));
    out.append(in);
    return out;
}

int
PacketMachine::doCardSecrets(QByteArray &in, QByteArray &out)
{
    // all of the bytes represented by in, should be encrypted using the server's public key
    QByteArray plain_in;
    QByteArray plain_out, cipher_out;
    if (!m_crypto->RSADecryptWithPrivateKey(in,plain_in)) {
        return ERROR_CARDSECRETS_RSA_DECRYPT_FAIL;
    }
    struct CardSecrets *secrets = (struct CardSecrets *)plain_in.data();
    if (secrets->magic != CARD_MAGIC) {
        return ERROR_CARDSECRETS_MAGIC_FAIL;
    }
    // TODO: check secrets->version for right packet version
    m_cardid.clear();
    m_cardid.append((const char*)secrets->cardid, sizeof(secrets->cardid));
    m_cipher = secrets->cipher;
    switch (m_cipher) {
        case CIPHER_AES256: {
            const char *p = (const char*)secrets->cipherdata;
            // next 16 bytes is the iv
            m_aes256_iv.clear();
            m_aes256_iv.append(p,AES256IV_LENGTH);
            p += AES256IV_LENGTH;
            // next 32 bytes is the symmetric key
            m_aes256_key.clear();
            m_aes256_key.append(p,AES256KEY_LENGTH);
        } break;

        default: {
            return ERROR_CARDSECRETS_UNKNOWN_CIPHER1;
        }
    }

    // query wallet for some basic data
    QString acctname = m_cardid.toHex();
    QString receiving_addr;
    QVector<QString> addrs;
    int rc = -1;
    rc = GetExistingAddresses(acctname,addrs);
    if (rc != SUCCESS || addrs.size() == 0) {
        // if we can't get an existing one, get a new one
        rc = GetNewAddress(acctname,receiving_addr);
        if (rc != SUCCESS) {
            return rc;
        }
    } else {
        receiving_addr = addrs[0];
    }

    double balance;
    rc = GetBalance(acctname,balance);
    if (rc != SUCCESS) {
        return rc;
    }
    unsigned long long bal_satoshis;
    bal_satoshis = Utility::ToSatoshis(balance);

    double txfee;
    rc = GetTxFee(txfee);
    if (rc != SUCCESS) {
        return rc;
    }
    unsigned long long txfee_satoshis;
    txfee_satoshis = Utility::ToSatoshis(txfee);

    // assemble the response
    unsigned long magic = SERVER_MAGIC;
    unsigned long version = PACKET_VERSION;
    unsigned short code = RESPONSE_CODE_HELLO;
    plain_out.clear();
    plain_out.append((char*)&magic,sizeof(magic));
    plain_out.append((char*)&version,sizeof(version));
    plain_out.append((char*)&code,sizeof(code));
    plain_out.append((char*)&bal_satoshis,sizeof(bal_satoshis));
    plain_out.append((char*)&txfee_satoshis,sizeof(txfee_satoshis));
    plain_out.append(receiving_addr);
    switch (m_cipher) {
        case CIPHER_AES256: {
            if (!m_crypto->AES256CBCEncrypt(m_aes256_key,m_aes256_iv,
                                            plain_out,cipher_out)) {
                return ERROR_CARDSECRETS_AES_ENCRYPT_FAIL;
            }
        } break;
        default: {
            return ERROR_CARDSECRETS_UNKNOWN_CIPHER2;
        }
    }
    out = wrapPacket(cipher_out);
    return SUCCESS;
}

int PacketMachine::doCommand(bool &keepgoing, QByteArray &in, QByteArray &out)
{
    QByteArray plain_in;
    switch (m_cipher) {
        case CIPHER_AES256: {
            if (!m_crypto->AES256CBCDecrypt(m_aes256_key,m_aes256_iv,in,plain_in)) {
                return ERROR_DOCOMMAND_AES_DECRYPT_FAIL;
            }
        }
        break;

        default: {
            return ERROR_DOCOMMAND_UNKNOWN_CIPHER1;
        }
        break;
    }
    if (plain_in.length() < (int)(sizeof(unsigned long) + sizeof(unsigned short))) {
        return ERROR_DOCOMMAND_PACKET_TOO_SHORT;
    }
    struct CardCommand *cmd = (struct CardCommand *)plain_in.data();
    if (cmd->magic != CARD_MAGIC) {
        return ERROR_DOCOMMAND_MAGIC_FAIL;
    }

    unsigned char *p = cmd->data;
    unsigned char *e = (unsigned char *)plain_in.data() + plain_in.length();
    QByteArray rest;
    if (p < e) {
        rest.append((char*)p,e-p);
    }

    keepgoing = false;
    switch(cmd->code) {
        case COMMAND_CODE_PAYMENT: {
            return doPayment(rest,out);
        }
        break;

        case COMMAND_CODE_GOODBYE: {
            return SUCCESS;
        }
        break;

        // again, very bad to get here
        default: {
            return ERROR_DOCOMMAND_UNKNOWN_COMMAND_CODE;
        }
    }

    // shouldn't ever get here
    return ERROR_DOCOMMAND_SWITCH_STATEMENT_BUG;
}

int PacketMachine::doPayment(QByteArray &in, QByteArray &out)
{
    const char *p = in.data();
    unsigned long long amt_satoshis;
    unsigned long long *pamt_satoshis = (unsigned long long *)p;
    amt_satoshis = *pamt_satoshis;
    p += sizeof(amt_satoshis);
    unsigned char len_wallet_phrase = *p;
    ++p;
    QByteArray wallet_passphrase;
    wallet_passphrase.append(p, (unsigned int)len_wallet_phrase);
    p += len_wallet_phrase;
    unsigned char len_dest_addr = *p;
    ++p;
    QByteArray dest_addr;
    dest_addr.append(p, (unsigned int)len_dest_addr);

    QString pass = wallet_passphrase;
    int rc = UnlockWallet(pass);
    if (rc != SUCCESS) {
        return rc;
    }

    QString acctname = m_cardid.toHex();
    QString recipient = dest_addr;
    QByteArray txid;
    rc = SendFrom(acctname,amt_satoshis,recipient,txid);
    if (rc != SUCCESS) {
        return rc;
    }

    // TODO: check this call and log on error, maybe alert on error too
    LockWallet();

    // assemble the success response
    QByteArray plain_out,cipher_out;
    unsigned long magic = SERVER_MAGIC;
    unsigned long version = PACKET_VERSION;
    unsigned short code = RESPONSE_CODE_PAYMENT;
    long status = 0;
    plain_out.clear();
    plain_out.append((char*)&magic,sizeof(magic));
    plain_out.append((char*)&version,sizeof(version));
    plain_out.append((char*)&code,sizeof(code));
    plain_out.append((char*)&status,sizeof(status));
    plain_out.append(txid);

    switch (m_cipher) {
        case CIPHER_AES256: {
            if (!m_crypto->AES256CBCEncrypt(m_aes256_key,m_aes256_iv,
                                            plain_out,cipher_out)) {
                return ERROR_DOPAYMENT_AES_ENCRYPT_FAIL;
            }
        } break;
        default: {
            return ERROR_DOPAYMENT_UNKNOWN_CIPHER;
        }
    }
    out = wrapPacket(cipher_out);

    return SUCCESS;
}

void PacketMachine::doError(int reason, QByteArray &out)
{
    QByteArray plain_out,cipher_out;
    unsigned long magic = SERVER_MAGIC;
    unsigned long version = PACKET_VERSION;
    unsigned short code = RESPONSE_CODE_ERROR;
    plain_out.clear();
    plain_out.append((char*)&magic,sizeof(magic));
    plain_out.append((char*)&version,sizeof(version));
    plain_out.append((char*)&code,sizeof(code));
    plain_out.append((char*)&reason,sizeof(reason));

    switch (m_cipher) {
        case CIPHER_AES256: {
            m_crypto->AES256CBCEncrypt(m_aes256_key,m_aes256_iv,
                                       plain_out,cipher_out);
        } break;

        default: {
        }
    }

    out = wrapPacket(cipher_out);
}

int PacketMachine::GetNewAddress(QString &acctname,QString &addr)
{
    QJsonDocument resp;
    if (!m_wallet->GetNewAccountAddress(acctname,resp)) {
        return ERROR_WALLET_NEWADDR_FAIL;
    }
    QJsonObject obj = resp.object();
    QString obj_rc = obj.value("error").toString();
    if (obj_rc != "") {
        return ERROR_WALLET_NEWADDR_JSON_ERROR;
    }
    addr = obj.value("result").toString();
    return SUCCESS;
}

int PacketMachine::GetExistingAddresses(QString &acctname,QVector<QString> &addrs)
{
    QJsonDocument resp;
    if (!m_wallet->GetAccountAddresses(acctname,resp)) {
        return ERROR_WALLET_EXISTINGADDR_FAIL;
    }
    QJsonObject obj = resp.object();
    QString obj_rc = obj.value("error").toString();
    if (obj_rc != "") {
        return ERROR_WALLET_EXISTINGADDR_JSON_ERROR;
    }
    addrs.clear();
    QJsonArray jvec = obj.value("result").toArray();
    for (int i=0; i<jvec.size(); ++i) {
        addrs.append(jvec[i].toString());
    }
    return SUCCESS;
}

int PacketMachine::GetBalance(QString &acctname,double &amount)
{
    QJsonDocument resp;
    if (!m_wallet->GetBalance(acctname,resp)) {
        return ERROR_WALLET_GETBALANCE_FAIL;
    }
    QJsonObject obj = resp.object();
    QString obj_rc = obj.value("error").toString();
    if (obj_rc != "") {
        return ERROR_WALLET_GETBALANCE_JSON_ERROR;
    }
    amount = obj.value("result").toDouble();
    return SUCCESS;
}

int PacketMachine::GetTxFee(double &amount)
{
    QJsonDocument resp;
    if (!m_wallet->GetInfo(resp)) {
        return ERROR_WALLET_GETTXFEE_FAIL;
    }
    QJsonObject obj = resp.object();
    QString obj_rc = obj.value("error").toString();
    if (obj_rc != "") {
        return ERROR_WALLET_GETTXFEE_JSON_ERROR;
    }
    QJsonObject result = obj.value("result").toObject();
    amount = result.value("paytxfee").toDouble();
    return SUCCESS;
}

int PacketMachine::UnlockWallet(QString &passphrase)
{
    QJsonDocument resp;
    if (!m_wallet->WalletPassphrase(passphrase,60,resp)) {
        return ERROR_UNLOCKWALLET_FAIL;
    }
    QJsonObject obj = resp.object();
    QString obj_rc = obj.value("error").toString();
    if (obj_rc != "") {
        return ERROR_UNLOCKWALLET_JSON_FAIL;
    }
    return SUCCESS;
}

int PacketMachine::LockWallet()
{
    QJsonDocument resp;
    if (!m_wallet->WalletLock(resp)) {
        return ERROR_LOCKWALLET_FAIL;
    }
    QJsonObject obj = resp.object();
    QString obj_rc = obj.value("error").toString();
    if (obj_rc != "") {
        return ERROR_LOCKWALLET_JSON_FAIL;
    }
    return SUCCESS;
}

int PacketMachine::SendFrom(QString &acctname,unsigned long long amt,QString &destaddr,QByteArray &txid_out)
{
    // sendfrom() has been tested to work, this debug placeholder is
    // to conserve spending bitcoins
    // to make this call live, just comment this out and comment the below back in
    std::cout << "SendFrom( " << acctname.toLocal8Bit().data() << ", "
              << amt << ", " << destaddr.toLocal8Bit().data() << ")" << std::endl;
    QByteArray test = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    txid_out = QByteArray::fromHex(test);

#if 0
    QJsonDocument resp;
    if (!m_wallet->SendFrom(acctname,amt,destaddr,resp)) {
        return ERROR_SENDFROM_FAIL;
    }
    QJsonObject obj = resp.object();
    QString obj_rc = obj.value("error").toString();
    if (obj_rc != "") {
        return ERROR_SENDFROM_JSON_FAIL;
    }
    QByteArray txid_out_hex = obj.value("result").toString();
    txid_out = QByteArray::fromHex(txid_out_hex);
#endif

    return SUCCESS;
}
