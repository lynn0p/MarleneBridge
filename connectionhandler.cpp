#include "connectionhandler.h"
#include "cardcrypto.h"
#include "packetmachine.h"
#include <fcntl.h>
#include <sys/socket.h>
#include <errno.h>

#define WAIT_BETWEEN_TRIES 100
#define MAX_READ_TRIES  3
#define MAX_WRITE_TRIES 3

ConnectionHandler::ConnectionHandler(QObject *parent) :
    QObject(parent), m_conn_sock(-1)
{
}

ConnectionHandler::~ConnectionHandler()
{
    if (m_conn_sock >= 0) {
        close(m_conn_sock);
        m_conn_sock = -1;
    }
}

void
ConnectionHandler::setWalletCred(QString &host, int port, QString &user, QString &pass)
{
    m_host = host;
    m_port = port;
    m_user = user;
    m_pass = pass;
}

void
ConnectionHandler::setConnection(int sock)
{
    if (m_conn_sock >= 0) {
        close(m_conn_sock);
        m_conn_sock = -1;
    }
    if (sock > 0) {
        m_conn_sock = sock;
    }
}

void
ConnectionHandler::run()
{
    int rc = -1;
    bool keepgoing = true;
    PacketMachine pacman(this,m_host,m_port,m_user,m_pass);
    do {
        // the packet format is length(2 bytes) followed by the
        // first 4 bytes SHA256 hash on the data followed by the data
        // and everything and i mean everything is little endian
        unsigned short packetlen = 0;
        rc = Read(&packetlen,sizeof(packetlen));
        if (rc < 0 || packetlen == 0) {
            // TODO: log an error here
            break;
        }
        long checksum1;
        rc = Read(&checksum1,sizeof(checksum1));
        if (rc < 0) {
            // TODO: log an error here
            break;
        }
        QByteArray payload;
        rc = Read(payload,packetlen);
        if (rc < 0) {
            // TODO: log an error here
            break;
        }
        long checksum2 = CardCrypto::CheckSum(payload);
        if (checksum1 == checksum2) {
            // everything checks out so invoke the packet handler on it
            QByteArray resp;
            rc = pacman.gobble(keepgoing,payload,resp);
            if (rc == 0) {
                rc = Write(resp);
            }
        } else {
            break;
        }
    } while(rc == 0 && keepgoing);

    close(m_conn_sock);
    m_conn_sock = -1;
}

bool ConnectionHandler::SetNonblocking()
{
    if (m_conn_sock < 0) { return false; }
    int flags = fcntl(m_conn_sock, F_GETFL, 0);
    return (fcntl(m_conn_sock, F_SETFL, flags|O_NONBLOCK) == 0);
}

int  ConnectionHandler::Read(void *buf,unsigned long len)
{
    int rc = -1;
    if (m_conn_sock >= 0) {
        int tries = MAX_READ_TRIES;
        unsigned char *p = (unsigned char *)buf;
        unsigned char *e = p + len;
        do {
            int rlen = recv(m_conn_sock,p,e-p,0);
            if (rlen < 0) {
                if (errno == EWOULDBLOCK || errno == EAGAIN) {
                    --tries;
                    if (tries) {
                        QThread::msleep(WAIT_BETWEEN_TRIES);
                        continue;
                    } else {
                        break;
                    }
                } else {
                    rc = errno;
                    break;
                }
            } else {
                p += rlen;
                if (p == e) { rc = 0; }
            }
        } while(p < e);
    }
    return rc;
}

int  ConnectionHandler::Read(QByteArray &buf, unsigned long len)
{
    int rc = 0;
    for (unsigned long i=0; i<len && rc == 0; ++i) {
        char foo[2];
        rc = Read(foo,1);
        if (rc == 0) {
            buf += foo[0];
        }
    }
    return rc;
}

int  ConnectionHandler::Write(const QByteArray &buf)
{
    int rc = -1;
    if (m_conn_sock >= 0) {
        int tries = MAX_WRITE_TRIES;
        const unsigned char *p = (unsigned char *)buf.data();
        const unsigned char *e = p + buf.length();
        do {
            int wrlen = send(m_conn_sock,p,e-p,0);
            if (wrlen < 0) {
                if (errno == EWOULDBLOCK || errno == EAGAIN) {
                    --tries;
                    if (tries) {
                        QThread::msleep(WAIT_BETWEEN_TRIES);
                        continue;
                    } else {
                        break;
                    }
                } else {
                    rc = errno;
                    break;
                }
            } else {
                p += wrlen;
                if (p == e) { rc = 0; }
            }
        } while(p < e);
    }
    return rc;
}
