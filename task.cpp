#include "task.h"
#include <iostream>
#include "QtWalletClient.h"
#include "cardcrypto.h"
#include "connectionhandler.h"
#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include <sys/socket.h>
#include <netinet/in.h>

#define DEFAULT_BIND_PORT 9999

void Task::run()
{
    doServer();
    qApp->exit();
}

void Task::doServer()
{
    initWalletConnectionInfo();

    int rc = 0;
    int server_socket = 0;
    struct sockaddr_in bind_addr;
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(DEFAULT_BIND_PORT);
    bind_addr.sin_addr.s_addr = INADDR_ANY;

    server_socket = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (server_socket < 0) { return; }
    rc = bind(server_socket,(sockaddr *)&bind_addr,sizeof(bind_addr));
    if (rc < 0) { return; }
    rc = listen(server_socket,255);
    if (rc < 0) { return; }

    struct sockaddr_in conn_addr;
    socklen_t conn_addr_len;
    while (m_keeprunning) {
        conn_addr_len = sizeof(conn_addr);
        int conn_socket = accept(server_socket,(sockaddr *)&conn_addr,&conn_addr_len);
        if (conn_socket < 0) {
            break;
        }

        ConnectionHandler *handler = new ConnectionHandler(this);
        handler->setWalletCred(m_host,m_port,m_user,m_pass);
        handler->setConnection(conn_socket);
        handler->run();
        delete handler;
    }
    close(server_socket);

#if 0
    QTcpServer sockserv;
    Q_ASSERT(sockserv.listen(QHostAddress::Any, 9999));
    while (m_keeprunning) {
        if (sockserv.waitForNewConnection(-1)) {
            QTcpSocket *connection = sockserv.nextPendingConnection();
            ConnectionHandler *handler = new ConnectionHandler(this);
            handler->setWalletCred(m_host,m_port,m_user,m_pass);
            handler->setConnection(connection);
            handler->run();
            delete handler;
        }
    }
#endif
}

void Task::initWalletConnectionInfo()
{
    m_host = "127.0.0.1";
    m_port = 8332;
    m_user = "bitcoin_json";
    m_pass = "AReallyLongStringOfTextThatsHardToGuess";
}

void Task::doCardCryptoTest1()
{
    QFile random_seed_file("/dev/urandom");
    random_seed_file.open(QIODevice::ReadOnly);
    QByteArray rnd_seed_data = random_seed_file.read(32);
    random_seed_file.close();

    CardCrypto crypto(rnd_seed_data);
    QByteArray key,in,out,iv;

    in = "AReallyLongStringToTestHashing";
    if (crypto.SHA256Hash(in,out)) {
        QByteArray hexout = out.toHex();
        std::cout << "SHA256: " << (const char*)hexout << std::endl;
    }


    in = "AReallyLongStringToTestAES256CBC";
    key = "0123456789012345678901234567890";
    iv = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    if (crypto.AES256CBCEncrypt(key,iv,in,out)) {
        QByteArray hexout = out.toHex();
        std::cout << "AES256: " << (const char *)hexout << std::endl;
    }

    in = out;
    if (crypto.AES256CBCDecrypt(key,iv,in,out)) {
        std::cout << "plaintext: " << (const char *)out << std::endl;
    }

    if (crypto.RSALoadKeyPEM("server_priv.pem")) {
        if (crypto.RSAExportPublicKeyInPKCS1(out)) {
            QByteArray hexout = out.toHex();
            std::cout << "RSAPKEY2048: " << (const char *)hexout << std::endl;
            std::cout << "RSAPKEYLEN: " << out.length() << std::endl;
        }

        in = "AReallyLongStringToTestRSA";
        if (crypto.RSAEncryptWithPublicKey(in,out)) {
            QByteArray hexout = out.toHex();
            std::cout << "RSA2048: " << (const char *)hexout << std::endl;
        }

        in = out;
        if (crypto.RSADecryptWithPrivateKey(in,out)) {
            std::cout << "plaintext: " << (const char *)out << std::endl;
        }
    }

    for(int i=0; i<8; ++i) {
        if (crypto.RNGGetBytes(out)) {
            QByteArray hexout = out.toHex();
            std::cout << "rand[" << i << "] = " << (const char *)hexout << std::endl;
        }
    }
}

void Task::doCardCryptoTest2()
{
    QByteArray pastebin = "35 76 3B 48 A6 33 56 C7 87 46 A4 99 5B C4 AF D3 EF DB 5B AA 44 8A A0 BB 4F 45 19 7A 54 FD 06 13 0B 3A 26 3F 05 A7 DD C0 C8 CD 60 E5 3E 8E 14 55 37 FA 8C C7 01 9E 42 49 25 65 58 98 38 27 3B 99"
            "4B A6 51 E8 99 49 CC 05 E2 29 1D DE BD CE CF 32 62 01 F3 06 BD 5F 14 D2 9D D4 F1 7E 6B 65 96 91 0F 2A C6 A8 6B 8B 40 1F 2F 44 2A 60 59 2B 59 20 43 A0 49 EA 8A 1B 72 58 88 B2 85 76 46 4B 77 C8"
            "AD BE C2 B9 23 B9 EF A6 D5 7E 37 66 C4 D2 BE 8C EA C3 B0 75 2E B5 D0 49 20 1E 08 C5 EE 9B 00 FF 4F CF 4C 82 FB F8 3E 9F C0 90 C9 CA C4 3E A3 3D E5 04 CA BA 55 80 9A AF 79 0A 80 71 03 08 0C 8D"
            "2B A1 84 CC C8 C4 9E 0D D4 20 3C 9F E7 FB A8 4B F7 B0 46 9B 39 A5 F5 1A CA 69 CB 63 E3 E3 D8 25 9B DF C3 2B E5 80 57 46 30 C6 15 AD 5C 54 7F AF F1 23 FE 87 52 B9 D6 AA 3D 06 E1 19 6F A0 3A 60"
            "00 98 92 5A DC BC FE 4C 55 DC 92 4E E4 25 84 A6 34 09 5A 1E 31 A7 5A B0 AD EF A2 27 4D A9 F9 DC EA 4B 11 26 6F 1E EF 08 CF 05 62 EA 21 5D E6 5D CE CA E6 AB 94 D4 68 7E 27 E7 00 C8 4C 0B E4 33"
            "E6 AF DA 2F 14 6E 97 20 67 16 BA BC 66 51 DE 0D 12 C8 41 A3 49 9D 7C 2F EE A0 AD D6 1C 5E AE 43 5A FA 78 A4 CC B6 BB 11 65 BF F4 2C E6 27 0C 25 14 66 75 4C BC 27 5A 3F 45 C7 AC FE 43 14 33 11"
            "9A D1 AE E2 E4 6B D5 9C 8A 57 10 74 65 45 44 34 2E F2 15 82 B9 E6 A2 68 FF 7B 00 74 D7 40 2D 33 C9 0D EF 27 9C 74 1F 96 B9 62 76 4C C8 42 85 D9 A9 6B B4 30 B3 9E 96 16 23 98 0A 39 D3 31 C4 4D"
            "DD 75 82 2F E0 7F 57 48 37 98 7F 4A FF 59 04 E4 5A 7E 47 74 FE 8F 45 62 76 C6 5B 0D 60 4B BF D6 95 24 D9 9D 23 D8 BC 12 73 9D 5A C9 4C 25 4F 37 EB FA 6F 60 B6 6C 04 9A 6B DF 22 00 75 5F 72 7F";

    QByteArray cipherhex;
    for (int i=0; i<pastebin.length(); ++i) {
        if (!isspace(pastebin[i])) { cipherhex += pastebin[i]; }
    }
    QByteArray ciphertext = QByteArray::fromHex(cipherhex);


    QFile random_seed_file("/dev/urandom");
    random_seed_file.open(QIODevice::ReadOnly);
    QByteArray rnd_seed_data = random_seed_file.read(32);
    random_seed_file.close();

    CardCrypto crypto(rnd_seed_data);
    if (crypto.RSALoadKeyPEM("server_key.pem")) {
        QByteArray plaintext;
        bool rc = crypto.RSADecryptWithPrivateKey(ciphertext,plaintext);
        if (rc) {
            unsigned long foo;
            memcpy(&foo,plaintext.data(),sizeof(foo));
            if (foo == 0xdeadbeef) {
                std::cout << (const char *)plaintext.toHex() << std::endl;
            }
        }
    }
}

void Task::doCardCryptoTest3()
{
    QByteArray cipherhex = "e06f63a711e8b7aa9f9440107d4680a1d2b31a759f324b8c0d1c764155455623ada17a7fe56f8330df1e80e2d03925ee";
    QByteArray ciphertext = QByteArray::fromHex(cipherhex);
    QFile random_seed_file("/dev/urandom");
    random_seed_file.open(QIODevice::ReadOnly);
    QByteArray rnd_seed_data = random_seed_file.read(32);
    random_seed_file.close();

    CardCrypto crypto(rnd_seed_data);
    QByteArray key,iv,out;

    key = "01234567890123456789012345678901";
    iv = "0123456789012345";
    if (crypto.AES256CBCDecrypt(key,iv,ciphertext,out)) {
        std::cout << (const char *)out << std::endl;
    }
}

void Task::doCardCryptoTest4()
{
    QFile random_seed_file("/dev/urandom");
    random_seed_file.open(QIODevice::ReadOnly);
    QByteArray rnd_seed_data = random_seed_file.read(32);
    random_seed_file.close();

    CardCrypto crypto(rnd_seed_data);
    QByteArray key,iv,plain,cipher,plain1;

    key = "01234567890123456789012345678901";
    iv = "0123456789012345";
    plain = "The quick brown fox, jumped over the lazy dog.";
    if (crypto.AES256CBCEncrypt(key,iv,plain,cipher)) {
        std::cout << (const char *)cipher.toHex() << std::endl;
    }
    if (crypto.AES256CBCDecrypt(key,iv,cipher,plain1)) {
        std::cout << (const char *)plain1 << std::endl;
    }
}

void Task::doWalletClientTest()
{
    QString user("bitcoin_json");
    QString pass("AReallyLongStringOfTextThatsHardToGuess");
    QString host("127.0.0.1");
    QString acctname("");
    QtWalletClient cli(user,pass,host);
    cli.Init();
    QJsonDocument resp;
    if (cli.GetInfo(resp)) {
        QByteArray buf = resp.toJson();
        std::cout << (const char *)buf << std::endl;
    }
    if (cli.GetAccountAddresses(acctname,resp)) {
        QByteArray buf = resp.toJson();
        std::cout << (const char *)buf << std::endl;
    }
    cli.Term();
}
