#ifndef CARDCRYPTO_H
#define CARDCRYPTO_H
#include <QtCore>

class CardCrypto
{
public:
    CardCrypto(QByteArray &rnd_seed_data);
    virtual ~CardCrypto();

    // RNG API
    bool RNGGetBytes(QByteArray &out, int num_bytes = 32);

    // RSA API
    bool RSALoadKeyPEM(const QString &filename);
    bool RSAGenerateNewKeyPair(int keylen=2048);
    bool RSAExportPublicKeyInPKCS1(QByteArray & out);
    bool RSAEncryptWithPublicKey(QByteArray &in, QByteArray &out);
    bool RSADecryptWithPrivateKey(QByteArray &in, QByteArray &out);

    // AES API
    bool AES256CBCEncrypt(QByteArray &key,QByteArray &iv,QByteArray &in,QByteArray &out);
    bool AES256CBCDecrypt(QByteArray &key,QByteArray &iv,QByteArray &in,QByteArray &out);

    // SHA256 API
    static bool SHA256Hash(QByteArray &in, QByteArray &out);

    // simple checksum call to verify packet integrity
    static long CheckSum(const QByteArray &in);

private:
    // don't impl
    CardCrypto(const CardCrypto & src);
    CardCrypto & operator=(const CardCrypto& src);

    struct rsa_st * m_rsakeydata;
};

#endif // CARDCRYPTO_H
