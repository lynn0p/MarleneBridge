// CardCrypto.cpp Copyright 2013 Owen Lynn <owen.lynn@gmail.com>
// Released under the GNU Public License V3

#include "cardcrypto.h"
#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include "openssl/aes.h"

CardCrypto::CardCrypto(QByteArray & rnd_seed_data) : m_rsakeydata(0)
{
    // init the RNG (needed for RSA keygen)
    const RAND_METHOD *temp = RAND_get_rand_method();
    RAND_set_rand_method(temp);
    RAND_seed(rnd_seed_data.data(),rnd_seed_data.length());
}

CardCrypto::~CardCrypto()
{
    if (m_rsakeydata) {
        RSA_free(m_rsakeydata);
        m_rsakeydata = 0;
    }
}

bool
CardCrypto::RNGGetBytes(QByteArray &out, int num_bytes)
{
    unsigned char buf[256];
    int bytes_left = num_bytes;
    int rc1 = 1;
    out.clear();
    while (rc1 && bytes_left > 0) {
        int bytes_to_get = (size_t)bytes_left > sizeof(buf) ? sizeof(buf) : bytes_left;
        rc1 = RAND_bytes(buf,bytes_to_get);
        if (rc1) {
            bytes_left -= bytes_to_get;
            out += QByteArray((char *)buf,bytes_to_get);
        }
    }
    return (rc1 != 0);

}

bool CardCrypto::RSALoadKeyPEM(const QString &filename)
{
    bool rc = false;
    if (m_rsakeydata) {
        RSA_free(m_rsakeydata);
        m_rsakeydata = 0;
    }
    FILE *fp = fopen(filename.toLocal8Bit().data(), "rb");
    rc = (fp != NULL);
    if (rc) {
        m_rsakeydata = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
        fp = NULL;
        rc = (m_rsakeydata != NULL);
    }
    return rc;
}

bool
CardCrypto::RSAGenerateNewKeyPair(int keylen)
{
    if (m_rsakeydata) {
        RSA_free(m_rsakeydata);
        m_rsakeydata = 0;
    }
    m_rsakeydata = RSA_generate_key(keylen,3,NULL,NULL);
    return (m_rsakeydata != 0);
}

bool
CardCrypto::RSAExportPublicKeyInPKCS1(QByteArray & out)
{
    bool rc = false;
    if (m_rsakeydata) {
        QByteArray pem_out;
        BIO * mem = BIO_new(BIO_s_mem());
        if (mem) {
            rc = (PEM_write_bio_RSAPublicKey(mem,m_rsakeydata) != 0);
            char * p = 0;
            int len = BIO_get_mem_data(mem,&p);
            pem_out = QByteArray(p,len);
            BIO_free(mem);
            mem = 0;
        }
        if (rc) {
            // chop off the header and footer and then base64 decode it
            // what you have left is a PKCS1 RSA public key in binary DER format
            QByteArray b64buf = pem_out.right((pem_out.length() -
                                               sizeof("-----BEGIN RSA PUBLIC KEY-----"))
                                              );
            b64buf.chop(sizeof("-----END RSA PUBLIC KEY-----"));

            out = QByteArray::fromBase64(b64buf);
        }
    }
    return rc;
}

bool
CardCrypto::RSAEncryptWithPublicKey(QByteArray &in, QByteArray &out)
{
    bool rc = false;
    if (m_rsakeydata) {
        unsigned char outbuf[8192];
        int outlen = RSA_size(m_rsakeydata);
        if (sizeof(outbuf) > (size_t)outlen) {
            if (RSA_public_encrypt(in.length(),(unsigned char *)in.data(),outbuf,m_rsakeydata,RSA_PKCS1_PADDING) != -1) {
                out = QByteArray((const char *)outbuf,outlen);
                rc = true;
            }
        }
    }
    return rc;
}

bool
CardCrypto::RSADecryptWithPrivateKey(QByteArray &in, QByteArray &out)
{
    bool rc = false;
    if (m_rsakeydata) {
        unsigned char outbuf[8192];
        int outlen = RSA_private_decrypt(in.length(),(unsigned char *)in.data(),outbuf,m_rsakeydata,RSA_PKCS1_PADDING);
        if (outlen > 0) {
            out = QByteArray((char *)outbuf,outlen);
            rc = true;
        }
    }
    return rc;
}

bool
CardCrypto::AES256CBCEncrypt(QByteArray &key,QByteArray &iv,QByteArray &in,QByteArray &out)
{
    out.clear();
    AES_KEY teh_key;
    AES_set_encrypt_key((const unsigned char *)key.data(),256,&teh_key);
    bool firstblock = true;
    int i=0,j=0;
    unsigned char plainblock[16];
    unsigned char cipherblock[16];
    while (i < in.length()) {
        memset(plainblock,0,sizeof(plainblock));
        unsigned char *p = plainblock;
        for(j=i; j<i+16 && j<in.length(); ++j) {
             *p = in[j];
            ++p;
        }
        i = j;
        if (firstblock) {
            firstblock = false;
            for(int k=0; k<16; ++k) { plainblock[k] ^= iv[k]; }
        } else {
            for(int k=0; k<16; ++k) { plainblock[k] ^= cipherblock[k]; }
        }
        AES_encrypt(plainblock,cipherblock,&teh_key);
        out.append((const char *)cipherblock,16);
    }
    return true;
}

bool
CardCrypto::AES256CBCDecrypt(QByteArray &key,QByteArray &iv,QByteArray &in,QByteArray &out)
{
    out.clear();
    AES_KEY teh_key;
    AES_set_decrypt_key((const unsigned char *)key.data(),256,&teh_key);
    bool firstblock = true;
    int i=0,j=0;
    unsigned char block[16];
    unsigned char plainblock[16];
    unsigned char cipherblock[16];
    while (i < in.length()) {
        memset(block,0,sizeof(block));
        unsigned char *p = block;
        for(j=i; j<i+16 && j<in.length(); ++j) {
             *p = in[j];
            ++p;
        }
        i = j;
        AES_decrypt(block,plainblock,&teh_key);
        if (firstblock) {
            firstblock = false;
            for(int k=0; k<16; ++k) { plainblock[k] ^= iv[k]; }
        } else {
            for(int k=0; k<16; ++k) { plainblock[k] ^= cipherblock[k]; }
        }
        memcpy(cipherblock,block,16);
        out.append((const char*)plainblock,sizeof(plainblock));
    }

    return true;
}

bool
CardCrypto::SHA256Hash(QByteArray &in, QByteArray &out)
{
    bool rc = false;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX hasherctx;
    rc = (SHA256_Init(&hasherctx) != 0);
    if (rc) {
        rc = (SHA256_Update(&hasherctx,in.data(),in.length()) != 0);
        if (rc) {
            rc = (SHA256_Final(digest,&hasherctx) != 0);
            out = QByteArray((const char *)digest,SHA256_DIGEST_LENGTH);
        }
    }
    return rc;
}

long
CardCrypto::CheckSum(const QByteArray &in)
{
    long sum = 0;
    for (int i=0; i<in.length(); ++i) {
        sum += (unsigned char)in[i];
    }
    return sum;
}
