/*
 * File:   cipher-wolfssl.h
 * Author: lizhou
 *
 * Created on 2017年3月31日, 下午 7:09
 */

#ifndef CIPHER_WOLFSSL_H
#define	CIPHER_WOLFSSL_H


#ifdef	__cplusplus
extern "C"
{
#endif

#include <stddef.h>
#if defined(_MSC_VER) && (_MSC_VER<=1500)
#include "stdint-msvc2008.h"
#else
#include <stdint.h>
#endif
#include <wolfssl/wolfcrypt/aes.h>
#define	HAVE_CHACHA
#include <wolfssl/wolfcrypt/arc4.h>
#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/hc128.h>
#include <wolfssl/wolfcrypt/rabbit.h>
#include "defs.h"
#define MD5_DIGEST_LENGTH 16
#define SODIUM_BLOCK_SIZE   64
#define CHUNK_SIZE_LEN          2
#define CHUNK_SIZE_MASK         0x3FFF
typedef struct
{
    size_t keyl;
    size_t ivl;
//    size_t saltl;
    uint8_t * key;
//    uint8_t * sub_key;
//    const EVP_CIPHER * type;

    struct
    {
        //            int init;
//        EVP_CIPHER_CTX ctx;
        union
        {
	    Aes aes;
            Arc4 arc4;
            ChaCha chacha;
            HC128 hc128;
            Rabbit rabbit;
        };
        uint8_t * iv;
        uint8_t * sub_key;
//	uint8_t nonce[12];
    } encrypt, decrypt;
} cipher_t;

#if defined(NDEBUG)
#else
void dump(unsigned char *tag, unsigned char *text, unsigned int len);
#endif
//cipher_t * cipher_new    (const char *);
void initialize_cipher();
//void destroy_cipher(cipher_t *);
//void    cipher_encrypt(shadow_t   *, size_t,  uv_buf_t *, uv_buf_t *);
//void      cipher_decrypt(shadow_t   *, size_t,  uv_buf_t *, uv_buf_t *);
#if defined(_WIN64)
/* Microsoft Windows (64-bit). ------------------------------ */

#elif defined(_WIN32)
/* Microsoft Windows (32-bit). ------------------------------ */
void cipher_encrypt(conn*, ULONG * encryptl,
                    const char * plain, size_t plainl);
void cipher_decrypt(conn *, ULONG * plainl,
                    const char * encrypt, size_t encryptl);
#else
void cipher_encrypt(conn *, size_t * encryptl,const char * plain, size_t plainl);
void cipher_decrypt(conn *, size_t * plainl,const char * encrypt, size_t encryptl);
#endif
void cleanup_cipher();
void create_key(unsigned char * iv, int,unsigned char *);
int bytes_to_key(const uint8_t *pass, int datal, uint8_t *key, uint8_t *iv);
void md5(const uint8_t *text, size_t, uint8_t *message);
void increment_nonce(unsigned char *);
#ifdef	__cplusplus
}
#endif

#endif	/* CIPHER_WOLFSSL_H */

