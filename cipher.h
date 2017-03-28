/* 
 * File:   cipher.h
 * Author: lizhou
 *
 * Created on 2017年3月26日, 下午 3:54
 */

#ifndef CIPHER_H
#define	CIPHER_H
#include <openssl/evp.h>

#ifdef	__cplusplus
extern "C" {
#endif

    typedef struct {
            size_t keyl;
    uint8_t * key;
    const EVP_CIPHER * type;
        struct {
            int init;
            EVP_CIPHER_CTX ctx;
            uv_buf_t iv;
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
    unsigned char* cipher_encrypt(conn*, size_t * encryptl,
            char * plain, size_t plainl);
    unsigned char * cipher_decrypt(conn *,size_t * plainl,
            char * encrypt, size_t encryptl);
    void cleanup_cipher();
    unsigned char * create_key(char * iv,int);
#ifdef	__cplusplus
}
#endif
#endif	/* CIPHER_H */

