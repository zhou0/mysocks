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
        size_t ivl;
        uint8_t * key;
        const EVP_CIPHER * type;

        struct {
            //            int init;
            EVP_CIPHER_CTX ctx;
//            uv_buf_t iv;
            uint8_t * iv;   
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
    void cipher_encrypt(conn*, size_t * encryptl,
            const char * plain, size_t plainl);
    void cipher_decrypt(conn *, size_t * plainl,
            const char * encrypt, size_t encryptl);
#endif
    void cleanup_cipher();
    unsigned char * create_key(unsigned char * iv, int);
#ifdef	__cplusplus
}
#endif
#endif	/* CIPHER_H */

