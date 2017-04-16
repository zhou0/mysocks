//
//  crypt.c
//  shadowsocks-libuv
//
//  Created by Cube on 14/11/9.
//  Copyright (c) 2014年 Cube. All rights reserved.
//
/*
 * File:   cipher-openssl.c
 * Author: lizhou
 *
 * Created on 2017年3月26日, 下午 3:54
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include "defs.h"
#include "cipher-openssl.h"

extern server_config config;
cipher_t cipher;

void initialize_cipher()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    //    cipher_t * cipher = calloc(1, sizeof (cipher_t));
    //cipher.encrypt.init = 0;
    //cipher.decrypt.init = 0;
    pr_info("%s %s", __FUNCTION__, config.method);
    if (strcmp(config.method, "rc4-md5") == 0)
    {
        config.method = "rc4";
    }
    cipher.type = EVP_get_cipherbyname(config.method);
    if (cipher.type)
    {
        cipher.keyl = EVP_CIPHER_key_length(cipher.type);
        if (strcmp(config.method, "rc4") == 0)
        {
            cipher.ivl = 16;
        }
        else
        {
            cipher.ivl = EVP_CIPHER_iv_length(cipher.type);
        }
        cipher.key = malloc(cipher.keyl);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_CIPHER_CTX_init(&cipher.encrypt.ctx);
        EVP_CIPHER_CTX_init(&cipher.decrypt.ctx);
#else
        cipher.encrypt.ctx = EVP_CIPHER_CTX_new();
        cipher.decrypt.ctx = EVP_CIPHER_CTX_new();
#endif
        EVP_BytesToKey(cipher.type, EVP_md5(), 0,
                       (uint8_t *) config.password, (int) strlen(config.password), 1,
                       cipher.key, 0);
        /*
        #if defined(NDEBUG)
        #else
                dump("KEY", cipher.key, cipher.keyl);
        #endif
         */
        cipher.encrypt.iv = malloc(cipher.ivl);
        cipher.decrypt.iv = malloc(cipher.ivl);
    }
    else
    {
        cleanup_cipher();
        pr_err("%s is not supported.", config.method);
        exit(1);
    }
    //    return cipher;
}
/*
cipher_t * create_cipher()
{
  cipher_t * cipherptr       = calloc(1, sizeof(cipher_t));
  EVP_CIPHER_CTX_init(&cipherptr->encrypt.ctx);
  EVP_CIPHER_CTX_init(&cipherptr->decrypt.ctx);
  return cipherptr;
}
 */

/*
void destroy_cipher(cipher_t * cipher) {
    if (!cipher) return;
 //   if (cipher->key) free(cipher->key);
    free(cipher);
}
 */

#if defined(_WIN64)
/* Microsoft Windows (64-bit). ------------------------------ */

#elif defined(_WIN32)
/* Microsoft Windows (32-bit). ------------------------------ */
void cipher_encrypt(conn* c, ULONG * encryptl,
                    const char * plain, size_t plainl)
#else
void cipher_encrypt(conn* c, size_t * encryptl,
                    const char * plain, size_t plainl)
#endif
{
    ASSERT( plain == c->t.buf);
    //    pr_info("%s %lu", __FUNCTION__, plainl);
    //    cipher_t * cipher = shadow->cipher;
//    unsigned char * encrypt = 0;

    uint8_t * dst;
    int outl;
    // if (!cipher.encrypt.init) {
    if (c->request_length)
    {
        //            int ivl;
        size_t prepend;
//        uint8_t * src, * ptr;
        //            uint8_t * iv = malloc(ivl);
//        cipher.encrypt.iv.base = malloc(cipher.encrypt.iv.len);
        RAND_bytes(cipher.encrypt.iv, cipher.ivl);
        /*
        #if defined(NDEBUG)
        #else
        dump("IV", cipher.encrypt.iv.base, cipher.encrypt.iv.len);
        #endif
         */
        //            cipher.encrypt.iv.base = malloc(ivl);
        //            memcpy(cipher.encrypt.iv.base,iv,ivl);
        //            cipher.encrypt.iv.len = ivl;
        if (strcmp(config.method, "rc4") == 0)
        {
            unsigned char *true_key = malloc(MD5_DIGEST_LENGTH);
            create_key(cipher.encrypt.iv, cipher.ivl,true_key);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            EVP_CipherInit_ex(&cipher.encrypt.ctx, cipher.type, 0,true_key, 0, 1);
#else
            EVP_CipherInit_ex(cipher.encrypt.ctx, cipher.type, 0, true_key, 0, 1);
#endif
            free(true_key);
        }
        else
        {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            EVP_CipherInit_ex(&cipher.encrypt.ctx, cipher.type, 0, cipher.key, cipher.encrypt.iv, 1);
#else
            EVP_CipherInit_ex(cipher.encrypt.ctx, cipher.type, 0, cipher.key, cipher.encrypt.iv, 1);
#endif
        }
        //        cipher.encrypt.init = 1;
        //    c->init = 1;
        //}

        //ASSERT(c->request != 0);
        //if( c->request_length )
        // {
        //        size_t prepend = shadow->socks5->len - 3
        //                pr_info("%s %lu", __FUNCTION__, c->request_length);

        prepend = c->request_length - 3;
//        src = malloc(prepend + plainl);
        //        src = malloc(plainl);
//        ptr = src + prepend;
        //memcpy(src, &shadow->socks5->data->atyp, prepend);
        /*
        #if defined(NDEBUG)
        #else
                dump("REQUEST", c->request, c->request_length);
                dump("REQUEST2", c->request + 3, prepend);
        #endif
         */
	memcpy(c->process_text, cipher.encrypt.iv, cipher.ivl);
	memcpy(c->t.buf + prepend, plain, plainl);
        memcpy(c->t.buf, c->request + 3, prepend);
        plainl += prepend;
        *encryptl = cipher.ivl + plainl;
//       encrypt = malloc(*encryptl);
//        memcpy(encrypt, cipher.encrypt.iv, cipher.ivl);
//        memcpy(c->process_text, cipher.encrypt.iv, cipher.ivl);
//        dst = (uint8_t *) encrypt + cipher.ivl;
        dst = (uint8_t *)c->process_text  + cipher.ivl;
        //    printf("---iv---\n");
        //    for (i = 0; i < ivl; i++) printf("%02x ", iv[i]);
        //    printf("\n");
        //
        //    printf("---key---\n");
        //    for (i = 0; i < cipher->keyl; i++) printf("%02x ", cipher->key[i]);
        //    printf("\n");

        //        free(iv);
//        plain = (char *) src;
        //cipher.encrypt.init = 1
        //        c->init = 1;
//        c->request = 0;
        c->request_length = 0;
    }
    else
    {
        //        pr_info("%s",__FUNCTION__);

        *encryptl = plainl;
//        encrypt = malloc(*encryptl);
//        dst = (uint8_t *) encrypt;
        dst = (uint8_t *)c->process_text;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CipherUpdate(&cipher.encrypt.ctx, dst, &outl, c->t.buf, (int) plainl);
#else
    EVP_CipherUpdate(cipher.encrypt.ctx, dst, &outl, c->t.buf, (int) plainl);
#endif
    //  printf("---encrypt count---\n");
    //  printf("%d %lu %lu\n", _, *encryptl, plainl);

    //  printf("---encrypt plain---\n");
    //  for (i = 0; i < 20; i++) printf("%02x ", src[i]);
    //  printf("\n");

    //  printf("---encrypt---\n");
    //  for (i = 0; i < len; i++) printf("%02x ", dst[i]);
    //  printf("\n");

    //    free(plain);

//   return encrypt;
}

#if defined(_WIN64)
/* Microsoft Windows (64-bit). ------------------------------ */

#elif defined(_WIN32)
/* Microsoft Windows (32-bit). ------------------------------ */
void cipher_decrypt(conn *c, ULONG * plainl, const char * encrypt, size_t encryptl)
#else
void cipher_decrypt(conn *c, size_t * plainl, const char * encrypt, size_t encryptl)
#endif
{
    //    pr_info("%s %lu", __FUNCTION__, encryptl);
    //    cipher_t * cipher = shadow->cipher;
//    unsigned char * plain = 0;

    uint8_t * src;
    int outl;
    //if (!cipher.decrypt.init) {
    //if (!c->init) {
//    if (!c->request_length)
//    {
    if (c->request_length < cipher.ivl)
    {
//        c->request = malloc(cipher.ivl);
        if ( c->request_length + encryptl < cipher.ivl )
        {

            memcpy(c->request + c->request_length, encrypt, encryptl);
            c->request_length += encryptl;
//            c->process_text = 0;
            c->cipher_len = 0;
            return;
        }
        else
        {
            memcpy(cipher.decrypt.iv,c->request,c->request_length);
            //     int ivl;
            //        uint8_t * iv = malloc(ivl);
//        cipher.decrypt.iv.base = malloc(cipher.decrypt.iv.len);
//        memcpy(cipher.decrypt.iv, encrypt, cipher.ivl);
            memcpy(cipher.decrypt.iv + c->request_length, encrypt, cipher.ivl - c->request_length);
            if (strcmp(config.method, "rc4") == 0)
            {
                unsigned char *true_key = malloc(MD5_DIGEST_LENGTH);
                create_key(cipher.decrypt.iv, cipher.ivl,true_key);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
                EVP_CipherInit_ex(&cipher.decrypt.ctx, cipher.type, 0, true_key, 0, 0);
#else
                EVP_CipherInit_ex(cipher.decrypt.ctx, cipher.type, 0, true_key, 0, 0);
#endif
                free(true_key);
            }
            else
            {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
                EVP_CipherInit_ex(&cipher.decrypt.ctx, cipher.type, 0, cipher.key, cipher.decrypt.iv, 0);
#else
                EVP_CipherInit_ex(cipher.decrypt.ctx, cipher.type, 0, cipher.key, cipher.decrypt.iv, 0);
#endif
            }

            //    if (c->request == 0) {

            *plainl = encryptl - cipher.ivl + c->request_length;;
//       plain = malloc(*plainl);
            src = (uint8_t *) encrypt + cipher.ivl - c->request_length;;
            //    printf("---iv---\n");
            //    for (i = 0; i < ivl; i++) printf("%02x ", iv[i]);
            //    printf("\n");
            //
            //    printf("---key---\n");
            //    for (i = 0; i < cipher->keyl; i++) printf("%02x ", cipher->key[i]);
            //    printf("\n");
//        c->request = malloc(cipher.ivl);
            memcpy(c->request, cipher.decrypt.iv, cipher.ivl);
            c->request_length = cipher.ivl;
            //        free(iv);
            //    cipher.decrypt.init = 1;
            //        c->init = 1;
        }
    }
    else
    {

        *plainl = encryptl;
        src = (uint8_t *) encrypt;
//       plain = malloc(*plainl);

    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CipherUpdate(&cipher.decrypt.ctx, (uint8_t *)c->process_text , &outl, src, (int) *plainl);
#else
    EVP_CipherUpdate(cipher.decrypt.ctx, (uint8_t *)c->process_text , &outl, src, (int) *plainl);
#endif

    //  printf("---decrypt plain---\n");
    //  for (i = 0; i < 5; i++) printf("%02x ", (unsigned char)plain[i]);
    //  printf("\n");

    //free(encrypt);

//   return plain;
}

#if defined(NDEBUG)
#else

void
dump(unsigned char *tag, unsigned char *text, unsigned int len)
{
    unsigned int i;
    printf("%s: ", tag);
    for (i = 0; i < len; i++)
        printf("0x%02x ", text[i]);
    printf("\n");
}
#endif

void cleanup_cipher()
{
    if (!cipher.key)
    {
        free(cipher.key);
    }
    if (!cipher.decrypt.iv)
    {
        free(cipher.decrypt.iv);
    }
    if (!cipher.encrypt.iv)
    {
        free(cipher.encrypt.iv);
    }
# if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(&cipher.encrypt.ctx);
    EVP_CIPHER_CTX_cleanup(&cipher.decrypt.ctx);
    EVP_cleanup();
#else
    EVP_CIPHER_CTX_free(cipher.encrypt.ctx);
    EVP_CIPHER_CTX_free(cipher.decrypt.ctx);
# endif
}

void create_key(unsigned char * iv, int ivl,unsigned char * true_key)
{
//    unsigned char *true_key = malloc(MD5_DIGEST_LENGTH);
    unsigned char key_iv[32];
    memcpy(key_iv, cipher.key, ivl);
    memcpy(key_iv + 16, iv, ivl);
    MD5(key_iv, 32, true_key);
    /*
    #if defined(NDEBUG)
    #else
    dump("RC4 KEY", true_key, ivl);
    #endif
     */
//    return true_key;
}
