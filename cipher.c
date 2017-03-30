//
//  crypt.c
//  shadowsocks-libuv
//
//  Created by Cube on 14/11/9.
//  Copyright (c) 2014年 Cube. All rights reserved.
//
/* 
 * File:   cipher.c
 * Author: lizhou
 *
 * Created on 2017年3月26日, 下午 3:54
 */

#include <string.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include "defs.h"
#include "cipher.h"

extern server_config config;
cipher_t cipher;

void initialize_cipher() {
    OpenSSL_add_all_algorithms();

    //    cipher_t * cipher = calloc(1, sizeof (cipher_t));
    //cipher.encrypt.init = 0;
    //cipher.decrypt.init = 0;
    pr_info("%s %s", __FUNCTION__, config.method);
    if (strcmp(config.method, "rc4-md5") == 0) {
        config.method = "rc4";
    }
    cipher.type = EVP_get_cipherbyname(config.method);
    if (cipher.type) {
        cipher.keyl = EVP_CIPHER_key_length(cipher.type);
        cipher.key = malloc(cipher.keyl);

        EVP_CIPHER_CTX_init(&cipher.encrypt.ctx);
        EVP_CIPHER_CTX_init(&cipher.decrypt.ctx);

        EVP_BytesToKey(cipher.type, EVP_md5(), 0,
                (uint8_t *) config.password, (int) strlen(config.password), 1,
                cipher.key, 0);
        /*
        #if defined(NDEBUG)
        #else
                dump("KEY", cipher.key, cipher.keyl);
        #endif
         */
    } else {
        cleanup_cipher();
        pr_err("wrong cipher name %s;", config.method);
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

unsigned char * cipher_encrypt(conn* c, size_t * encryptl,
        char * plain, size_t plainl) {
    //    pr_info("%s %lu", __FUNCTION__, plainl);
    //    cipher_t * cipher = shadow->cipher;
    unsigned char * encrypt = 0;

    uint8_t * dst;

    // if (!cipher.encrypt.init) {
    if (c->request.len) {
        //            int ivl;
        if (strcmp(config.method, "rc4") == 0) {
            cipher.encrypt.iv.len = 16;
        } else {
            cipher.encrypt.iv.len = EVP_CIPHER_iv_length(cipher.type);
        }
        //            uint8_t * iv = malloc(ivl);
        cipher.encrypt.iv.base = malloc(cipher.encrypt.iv.len);
        RAND_bytes(cipher.encrypt.iv.base, cipher.encrypt.iv.len);
        /*
#if defined(NDEBUG)
#else
        dump("IV", cipher.encrypt.iv.base, cipher.encrypt.iv.len);
#endif
         */
        //            cipher.encrypt.iv.base = malloc(ivl);
        //            memcpy(cipher.encrypt.iv.base,iv,ivl);
        //            cipher.encrypt.iv.len = ivl;
        if (strcmp(config.method, "rc4") == 0) {
            EVP_CipherInit_ex(&cipher.encrypt.ctx, cipher.type, 0, create_key(cipher.encrypt.iv.base, cipher.encrypt.iv.len), 0, 1);
        } else {
            EVP_CipherInit_ex(&cipher.encrypt.ctx, cipher.type, 0, cipher.key, cipher.encrypt.iv.base, 1);
        }
        //        cipher.encrypt.init = 1;
        //    c->init = 1;    
        //}

        //ASSERT(c->request.base != 0);
        //if( c->request.len )
        // {
        //        size_t prepend = shadow->socks5->len - 3
        //                pr_info("%s %lu", __FUNCTION__, c->request.len);
        size_t prepend = c->request.len - 3;

        uint8_t * src, * ptr;
        src = malloc(prepend + plainl);
        //        src = malloc(plainl);
        ptr = src + prepend;
        //memcpy(src, &shadow->socks5->data->atyp, prepend);
        /*
        #if defined(NDEBUG)
        #else
                dump("REQUEST", c->request.base, c->request.len);
                dump("REQUEST2", c->request.base + 3, prepend);
        #endif
         */
        memcpy(src, c->request.base + 3, prepend);
        memcpy(ptr, plain, plainl);
        plainl += prepend;
        *encryptl = cipher.encrypt.iv.len + plainl;
        encrypt = malloc(*encryptl);
        memcpy(encrypt, cipher.encrypt.iv.base, cipher.encrypt.iv.len);
        dst = (uint8_t *) encrypt + cipher.encrypt.iv.len;
        //    printf("---iv---\n");
        //    for (i = 0; i < ivl; i++) printf("%02x ", iv[i]);
        //    printf("\n");
        //
        //    printf("---key---\n");
        //    for (i = 0; i < cipher->keyl; i++) printf("%02x ", cipher->key[i]);
        //    printf("\n");

        //        free(iv);
        plain = (char *) src;
        //cipher.encrypt.init = 1
        //        c->init = 1;
        c->request.base = 0;
        c->request.len = 0;
    } else {
        //        pr_info("%s",__FUNCTION__); 

        *encryptl = plainl;
        encrypt = malloc(*encryptl);
        dst = (uint8_t *) encrypt;
    }

    int _;
    EVP_CipherUpdate(&cipher.encrypt.ctx, dst, &_, (uint8_t *) plain, (int) plainl);
    //  printf("---encrypt count---\n");
    //  printf("%d %lu %lu\n", _, *encryptl, plainl);

    //  printf("---encrypt plain---\n");
    //  for (i = 0; i < 20; i++) printf("%02x ", src[i]);
    //  printf("\n");

    //  printf("---encrypt---\n");
    //  for (i = 0; i < len; i++) printf("%02x ", dst[i]);
    //  printf("\n");

    //    free(plain);

    return encrypt;
}

unsigned char * cipher_decrypt(conn *c, size_t * plainl, char * encrypt, size_t encryptl) {
    //    pr_info("%s %lu", __FUNCTION__, encryptl);
    //    cipher_t * cipher = shadow->cipher;
    unsigned char * plain = 0;

    uint8_t * src;

    //if (!cipher.decrypt.init) {
    //if (!c->init) {
    if (!c->request.len) {
        //     int ivl;
        if (strcmp(config.method, "rc4") == 0) {
            cipher.decrypt.iv.len = 16;
        } else {
            cipher.decrypt.iv.len = EVP_CIPHER_iv_length(cipher.type);
        }
        //        uint8_t * iv = malloc(ivl);
        cipher.decrypt.iv.base = malloc(cipher.decrypt.iv.len);
        memcpy(cipher.decrypt.iv.base, encrypt, cipher.decrypt.iv.len);
        if (strcmp(config.method, "rc4") == 0) {

            EVP_CipherInit_ex(&cipher.decrypt.ctx, cipher.type, 0, create_key(cipher.decrypt.iv.base, cipher.decrypt.iv.len), 0, 0);
        } else {
            EVP_CipherInit_ex(&cipher.decrypt.ctx, cipher.type, 0, cipher.key, cipher.decrypt.iv.base, 0);
        }

        //    if (c->request.base == 0) {

        *plainl = encryptl - cipher.decrypt.iv.len;
        plain = malloc(*plainl);
        src = (uint8_t *) encrypt + cipher.decrypt.iv.len;
        //    printf("---iv---\n");
        //    for (i = 0; i < ivl; i++) printf("%02x ", iv[i]);
        //    printf("\n");
        //
        //    printf("---key---\n");
        //    for (i = 0; i < cipher->keyl; i++) printf("%02x ", cipher->key[i]);
        //    printf("\n");
        c->request.base = malloc(cipher.decrypt.iv.len);
        memcpy(c->request.base, cipher.decrypt.iv.base, cipher.decrypt.iv.len);
        c->request.len = cipher.decrypt.iv.len;
        //        free(iv);
        //    cipher.decrypt.init = 1;
        //        c->init = 1;
    } else {

        *plainl = encryptl;
        src = (uint8_t *) encrypt;
        plain = malloc(*plainl);

    }

    int _;
    EVP_CipherUpdate(&cipher.decrypt.ctx, (uint8_t *) plain, &_, src, (int) *plainl);

    //  printf("---decrypt plain---\n");
    //  for (i = 0; i < 5; i++) printf("%02x ", (unsigned char)plain[i]);
    //  printf("\n");

    //free(encrypt);

    return plain;
}

#if defined(NDEBUG)
#else

void
dump(unsigned char *tag, unsigned char *text, unsigned int len) {
    int i;
    printf("%s: ", tag);
    for (i = 0; i < len; i++)
        printf("0x%02x ", text[i]);
    printf("\n");
}
#endif

void cleanup_cipher() {
    EVP_CIPHER_CTX_cleanup(&cipher.encrypt.ctx);
    EVP_CIPHER_CTX_cleanup(&cipher.decrypt.ctx);
}

unsigned char * create_key(char * iv, int ivl) {

    unsigned char *true_key = malloc(MD5_DIGEST_LENGTH);
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
    return true_key;
}