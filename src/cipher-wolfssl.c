/*
 * File:   cipher-wolfssl.c
 * Author: lizhou
 *
 * Created on 2017年3月26日, 下午 3:54
 */


#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(__linux__)
/* Linux. --------------------------------------------------- */
#include <linux/random.h>
#include <features.h>
#endif
#ifdef _MSC_VER
#include <malloc.h>
#endif
#include <wolfssl/wolfcrypt/aes.h>
#define HAVE_CHACHA
#define HAVE_POLY1305
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#define HAVE_HKDF
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/md5.h>
//#define HAVE_HASHDRBG
#include <wolfssl/wolfcrypt/random.h>
#include "defs.h"
#include "cipher-wolfssl.h"
#include "client.h"

extern server_config config;
cipher_t cipher;

void initialize_cipher()
{
    int ret;
    pr_info("%s %s", __FUNCTION__, config.method);
    if (strcmp(config.method, "rc4-md5") == 0)
    {
        cipher.keyl = 16;
        cipher.ivl = 16;
        cipher.key = malloc(cipher.keyl);
        bytes_to_key((uint8_t *) config.password, (int) strlen(config.password), cipher.key, 0);
        cipher.encrypt.iv = malloc(cipher.ivl);
        cipher.decrypt.iv = malloc(cipher.ivl);
    }
    else if (strcmp(config.method, "chacha20-ietf") == 0 || strcmp(config.method, "chacha20-ietf-poly1305") == 0)
    {
        cipher.keyl = 32;
        cipher.ivl = 12;
        cipher.key = malloc(cipher.keyl);
        bytes_to_key((uint8_t *) config.password, (int) strlen(config.password), cipher.key, 0);
#if defined(NDEBUG)
#else
        dump("KEY",cipher.key,cipher.keyl);
#endif
        if (strcmp(config.method, "chacha20-ietf") == 0)
        {
            wc_Chacha_SetKey(&cipher.encrypt.chacha, cipher.key, cipher.keyl);
            wc_Chacha_SetKey(&cipher.decrypt.chacha, cipher.key, cipher.keyl);
            cipher.encrypt.iv = malloc(cipher.ivl);
            cipher.decrypt.iv = malloc(cipher.ivl);
        }
        else
        {
//            cipher.saltl = 32;
            cipher.ivl = 32;
            cipher.encrypt.iv = malloc(cipher.ivl);
            cipher.decrypt.iv = malloc(cipher.ivl);
            cipher.encrypt.sub_key = malloc(cipher.keyl);
            cipher.decrypt.sub_key = malloc(cipher.keyl);
        }
    }
    else if (strcmp(config.method, "hc-128") == 0)
    {
        cipher.keyl = 16;
        cipher.ivl = 16;
        cipher.key = malloc(cipher.keyl);
        bytes_to_key((uint8_t *) config.password, (int) strlen(config.password), cipher.key, 0);
        cipher.encrypt.iv = malloc(cipher.ivl);
        cipher.decrypt.iv = malloc(cipher.ivl);
    }
    else if (strcmp(config.method, "rabbit") == 0)
    {
        cipher.keyl = 16;
        cipher.ivl = 8;
        cipher.key = malloc(cipher.keyl);
        bytes_to_key((uint8_t *) config.password, (int) strlen(config.password), cipher.key, 0);
        cipher.encrypt.iv = malloc(cipher.ivl);
        cipher.decrypt.iv = malloc(cipher.ivl);
    }
    else if (strcmp(config.method,"aes-128-gcm") == 0 || strcmp(config.method,"aes-192-gcm") == 0 || strcmp(config.method,"aes-256-gcm") == 0)
    {
        if (strcmp(config.method,"aes-128-gcm") == 0)
        {
            cipher.keyl = 16;
            cipher.ivl = 16;
        }
        else if (strcmp(config.method,"aes-192-gcm") == 0)
        {
            cipher.keyl = 24;
            cipher.ivl = 24;
        }
        else
        {
            cipher.keyl = 32;
            cipher.ivl = 32;
        }
        cipher.key = malloc(cipher.keyl);
        bytes_to_key((uint8_t *) config.password, (int) strlen(config.password), cipher.key, 0);
#if defined(NDEBUG)
#else
        dump("KEY",cipher.key,cipher.keyl);
#endif
        cipher.encrypt.iv = malloc(cipher.ivl);
        cipher.decrypt.iv = malloc(cipher.ivl);
        cipher.encrypt.sub_key = malloc(cipher.keyl);
        cipher.decrypt.sub_key = malloc(cipher.keyl);
    }
    else
    {
        pr_err("%s is not supported.", config.method);
        cleanup_cipher();
        exit(1);
    }
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
    uint8_t *dst;
    ASSERT( plain == c->t.buf);
    //    pr_info("%s %lu", __FUNCTION__, plainl);
    //    cipher_t * cipher = shadow->cipher;
    //unsigned char * encrypt = 0;

//    uint8_t * plainptr;
    // if (!cipher.encrypt.init) {
    if (c->request_length)
    {
        int ret;
        size_t prepend;
        RNG  rng;

#ifdef HAVE_CAVIUM
        wc_InitRngCavium(&rng, CAVIUM_DEV_ID);
#endif
        ret = wc_InitRng(&rng);
        if (ret != 0) {
            pr_err("%s:RNG init failed",__FUNCTION__);
            return;
        }
        else
        {
            ret = wc_RNG_GenerateBlock(&rng, cipher.encrypt.iv, cipher.ivl);
            if (ret != 0)
            {
                pr_err("%s: generating block failed!",__FUNCTION__);
                return; //generating block failed!
            }
            else
            {
#if defined(NDEBUG)
#else
                dump("Encryption IV",cipher.encrypt.iv,cipher.ivl);
#endif
//#if defined (_MSC_VER)
//        uint8_t * src, * ptr;
//#else
//		unsigned int srcl,ptrl;
//		uint8_t src[srcl],ptr[ptrl];
//#endif

                if (strcmp(config.method, "rc4-md5") == 0)
                {
                    unsigned char *true_key = malloc(MD5_DIGEST_LENGTH);
                    create_key(cipher.encrypt.iv, cipher.ivl,true_key);
                    wc_Arc4SetKey(&cipher.encrypt.arc4, true_key, cipher.keyl);
                    free(true_key);
                }
                else if (strcmp(config.method, "chacha20-ietf-poly1305") == 0)
                {
                    int ret;
                    ret = wc_HKDF(SHA, cipher.key, cipher.keyl, cipher.encrypt.iv, cipher.keyl,"ss-subkey", strlen("ss-subkey"), cipher.encrypt.sub_key, cipher.keyl);

                    if ( ret != 0 ) {
                        pr_err("%s: error generating derived key",__FUNCTION__);
                        cleanup_cipher();
                        exit(1);
                    }
                    else
                    {
#if defined(NDEBUG)
#else
                        dump("ENCRYPTION SUBKEY",cipher.encrypt.sub_key,cipher.keyl);
#endif
                    }
                }
                else if (strcmp(config.method, "hc128") == 0)
                {
                    wc_Hc128_SetKey(&cipher.encrypt.hc128, cipher.key, cipher.encrypt.iv);
                }
                else if (strcmp(config.method, "rabbit") == 0)
                {
                    wc_RabbitSetKey(&cipher.encrypt.rabbit, cipher.key, cipher.encrypt.iv);
                }
                else if (strcmp(config.method,"aes-128-gcm") == 0 || strcmp(config.method,"aes-192-gcm") == 0 || strcmp(config.method,"aes-256-gcm") == 0)
                {
                    int ret;
                    ret = wc_HKDF(SHA, cipher.key, cipher.keyl, cipher.encrypt.iv, cipher.keyl,"ss-subkey", strlen("ss-subkey"), cipher.encrypt.sub_key, cipher.keyl);

                    if ( ret != 0 ) {
                        pr_err("%s: error generating derived key",__FUNCTION__);
                        cleanup_cipher();
                        exit(1);
                    }
                    else
                    {
#if defined(NDEBUG)
#else
                        dump("ENCRYPTION SUBKEY",cipher.encrypt.sub_key,cipher.keyl);
#endif
                    }
                    wc_AesGcmSetKey(&cipher.encrypt.aes, cipher.encrypt.sub_key, cipher.keyl);
                }
                /*
                #if defined(NDEBUG)
                #else
                dump("IV", cipher.encrypt.iv.base, cipher.encrypt.iv.len);
                #endif
                 */
                //            cipher.encrypt.iv.base = malloc(ivl);
                //            memcpy(cipher.encrypt.iv.base,iv,ivl);
                //            cipher.encrypt.iv.len = ivl;
                //        cipher.encrypt.init = 1;
                //    c->init = 1;
                //}

                //ASSERT(c->request.base != 0);
                //if( c->request.len )
                // {
                //        size_t prepend = shadow->socks5->len - 3
                //                pr_info("%s %lu", __FUNCTION__, c->request.len);
            }
            ret = wc_FreeRng(&rng);
            if (ret != 0)
            {
                pr_err("%s:free of rng failed!",__FUNCTION__ );
//	       return ;
            }
            prepend = c->request_length - 3;

//        src = malloc(prepend + plainl);
//#if defined (_MSC_VER)
//        src = _malloca(prepend + plainl);
//#else
//        src = malloc(prepend + plainl);
//#endif
            //        src = malloc(plainl);
//        ptr = src + prepend;
            //memcpy(src, &shadow->socks5->data->atyp, prepend);
            /*
            #if defined(NDEBUG)
            #else
                    dump("REQUEST", c->request.base, c->request.len);
                    dump("REQUEST2", c->request.base + 3, prepend);
            #endif
             */
            memcpy(c->process_text, cipher.encrypt.iv, cipher.ivl);
//        memcpy(src, c->request + 3, prepend);
            memcpy(c->t.buf + prepend, plain, plainl);
            memcpy(c->t.buf, c->request + 3, prepend);
            plainl += prepend;
            *encryptl = cipher.ivl + plainl;
//        encrypt = malloc(*encryptl);
//        memcpy(encrypt, cipher.encrypt.iv, cipher.ivl);
//        memcpy(c->process_text, cipher.encrypt.iv, cipher.ivl);
//        dst = (uint8_t *) encrypt + cipher.ivl;
            dst = (uint8_t *) c->process_text + cipher.ivl;
            //    printf("---iv---\n");
            //    for (i = 0; i < ivl; i++) printf("%02x ", iv[i]);
            //    printf("\n");
            //
            //    printf("---key---\n");
            //    for (i = 0; i < cipher->keyl; i++) printf("%02x ", cipher->key[i]);
            //    printf("\n");

            //        free(iv);
//        plain = (char *) src;
//        plainptr = src;
            //cipher.encrypt.init = 1
            //        c->init = 1;
//        c->request.base = 0;
//        if (c->request.base)
//        {
//            free(c->request.base);
//        }
            c->request_length = 0;
        }
    }
    else
    {
        //        pr_info("%s",__FUNCTION__);

        *encryptl = plainl;
//		plainptr = plain;
//        encrypt = malloc(*encryptl);
//        dst = (uint8_t *) encrypt;
        dst = (uint8_t *) c->process_text;
    }
    c->process_len = *encryptl;

    //    EVP_CipherUpdate(&cipher.encrypt.ctx, dst, &l, (uint8_t *) plain, (int) plainl);
//    arcfour_stream(&cipher.encrypt.ctx, plain, dst, plainl);
    if (strcmp(config.method, "rc4-md5") == 0)
    {
        wc_Arc4Process(&cipher.encrypt.arc4, dst, plain, plainl);
    }
    else if (strcmp(config.method, "chacha20-ietf") == 0)
    {
        int padding = c->counter % SODIUM_BLOCK_SIZE;
        wc_Chacha_SetIV(&cipher.encrypt.chacha, cipher.encrypt.iv, c->counter / SODIUM_BLOCK_SIZE);
        if (padding)
        {
            memmove(c->t.buf + padding, plain,plainl);
            memset(c->t.buf,0,padding);
            wc_Chacha_Process(&cipher.encrypt.chacha, dst, c->t.buf, plainl + padding);
            memmove(dst,dst + padding, plainl);
        }
        else
        {
            wc_Chacha_Process(&cipher.encrypt.chacha, dst, plain, plainl);
        }
        c->counter += plainl;
#if defined(NDEBUG)
#else
        pr_info("%s %u",__FUNCTION__,c->counter);
#endif
    }
    else if (strcmp(config.method, "chacha20-ietf-poly1305") == 0)
    {
//#if defined(NDEBUG)
//#else
//        dump("NONCE",c->nonce,12);
//#endif
        //pr_info("%s %lu",__FUNCTION__,plainl);
        int ret;
        uint16_t t;
        uint8_t len_buf[CHUNK_SIZE_LEN];
        unsigned char length_cipher[2];
        unsigned char length_tag[16];
        unsigned char data_tag[16];
        t = htons((plainl ) & CHUNK_SIZE_MASK);
        memcpy(len_buf, &t, CHUNK_SIZE_LEN);

        ret = wc_ChaCha20Poly1305_Encrypt(cipher.encrypt.sub_key, c->nonce, 0, 0,len_buf, CHUNK_SIZE_LEN, length_cipher, length_tag);
        increment_nonce(c->nonce);
//#if defined(NDEBUG)
//#else
//        dump("NONCE",c->nonce,12);
//#endif
        memcpy(dst,length_cipher,CHUNK_SIZE_LEN);
        memcpy(dst + CHUNK_SIZE_LEN, length_tag, 16);
        ret = wc_ChaCha20Poly1305_Encrypt(cipher.encrypt.sub_key, c->nonce, 0, 0,plain, plainl, dst + CHUNK_SIZE_LEN + 16 , data_tag);
        increment_nonce(c->nonce);
//#if defined(NDEBUG)
//#else
//        dump("NONCE",c->nonce,12);
//#endif
        memcpy(dst + CHUNK_SIZE_LEN + 16 + plainl, data_tag,16);
//#if defined(NDEBUG)
//#else
//        dump("FIRST CHUNK",c->process_text,plainl + 34);
//#endif
        c->process_len = *encryptl + 34;
    }
    else if (strcmp(config.method, "hc128") == 0)
    {
        wc_Hc128_Process(&cipher.encrypt.hc128, dst, plain, plainl);
    }
    else if (strcmp(config.method, "rabbit") == 0)
    {
        wc_RabbitProcess(&cipher.encrypt.rabbit, dst, plain, plainl);
    }
    else if (strcmp(config.method,"aes-128-gcm") == 0 || strcmp(config.method,"aes-192-gcm") == 0 || strcmp(config.method,"aes-256-gcm") == 0)
    {
        int ret;
        uint16_t t;
        uint8_t len_buf[CHUNK_SIZE_LEN];
        unsigned char length_cipher[2];
        unsigned char length_tag[16];
        unsigned char data_tag[16];
        t = htons((plainl ) & CHUNK_SIZE_MASK);
        memcpy(len_buf, &t, CHUNK_SIZE_LEN);

        ret = wc_AesGcmEncrypt(&cipher.encrypt.aes,length_cipher,len_buf, CHUNK_SIZE_LEN,c->nonce, 12,length_tag,16, 0, 0);
        increment_nonce(c->nonce);
//#if defined(NDEBUG)
//#else
//        dump("NONCE",c->nonce,12);
//#endif
        memcpy(dst,length_cipher,CHUNK_SIZE_LEN);
        memcpy(dst + CHUNK_SIZE_LEN, length_tag, 16);
        ret = wc_AesGcmEncrypt(&cipher.encrypt.aes, dst + CHUNK_SIZE_LEN + 16,plain,plainl,c->nonce,12, data_tag,16,0,0);
        increment_nonce(c->nonce);
//#if defined(NDEBUG)
//#else
//        dump("NONCE",c->nonce,12);
//#endif
        memcpy(dst + CHUNK_SIZE_LEN + 16 + plainl, data_tag,16);
//#if defined(NDEBUG)
//#else
//        dump("FIRST CHUNK",c->process_text,plainl + 34);
//#endif
        c->process_len = *encryptl + 34;
    }
    //  printf("---encrypt count---\n");
    //  printf("%d %lu %lu\n", _, *encryptl, plainl);

    //  printf("---encrypt plain---\n");
    //  for (i = 0; i < 20; i++) printf("%02x ", src[i]);
    //  printf("\n");

    //  printf("---encrypt---\n");
    //  for (i = 0; i < len; i++) printf("%02x ", dst[i]);
    //  printf("\n");
//#ifdef _MSC_VER
//    _freea(plain);
//#else
//    free(plain);
//#endif
//        free(plain);

//    return encrypt;
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
    uint8_t * src;
    ASSERT(encrypt == c->t.buf);
    //pr_info("%s %u %lu", __FUNCTION__, __LINE__,encryptl);
    //if (!cipher.decrypt.init) {
    //if (!c->init) {

    if (c->request_length < cipher.ivl)
    {
//        c->request.base = malloc(cipher.ivl);
        if ( c->request_length + encryptl < cipher.ivl )
        {

            memcpy(c->request + c->request_length, encrypt, encryptl);
            c->request_length += encryptl;
//            c->process_text = {0};
//            c->process_len = 0;
            return;
        }
        else
        {
            memcpy(cipher.decrypt.iv,c->request,c->request_length);
            //     int ivl;
            //        uint8_t * iv = malloc(ivl);
//        cipher.decrypt.iv.base = malloc(cipher.decrypt.iv.len);
            memcpy(cipher.decrypt.iv + c->request_length, encrypt, cipher.ivl - c->request_length);
#if defined(NDEBUG)
#else
            dump("Decryption IV",cipher.decrypt.iv,cipher.ivl);
#endif
            if (strcmp(config.method, "rc4-md5") == 0)
            {
                unsigned char *true_key = malloc(MD5_DIGEST_LENGTH);
                create_key(cipher.decrypt.iv, cipher.ivl,true_key);
                wc_Arc4SetKey(&cipher.decrypt.arc4,true_key , cipher.keyl);
                free(true_key);
            }
            else if (strcmp(config.method, "chacha20-ietf-poly1305") == 0)
            {
                int ret;
                ret = wc_HKDF(SHA, cipher.key, cipher.keyl, cipher.decrypt.iv, cipher.keyl,"ss-subkey", 9, cipher.decrypt.sub_key, cipher.keyl);
                if ( ret != 0 ) {
                    pr_err("%s: error generating derived key",__FUNCTION__);
                    do_kill(c->client);
                }
                else
                {
#if defined(NDEBUG)
#else
                    dump("DECRYPTION SUBKEY",cipher.decrypt.sub_key,cipher.keyl);
#endif
                }
            }
            else if (strcmp(config.method, "hc128") == 0)
            {
                wc_Hc128_SetKey(&cipher.decrypt.hc128, cipher.key, cipher.decrypt.iv);
            }
            else if (strcmp(config.method, "rabbit") == 0)
            {
                wc_RabbitSetKey(&cipher.decrypt.rabbit, cipher.key, cipher.decrypt.iv);
            }
            else if (strcmp(config.method,"aes-128-gcm") == 0 || strcmp(config.method,"aes-192-gcm") == 0 || strcmp(config.method,"aes-256-gcm") == 0)
            {
                int ret;
                ret = wc_HKDF(SHA, cipher.key, cipher.keyl, cipher.decrypt.iv, cipher.keyl,"ss-subkey", 9, cipher.decrypt.sub_key, cipher.keyl);
                if ( ret != 0 ) {
                    pr_err("%s: error generating derived key",__FUNCTION__);
                    do_kill(c->client);
                }
                else
                {
#if defined(NDEBUG)
#else
                    dump("DECRYPTION SUBKEY",cipher.decrypt.sub_key,cipher.keyl);
#endif
                }
                wc_AesGcmSetKey(&cipher.decrypt.aes, cipher.decrypt.sub_key, cipher.keyl);
            }
            //    if (c->request.base == 0) {

            *plainl = encryptl - cipher.ivl + c->request_length;
//          plain = malloc(*plainl);
            src = (uint8_t *) encrypt + cipher.ivl - c->request_length;
//          printf("---iv---\n");
//          for (i = 0; i < ivl; i++) printf("%02x ", iv[i]);
//          printf("\n");
//
//          printf("---key---\n");
            //    for (i = 0; i < cipher->keyl; i++) printf("%02x ", cipher->key[i]);
            //    printf("\n");
//            c->request.base = malloc(cipher.ivl);
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
//        plain = malloc(*plainl);

    }
    c->process_len = *plainl;
    //    int _;
    //    EVP_CipherUpdate(&cipher.decrypt.ctx, (uint8_t *) plain, &_, src, (int) *plainl);
//    arcfour_stream(&cipher.decrypt.ctx, src, plain, *plainl);
//	arcfour_stream(&cipher.decrypt.ctx, src, c->process_text, *plainl);

    if (strcmp(config.method, "rc4-md5") == 0)
    {
        wc_Arc4Process(&cipher.decrypt.arc4, c->process_text, src, *plainl);
    }
    else if (strcmp(config.method, "chacha20-ietf") == 0)
    {
        int padding = c->counter % SODIUM_BLOCK_SIZE;
        wc_Chacha_SetIV(&cipher.decrypt.chacha, cipher.decrypt.iv, c->counter / SODIUM_BLOCK_SIZE);
        if (padding)
        {
            memmove(c->t.buf + padding, src,*plainl);
            memset(c->t.buf,0,padding);
            wc_Chacha_Process(&cipher.decrypt.chacha, c->process_text, c->t.buf, padding + *plainl);
            memcpy(c->process_text,c->process_text + padding, *plainl);
        }
        else
        {
            wc_Chacha_Process(&cipher.decrypt.chacha, c->process_text, src, *plainl);
        }
        c->counter += *plainl;
#if defined(NDEBUG)
#else
        pr_info("%s %u",__FUNCTION__,c->counter);
#endif
    }
    else if (strcmp(config.method, "chacha20-ietf-poly1305") == 0)
    {
        unsigned int process_total = 0;
        //pr_info("%s %u %lu",__FUNCTION__,__LINE__,c->half_done);
        //pr_info("%s %u %lu",__FUNCTION__,__LINE__,*plainl);
        //pr_info("%s %u %lu",__FUNCTION__,__LINE__,c->partial_cipherl);
        memcpy(c->partial_cipher + c->partial_cipherl, src,*plainl);
        c->partial_cipherl += *plainl;
        //pr_info("%s %u %lu",__FUNCTION__,__LINE__,c->partial_cipherl);
        while ( c->partial_cipherl >0)
        {
//	    pr_info("%s %u %lu",__FUNCTION__,__LINE__,c->partial_cipherl);
//            c->partial_cipher = realloc(c->partial_cipher,c->partial_cipherl + *plainl);
            if (c->partial_cipherl   < 35)
            {
                c->process_len = 0;
                break;
            }
            else
            {
//#if defined(NDEBUG)
//#else
//                dump("CHUNK RECEIVED",c->partial_cipher,c->partial_cipherl);
//#endif
                if(!c->half_done)
                {
                    int ret;
                    unsigned char length_plain[2];
                    ret = wc_ChaCha20Poly1305_Decrypt(cipher.decrypt.sub_key, c->nonce, 0, 0,c->partial_cipher, CHUNK_SIZE_LEN, c->partial_cipher + CHUNK_SIZE_LEN, length_plain);

                    if(ret == MAC_CMP_FAILED_E) {
                        pr_err("%s:error during authentication",__FUNCTION__);
                        do_kill(c->client);
                    } else if( ret != 0) {
                        pr_err("%s:error with function arguments",__FUNCTION__);
                        do_kill(c->client);
                    }
                    else
                    {
                        unsigned int cipher_length;
                        increment_nonce(c->nonce);
//#if defined(NDEBUG)
//#else
//                        dump("NONCE",c->nonce,12);
//#endif
                        cipher_length = ntohs(*(uint16_t *)length_plain);
#if defined(NDEBUG)
#else
                        pr_info("%s %u %u",__FUNCTION__,__LINE__,cipher_length);
#endif
                        cipher_length = cipher_length & CHUNK_SIZE_MASK;
                        if (c->partial_cipherl < cipher_length + 34 )
                        {
                            c->half_done = 1;
                            c->payload_length = cipher_length;
                            //pr_info("%s %u %lu",__FUNCTION__,__LINE__,c->payload_length);
                            //c->process_len = 0;
                            break;
                        }
                        else
                        {
                            ret = wc_ChaCha20Poly1305_Decrypt(cipher.decrypt.sub_key, c->nonce, 0, 0,c->partial_cipher + 18, cipher_length, c->partial_cipher + 18 + cipher_length , c->process_text + process_total);
                            if(ret == MAC_CMP_FAILED_E) {
                                pr_err("%s:error during authentication",__FUNCTION__);
                                do_kill(c->client);
                            } else if( ret != 0) {
                                pr_err("%s:error with function arguments",__FUNCTION__);
                                do_kill(c->client);
                            }
                            else
                            {
                                increment_nonce(c->nonce);
//#if defined(NDEBUG)
//#else
//                                dump("NONCE",c->nonce,12);
//#endif
                                process_total += cipher_length;
//                                c->half_done = 0;
//                                c->payload_length = 0;
                                ASSERT(c->partial_cipherl >= cipher_length + 34);
                                c->partial_cipherl -= (cipher_length + 34);
                                //pr_info("%s %u %u",__FUNCTION__,__LINE__,c->partial_cipherl);
//                                c->partial_cipher = realloc(c->partial_cipher + cipher_length + 34, c->partial_cipherl);
                                if (c->partial_cipherl !=0)
                                {
                                    memmove(c->partial_cipher,c->partial_cipher + cipher_length + 34, c->partial_cipherl);
//				    memset(c->partial_cipher + c->partial_cipherl,0, 2048 - c->partial_cipherl );
                                }
                            }
                        }
                    }
                }
                else
                {
//#if defined(NDEBUG)
//#else
//                    pr_info("%s %u %u",__FUNCTION__,__LINE__,c->partial_cipherl);
//#endif
                    if (c->partial_cipherl < c->payload_length + 34 )
                    {
//                        c->half_done = 1;
//                        c->payload_length = cipher_length;
                        //c->process_len = 0;
                        break;
                    }
                    else
                    {
//#if defined(NDEBUG)
//#else
//                        dump("NONCE",c->nonce,12);
//#endif
                        //pr_info("%s %u %lu",__FUNCTION__,__LINE__,c->payload_length);
                        //pr_info("%s %u %lu",__FUNCTION__,__LINE__,process_total);
                        int ret;
                        ret = wc_ChaCha20Poly1305_Decrypt(cipher.decrypt.sub_key, c->nonce, 0, 0,c->partial_cipher + 18, c->payload_length, c->partial_cipher + 18 + c->payload_length , c->process_text + process_total);
                        if(ret == MAC_CMP_FAILED_E)
                        {
                            pr_err("%s:error during authentication",__FUNCTION__);
                            do_kill(c->client);
                        }
                        else if( ret != 0)
                        {
                            pr_err("%s:error with function arguments",__FUNCTION__);
                            do_kill(c->client);
                        }
                        else
                        {
                            increment_nonce(c->nonce);
//#if defined(NDEBUG)
//#else
//                            dump("NONCE",c->nonce,12);
//#endif
                            process_total += c->payload_length;

                            ASSERT(c->partial_cipherl >= c->payload_length + 34);
                            c->partial_cipherl -= (c->payload_length + 34);
                            if (c->partial_cipherl !=0)
                            {
//                            c->partial_cipher = realloc(c->partial_cipher + c->payload_length + 34, c->partial_cipherl);
                                memmove(c->partial_cipher,c->partial_cipher + c->payload_length + 34, c->partial_cipherl);
                            }
                            c->payload_length = 0;
                            c->half_done = 0;
//			    c->process_len = process_total;
                        }
                    }
                }
            }
        }
        c->process_len = process_total;
//	pr_info("%s %u %lu",__FUNCTION__,__LINE__,c->process_len);
    }
    else if (strcmp(config.method, "hc128") == 0)
    {
        wc_Hc128_Process(&cipher.decrypt.hc128, c->process_text, src, *plainl);
    }
    else if (strcmp(config.method, "rabbit") == 0)
    {
        wc_RabbitProcess(&cipher.decrypt.rabbit, c->process_text, src, *plainl);
    }
    else if (strcmp(config.method,"aes-128-gcm") == 0 || strcmp(config.method,"aes-192-gcm") == 0 || strcmp(config.method,"aes-256-gcm") == 0)
    {
        unsigned int process_total = 0;
        //pr_info("%s %u %lu",__FUNCTION__,__LINE__,c->half_done);
        pr_info("%s %u %lu",__FUNCTION__,__LINE__,c->partial_cipherl);
	pr_info("%s %u %lu",__FUNCTION__,__LINE__,*plainl);
        memcpy(c->partial_cipher + c->partial_cipherl, src,*plainl);
        c->partial_cipherl += *plainl;
        //pr_info("%s %u %lu",__FUNCTION__,__LINE__,c->partial_cipherl);
        while ( c->partial_cipherl >0)
        {
//	    pr_info("%s %u %lu",__FUNCTION__,__LINE__,c->partial_cipherl);
//            c->partial_cipher = realloc(c->partial_cipher,c->partial_cipherl + *plainl);
            if (c->partial_cipherl   < 35)
            {
                c->process_len = 0;
                break;
            }
            else
            {
//#if defined(NDEBUG)
//#else
//                dump("CHUNK RECEIVED",c->partial_cipher,c->partial_cipherl);
//#endif
                if(!c->half_done)
                {
                    int ret;
                    unsigned char length_plain[2];
                    ret = wc_AesGcmDecrypt(&cipher.decrypt.aes,length_plain,c->partial_cipher,CHUNK_SIZE_LEN,c->nonce, 12,c->partial_cipher + CHUNK_SIZE_LEN,16,0, 0);

                    if(ret == AES_GCM_AUTH_E) {
                        pr_err("%s:error during authentication",__FUNCTION__);
                        do_kill(c->client);
                    }
                    else
                    {
                        unsigned int cipher_length;
                        increment_nonce(c->nonce);
//#if defined(NDEBUG)
//#else
//                        dump("NONCE",c->nonce,12);
//#endif
                        cipher_length = ntohs(*(uint16_t *)length_plain);
#if defined(NDEBUG)
#else
                        pr_info("%s %u %u",__FUNCTION__,__LINE__,cipher_length);
#endif
                        cipher_length = cipher_length & CHUNK_SIZE_MASK;
                        if (c->partial_cipherl < cipher_length + 34 )
                        {
                            c->half_done = 1;
                            c->payload_length = cipher_length;
                            //pr_info("%s %u %lu",__FUNCTION__,__LINE__,c->payload_length);
                            //c->process_len = 0;
                            break;
                        }
                        else
                        {
                            ret = wc_AesGcmDecrypt(&cipher.decrypt.aes, c->process_text + process_total,c->partial_cipher + 18,cipher_length,c->nonce,12, c->partial_cipher + 18 + cipher_length,16,0, 0);
                            if(ret == AES_GCM_AUTH_E) {
                                pr_err("%s %s :error during authentication",__FUNCTION__,__LINE__);
                                do_kill(c->client);
                            }
                            else
                            {
                                increment_nonce(c->nonce);
//#if defined(NDEBUG)
//#else
//                                dump("NONCE",c->nonce,12);
//#endif
                                process_total += cipher_length;
//                                c->half_done = 0;
//                                c->payload_length = 0;
                                ASSERT(c->partial_cipherl >= cipher_length + 34);
                                c->partial_cipherl -= (cipher_length + 34);
                                //pr_info("%s %u %u",__FUNCTION__,__LINE__,c->partial_cipherl);
//                                c->partial_cipher = realloc(c->partial_cipher + cipher_length + 34, c->partial_cipherl);
                                if (c->partial_cipherl !=0)
                                {
                                    memmove(c->partial_cipher,c->partial_cipher + cipher_length + 34, c->partial_cipherl);
//				    memset(c->partial_cipher + c->partial_cipherl,0, 2048 - c->partial_cipherl );
                                }
                            }
                        }
                    }
                }
                else
                {
//#if defined(NDEBUG)
//#else
//                    pr_info("%s %u %u",__FUNCTION__,__LINE__,c->partial_cipherl);
//#endif
                    if (c->partial_cipherl < c->payload_length + 34 )
                    {
//                        c->half_done = 1;
//                        c->payload_length = cipher_length;
                        //c->process_len = 0;
                        break;
                    }
                    else
                    {
//#if defined(NDEBUG)
//#else
//                        dump("NONCE",c->nonce,12);
//#endif
                        //pr_info("%s %u %lu",__FUNCTION__,__LINE__,c->payload_length);
                        //pr_info("%s %u %lu",__FUNCTION__,__LINE__,process_total);
                        int ret;
                        ret = wc_AesGcmDecrypt(&cipher.decrypt.aes,c->process_text + process_total,c->partial_cipher + 18, c->payload_length, c->nonce, 12, c->partial_cipher + 18 + c->payload_length,16,0,0 );
                        if(ret == AES_GCM_AUTH_E)
                        {
                            pr_err("%s %s :error during authentication",__FUNCTION__,__LINE__);
                            do_kill(c->client);
                        }
                        else
                        {
                            increment_nonce(c->nonce);
//#if defined(NDEBUG)
//#else
//                            dump("NONCE",c->nonce,12);
//#endif
                            process_total += c->payload_length;

                            ASSERT(c->partial_cipherl >= c->payload_length + 34);
                            c->partial_cipherl -= (c->payload_length + 34);
                            if (c->partial_cipherl !=0)
                            {
//                            c->partial_cipher = realloc(c->partial_cipher + c->payload_length + 34, c->partial_cipherl);
                                memmove(c->partial_cipher,c->partial_cipher + c->payload_length + 34, c->partial_cipherl);
                            }
                            c->payload_length = 0;
                            c->half_done = 0;
//			    c->process_len = process_total;
                        }
                    }
                }
            }
        }
        c->process_len = process_total;
//	pr_info("%s %u %lu",__FUNCTION__,__LINE__,c->process_len);

    }
    //  printf("---decrypt plain---\n");
    //  for (i = 0; i < 5; i++) printf("%02x ", (unsigned char)plain[i]);
    //  printf("\n");

    //free(encrypt);

//    return plain;
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
    //    EVP_CIPHER_CTX_cleanup(&cipher.encrypt.ctx);
    //    EVP_CIPHER_CTX_cleanup(&cipher.decrypt.ctx);
}

void create_key(unsigned char * iv, int ivl,unsigned char * true_key)
{
//    unsigned char *true_key = malloc(MD5_DIGEST_LENGTH);
    unsigned char key_iv[32];
    memcpy(key_iv, cipher.key, ivl);
    memcpy(key_iv + 16, iv, ivl);
    //    MD5(key_iv, 32, true_key);
    md5(key_iv, 32, true_key);
    /*
    #if defined(NDEBUG)
    #else
    dump("RC4 KEY", true_key, ivl);
    #endif
     */
//    return (char *)true_key;
}

/*
 * message must be uint8_t[16]
 */
void md5(const uint8_t *text, size_t len, uint8_t *digest)
{
    Md5 md5;
    wc_InitMd5(&md5);
    wc_Md5Update(&md5, text, len);  // can be called again and again
    wc_Md5Final(&md5, digest);
}

int bytes_to_key(const uint8_t *pass, int datal, uint8_t *key, uint8_t *iv)
{
    unsigned char md_buf[MD5_DIGEST_LENGTH];
    int niv;
    int nkey;
    int addmd;
    unsigned int mds;
    unsigned int i;
    int rv;
//    md5_state_t hash_state;
    Md5 md5;
    //    nkey = cipher_key_size(cipher);
    nkey = cipher.keyl;
    //    niv = cipher_iv_size(cipher);
    niv = cipher.ivl;
    rv = nkey;
    if (pass == NULL)
    {
        return nkey;
    }

    addmd = 0;
    //    mds = md_get_size(md);
    mds = 16;
    for (;;)
    {
        int error;
        do
        {
            error = 1;
//            md5_init(&hash_state);
            wc_InitMd5(&md5);
            if (addmd)
            {
//                md5_append(&hash_state, &(md_buf[0]), mds);
                wc_Md5Update(&md5, &(md_buf[0]), mds);
            }
            else
            {
                addmd = 1;
            }
//            md5_append(&hash_state, pass, datal);
            wc_Md5Update(&md5,pass,datal);
//            md5_finish(&hash_state, &(md_buf[0]));
            wc_Md5Final(&md5,&(md_buf[0]));
            error = 0;
        }
        while (0);
        if (error)
        {
            memset(md_buf, 0, MD5_DIGEST_LENGTH);
            return 0;
        }

        i = 0;
        if (nkey)
        {
            for (;;)
            {
                if (nkey == 0) break;
                if (i == mds) break;
                if (key != NULL)
                    *(key++) = md_buf[i];
                nkey--;
                i++;
            }
        }
        if (niv && (i != mds))
        {
            for (;;)
            {
                if (niv == 0) break;
                if (i == mds) break;
                if (iv != NULL)
                    *(iv++) = md_buf[i];
                niv--;
                i++;
            }
        }
        if ((nkey == 0) && (niv == 0)) break;
    }
    memset(md_buf, 0, MD5_DIGEST_LENGTH);
    return rv;
}

/* This assumes a 12-byte nonce! */
void increment_nonce(unsigned char *nonce) {
    if (!++nonce[0]) if (!++nonce[1]) if (!++nonce[2]) if (!++nonce[3])
                    if (!++nonce[4]) if (!++nonce[5]) if (!++nonce[6]) if (!++nonce[7])
                                    if (!++nonce[8]) if (!++nonce[9]) if (!++nonce[10]) if (!++nonce[11])
                                                {
                                                    /* If you get here, you're out of nonces.  This really shouldn't happen
                                                     * with an 12-byte nonce;
                                                     */
                                                    return;
                                                }
//#if defined(NDEBUG)
//#else
//    dump("NONCE",nonce,12);
//#endif
}
