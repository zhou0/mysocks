//
//  crypt.c
//  shadowsocks-libuv
//
//  Created by Cube on 14/11/9.
//  Copyright (c) 2014年 Cube. All rights reserved.
//
/*
 * File:   cipher-wolfssl.c
 * Author: lizhou
 *
 * Created on 2017年3月26日, 下午 3:54
 */

#include <string.h>
#include <arpa/inet.h>
#include "defs.h"
#include "cipher-wolfssl.h"

extern server_config config;
cipher_t cipher;

void initialize_cipher()
{
//    wolfSSL_Init();

    //    cipher_t * cipher = calloc(1, sizeof (cipher_t));
    //cipher.encrypt.init = 0;
    //cipher.decrypt.init = 0;
    pr_info("%s %s", __FUNCTION__, config.method);
    if (strcmp(config.method, "rc4-md5") == 0)
    {
        config.method = "rc4";
    }
    if (strcmp(config.method, "rc4") == 0)
    {
        cipher.keyl = 16;
        cipher.ivl = 16;
        cipher.key = malloc(cipher.keyl);
        bytes_to_key((uint8_t *) config.password, (int) strlen(config.password), cipher.key, 0);
        cipher.encrypt.iv = malloc(cipher.ivl);
        cipher.decrypt.iv = malloc(cipher.ivl);
    }
    else if (strcmp(config.method, "aes-128-cfb") == 0 || strcmp(config.method, "aes-128-ctr") == 0 || strcmp(config.method, "aes-128-gcm") == 0)
    {
        cipher.keyl = 16;
        cipher.ivl = 16;
        cipher.key = malloc(cipher.keyl);
        bytes_to_key((uint8_t *) config.password, (int) strlen(config.password), cipher.key, 0);
        cipher.encrypt.iv = malloc(cipher.ivl);
        cipher.decrypt.iv = malloc(cipher.ivl);
    }
    else if (strcmp(config.method, "aes-192-cfb") == 0 || strcmp(config.method, "aes-192-ctr") == 0 || strcmp(config.method, "aes-192-gcm") == 0)
    {
        cipher.keyl = 24;
        cipher.ivl = 16;
        cipher.key = malloc(cipher.keyl);
        bytes_to_key((uint8_t *) config.password, (int) strlen(config.password), cipher.key, 0);
        cipher.encrypt.iv = malloc(cipher.ivl);
        cipher.decrypt.iv = malloc(cipher.ivl);
    }
    else if (strcmp(config.method, "aes-256-cfb") == 0 || strcmp(config.method, "aes-256-ctr") == 0 || strcmp(config.method, "aes-256-gcm") == 0)
    {
        cipher.keyl = 32;
        cipher.ivl = 16;
        cipher.key = malloc(cipher.keyl);
        bytes_to_key((uint8_t *) config.password, (int) strlen(config.password), cipher.key, 0);
        cipher.encrypt.iv = malloc(cipher.ivl);
        cipher.decrypt.iv = malloc(cipher.ivl);
    }
    else if (strcmp(config.method, "camellia-128-cfb") == 0)
    {
        cipher.keyl = 16;
        cipher.ivl = 16;
        cipher.key = malloc(cipher.keyl);
        bytes_to_key((uint8_t *) config.password, (int) strlen(config.password), cipher.key, 0);
        cipher.encrypt.iv = malloc(cipher.ivl);
        cipher.decrypt.iv = malloc(cipher.ivl);
    }
    else if (strcmp(config.method, "camellia-192-cfb") == 0)
    {
        cipher.keyl = 24;
        cipher.ivl = 16;
        cipher.key = malloc(cipher.keyl);
        bytes_to_key((uint8_t *) config.password, (int) strlen(config.password), cipher.key, 0);
        cipher.encrypt.iv = malloc(cipher.ivl);
        cipher.decrypt.iv = malloc(cipher.ivl);
    }
    else if (strcmp(config.method, "camellia-256-cfb") == 0)
    {
        cipher.keyl = 32;
        cipher.ivl = 16;
        cipher.key = malloc(cipher.keyl);
        bytes_to_key((uint8_t *) config.password, (int) strlen(config.password), cipher.key, 0);
        cipher.encrypt.iv = malloc(cipher.ivl);
        cipher.decrypt.iv = malloc(cipher.ivl);
    }
    else if (strcmp(config.method, "chacha20-ietf") == 0)
    {
        cipher.keyl = 32;
        cipher.ivl = 12;
        cipher.key = malloc(cipher.keyl);
        bytes_to_key((uint8_t *) config.password, (int) strlen(config.password), cipher.key, 0);
        cipher.encrypt.iv = malloc(cipher.ivl);
        cipher.decrypt.iv = malloc(cipher.ivl);
    }
    else if (strcmp(config.method, "chacha20-ietf-poly1305") == 0)
    {
        cipher.keyl = 32;
        cipher.ivl = 32;
        cipher.key = malloc(cipher.keyl);
        bytes_to_key((uint8_t *) config.password, (int) strlen(config.password), cipher.key, 0);
        cipher.encrypt.iv = malloc(cipher.ivl);
        cipher.decrypt.iv = malloc(cipher.ivl);
    }
    else if (strcmp(config.method, "hc128") == 0)
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
    else
    {
        pr_err("%s is not supported.", config.method);
	cleanup_cipher();
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

#if defined(_WIN32)
/* Microsoft Windows. ------------------------------ */
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
//        uint8_t * src, * ptr;

        //shadow->cipher->encrypt.iv = malloc(ivl);

//        RAND_bytes(cipher.encrypt.iv, cipher.ivl);
        WC_RNG rng;
        wc_InitRng(&rng);
        wc_RNG_GenerateBlock(&rng, cipher.encrypt.iv, (word32)cipher.ivl);
        wc_FreeRng(&rng);
        /*
        #if defined(NDEBUG)
        #else
                dump("IV", cipher.encrypt.iv, cipher.ivl);
        #endif
         */

        if (strcmp(config.method, "rc4") == 0 || strcmp(config.method, "rc4-md5") == 0)
        {
            unsigned char *true_key = malloc(MD5_DIGEST_LENGTH);
            create_key(cipher.encrypt.iv, (int)cipher.ivl, true_key);
            wc_Arc4SetKey(&cipher.encrypt.arc4, true_key, (word32)cipher.keyl);
            free(true_key);
        }
        else if (strcmp(config.method, "aes-128-ctr") == 0 || strcmp(config.method, "aes-192-ctr") == 0 || strcmp(config.method, "aes-256-ctr") == 0)
        {
            wc_AesSetKeyDirect(&cipher.encrypt.aes, cipher.key, (word32)cipher.keyl, cipher.encrypt.iv, AES_ENCRYPTION);
        }
        else if (strcmp(config.method, "chacha20-ietf-poly1305") == 0)
        {
            wc_AesSetKeyDirect(&cipher.encrypt.aes, cipher.key, (word32)cipher.keyl, 0, AES_ENCRYPTION);
            memset(c->nonce, 0, 12);
            memcpy(c->nonce + 4, cipher.encrypt.iv, 8);
        }
        else if (strcmp(config.method, "hc128") == 0)
        {
#if defined(HAVE_HC128) || defined(WOLFSSL_HC128)
            wc_Hc128_SetKey(&cipher.encrypt.hc128, cipher.key, cipher.encrypt.iv);
#endif
        }
        else if (strcmp(config.method, "rabbit") == 0)
        {
#if defined(HAVE_RABBIT) || defined(WOLFSSL_RABBIT)
            wc_RabbitSetKey(&cipher.encrypt.rabbit, cipher.key, cipher.encrypt.iv);
#endif
        }
        else if (strcmp(config.method, "chacha20-ietf") == 0)
        {
            wc_Chacha_SetKey(&cipher.encrypt.chacha, cipher.key, (word32)cipher.keyl);
            wc_Chacha_SetIV(&cipher.encrypt.chacha, cipher.encrypt.iv, 0);
        }

        prepend = c->request_length - 3;

        memcpy(c->process_text, cipher.encrypt.iv, cipher.ivl);
        memcpy(c->t.buf + prepend, plain, plainl);
        memcpy(c->t.buf, c->request + 3, prepend);
        plainl += prepend;

        *encryptl = cipher.ivl + plainl;
        dst = (uint8_t *) c->process_text + cipher.ivl;
        c->request_length = 0;
    }
    else
    {
        //        pr_info("%s",__FUNCTION__);

        *encryptl = plainl;
        dst = (uint8_t *) c->process_text;
    }
    c->process_len = *encryptl;

    if (strcmp(config.method, "rc4") == 0 || strcmp(config.method, "rc4-md5") == 0)
    {
        wc_Arc4Process(&cipher.encrypt.arc4, dst, (const byte *)c->t.buf, (word32)plainl);
    }
    else if (strcmp(config.method, "aes-128-ctr") == 0 || strcmp(config.method, "aes-192-ctr") == 0 || strcmp(config.method, "aes-256-ctr") == 0)
    {
        wc_AesCtrEncrypt(&cipher.encrypt.aes, dst, (const byte *)c->t.buf, (word32)plainl);
    }
    else if (strcmp(config.method, "chacha20-ietf-poly1305") == 0)
    {
        unsigned char length_plain[2];
        unsigned char length_cipher[2];
        unsigned int process_total = 0;
        *(uint16_t *)length_plain = htons(plainl);
        wc_AesGcmEncrypt(&cipher.encrypt.aes, length_cipher, length_plain, 2, c->nonce, 12, dst + 2, 16, 0, 0);
        increment_nonce(c->nonce);
        memcpy(dst, length_cipher, 2);
        process_total += 18;
        wc_AesGcmEncrypt(&cipher.encrypt.aes, dst + 18, (const byte *)c->t.buf, (word32)plainl, c->nonce, 12, dst + 18 + plainl, 16, 0, 0);
        increment_nonce(c->nonce);
        process_total += (plainl + 16);
        *encryptl += 34; // 2 length + 16 tag + 16 tag
        c->process_len = *encryptl;

    }
    else if (strcmp(config.method, "hc128") == 0)
    {
#if defined(HAVE_HC128) || defined(WOLFSSL_HC128)
        wc_Hc128_Process(&cipher.encrypt.hc128, dst, (const byte *)c->t.buf, (word32)plainl);
#endif
    }
    else if (strcmp(config.method, "rabbit") == 0)
    {
#if defined(HAVE_RABBIT) || defined(WOLFSSL_RABBIT)
        wc_RabbitProcess(&cipher.encrypt.rabbit, dst, (const byte *)c->t.buf, (word32)plainl);
#endif
    }
    else if (strcmp(config.method, "chacha20-ietf") == 0)
    {
        wc_Chacha_Process(&cipher.encrypt.chacha, dst, (const byte *)c->t.buf, (word32)plainl);
    }

}

#if defined(_WIN32)
/* Microsoft Windows. ------------------------------ */
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
//            c->process_text = 0;
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
            dump("Decryption IV",cipher.decrypt.iv,(unsigned int)cipher.ivl);
#endif
            if (strcmp(config.method, "rc4") == 0 || strcmp(config.method, "rc4-md5") == 0)
            {
                unsigned char *true_key = malloc(MD5_DIGEST_LENGTH);
                create_key(cipher.decrypt.iv, (int)cipher.ivl,true_key);
                wc_Arc4SetKey(&cipher.decrypt.arc4,true_key , (word32)cipher.keyl);
                free(true_key);
            }
            else if (strcmp(config.method, "aes-128-ctr") == 0 || strcmp(config.method, "aes-192-ctr") == 0 || strcmp(config.method, "aes-256-ctr") == 0)
            {
                wc_AesSetKeyDirect(&cipher.decrypt.aes, cipher.key, (word32)cipher.keyl, cipher.decrypt.iv, AES_ENCRYPTION);
            }
            else if (strcmp(config.method, "chacha20-ietf-poly1305") == 0)
            {
                wc_AesSetKeyDirect(&cipher.decrypt.aes, cipher.key, (word32)cipher.keyl, 0, AES_ENCRYPTION);
                memset(c->nonce,0,12);
                memcpy(c->nonce+4,cipher.decrypt.iv,8);
            }
            else if (strcmp(config.method, "hc128") == 0)
            {
#if defined(HAVE_HC128) || defined(WOLFSSL_HC128)
                wc_Hc128_SetKey(&cipher.decrypt.hc128, cipher.key, cipher.decrypt.iv);
#endif
            }
            else if (strcmp(config.method, "rabbit") == 0)
            {
#if defined(HAVE_RABBIT) || defined(WOLFSSL_RABBIT)
                wc_RabbitSetKey(&cipher.decrypt.rabbit, cipher.key, cipher.decrypt.iv);
#endif
            }
            else if (strcmp(config.method, "chacha20-ietf") == 0)
            {
                wc_Chacha_SetKey(&cipher.decrypt.chacha, cipher.key, (word32)cipher.keyl);
                wc_Chacha_SetIV(&cipher.decrypt.chacha, cipher.decrypt.iv, 0);
            }

            *plainl = encryptl - cipher.ivl + c->request_length;
            src = (uint8_t *) encrypt + cipher.ivl - c->request_length;
            memcpy(c->request, cipher.decrypt.iv, cipher.ivl);
            c->request_length = cipher.ivl;
        }
    }
    else
    {
        *plainl = encryptl;
        src = (uint8_t *) encrypt;
    }

    if (strcmp(config.method, "rc4") == 0 || strcmp(config.method, "rc4-md5") == 0)
    {
        c->process_len = *plainl;
        wc_Arc4Process(&cipher.decrypt.arc4, c->process_text, src, (word32)*plainl);
    }
    else if (strcmp(config.method, "aes-128-ctr") == 0 || strcmp(config.method, "aes-192-ctr") == 0 || strcmp(config.method, "aes-256-ctr") == 0)
    {
        c->process_len = *plainl;
        wc_AesCtrEncrypt(&cipher.decrypt.aes, c->process_text, src, (word32)*plainl);
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
        //pr_info("%s %u %u",__FUNCTION__,__LINE__,(unsigned int)*plainl);
        //pr_info("%s %u %u",__FUNCTION__,__LINE__,(unsigned int)c->partial_cipherl);
        memcpy(c->partial_cipher + c->partial_cipherl, src,*plainl);
        c->partial_cipherl += *plainl;
        //pr_info("%s %u %u",__FUNCTION__,__LINE__,(unsigned int)c->partial_cipherl);
        while ( c->partial_cipherl >0)
        {
//	    pr_info("%s %u %u",__FUNCTION__,__LINE__,(unsigned int)c->partial_cipherl);
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
#if defined(HAVE_HC128) || defined(WOLFSSL_HC128)
        c->process_len = *plainl;
        wc_Hc128_Process(&cipher.decrypt.hc128, c->process_text, src, (word32)*plainl);
#endif
    }
    else if (strcmp(config.method, "rabbit") == 0)
    {
#if defined(HAVE_RABBIT) || defined(WOLFSSL_RABBIT)
        c->process_len = *plainl;
        wc_RabbitProcess(&cipher.decrypt.rabbit, c->process_text, src, (word32)*plainl);
#endif
    }
    else if (strcmp(config.method,"aes-128-gcm") == 0 || strcmp(config.method,"aes-192-gcm") == 0 || strcmp(config.method,"aes-256-gcm") == 0)
    {
        unsigned int process_total = 0;
        //pr_info("%s %u %lu",__FUNCTION__,__LINE__,c->half_done);
        pr_info("%s %u %u",__FUNCTION__,__LINE__,(unsigned int)c->partial_cipherl);
        pr_info("%s %u %u",__FUNCTION__,__LINE__,(unsigned int)*plainl);
        memcpy(c->partial_cipher + c->partial_cipherl, src,*plainl);
        c->partial_cipherl += *plainl;
        //pr_info("%s %u %u",__FUNCTION__,__LINE__,(unsigned int)c->partial_cipherl);
        while ( c->partial_cipherl >0)
        {
//	    pr_info("%s %u %u",__FUNCTION__,__LINE__,(unsigned int)c->partial_cipherl);
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
                                pr_err("%s %d :error during authentication",__FUNCTION__,__LINE__);
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
                            pr_err("%s %d :error during authentication",__FUNCTION__,__LINE__);
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
