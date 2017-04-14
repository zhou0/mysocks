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
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include "defs.h"
#include "cipher-wolfssl.h"

extern server_config config;
cipher_t cipher;

void initialize_cipher()
{

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
        wc_Chacha_SetKey(&cipher.encrypt.chacha, cipher.key, cipher.keyl);
        wc_Chacha_SetKey(&cipher.decrypt.chacha, cipher.key, cipher.keyl);
        cipher.encrypt.iv = malloc(cipher.ivl);
        cipher.decrypt.iv = malloc(cipher.ivl);
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


    //    pr_info("%s %lu", __FUNCTION__, plainl);
    //    cipher_t * cipher = shadow->cipher;
    //unsigned char * encrypt = 0;

//    uint8_t * plainptr;
    uint8_t *dst;
    //    int l;
    // if (!cipher.encrypt.init) {
    if (c->request.len)
    {

        //            int ivl;
        size_t prepend;
//#if defined (_MSC_VER)
        uint8_t * src, * ptr;
//#else
//		unsigned int srcl,ptrl;
//		uint8_t src[srcl],ptr[ptrl];
//#endif

        //            uint8_t * iv = malloc(ivl);
//        cipher.encrypt.iv = malloc(cipher.ivl);
        //        RAND_bytes(cipher.encrypt.iv.base, cipher.encrypt.iv.len);
        RNG  rng;
//    byte block[16];
//    int ret;

#ifdef HAVE_CAVIUM
        ret = wc_InitRngCavium(&rng, CAVIUM_DEV_ID);
        if (ret != 0) return -2007;
#endif
//    ret = InitRng(&rng);
        wc_InitRng(&rng);
//    if (ret != 0) return -39;

//	ret = RNG_GenerateBlock(&rng, cipher.encrypt.iv, cipher.ivl);
        wc_RNG_GenerateBlock(&rng, cipher.encrypt.iv, cipher.ivl);
//    if (ret != 0) return -40;
#if defined(NDEBUG)
#else
        dump("Encryption IV",cipher.encrypt.iv,cipher.ivl);
#endif
//        arcfour_setkey(&cipher.encrypt.ctx, create_key(cipher.encrypt.iv, cipher.ivl), cipher.keyl);
        if (strcmp(config.method, "rc4-md5") == 0)
        {
            wc_Arc4SetKey(&cipher.encrypt.arc4, create_key(cipher.encrypt.iv, cipher.ivl), cipher.keyl);
        }
//        else if (strcmp(config.method, "chacha20-ietf") == 0)
//        {
//            Chacha_SetIV(&cipher.encrypt.chacha, cipher.encrypt.iv, c->counter / SODIUM_BLOCK_SIZE);
//        }
        else if (strcmp(config.method, "hc128") == 0)
        {
            wc_Hc128_SetKey(&cipher.encrypt.hc128, cipher.key, cipher.encrypt.iv);
        }
        else if (strcmp(config.method, "rabbit") == 0)
        {
            wc_RabbitSetKey(&cipher.encrypt.rabbit, cipher.key, cipher.encrypt.iv);
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

        prepend = c->request.len - 3;

//        src = malloc(prepend + plainl);
#if defined (_MSC_VER)
        src = _malloca(prepend + plainl);
#else
        src = malloc(prepend + plainl);
#endif
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
        *encryptl = cipher.ivl + plainl;
//        encrypt = malloc(*encryptl);
//        memcpy(encrypt, cipher.encrypt.iv, cipher.ivl);
        memcpy(c->process_text, cipher.encrypt.iv, cipher.ivl);
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
        plain = (char *) src;
//        plainptr = src;
        //cipher.encrypt.init = 1
        //        c->init = 1;
//        c->request.base = 0;
        if (c->request.base)
        {
            free(c->request.base);
        }
        c->request.len = 0;
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
	    memcpy(c->plain_buf + padding, plain,plainl);
	    wc_Chacha_Process(&cipher.encrypt.chacha, c->cipher_buf, c->plain_buf, plainl + padding);
	    memcpy(dst,c->cipher_buf + padding, plainl);
	}
	else
	{
            wc_Chacha_Process(&cipher.encrypt.chacha, dst, plain, plainl);
	}
        c->counter += plainl;
	pr_info("%s %u",__FUNCTION__,c->counter);
    }
    else if (strcmp(config.method, "chacha20-ietf-poly1305") == 0)
    {
      byte authTag[16];
      int ret = wc_ChaCha20Poly1305_Encrypt(cipher.key, cipher.encrypt.iv, 0, 0,plain, plainl, dst, authTag);
    }
    else if (strcmp(config.method, "hc128") == 0)
    {
        wc_Hc128_Process(&cipher.encrypt.hc128, dst, plain, plainl);
    }
    else if (strcmp(config.method, "rabbit") == 0)
    {
        wc_RabbitProcess(&cipher.encrypt.rabbit, dst, plain, plainl);
    }
    //  printf("---encrypt count---\n");
    //  printf("%d %lu %lu\n", _, *encryptl, plainl);

    //  printf("---encrypt plain---\n");
    //  for (i = 0; i < 20; i++) printf("%02x ", src[i]);
    //  printf("\n");

    //  printf("---encrypt---\n");
    //  for (i = 0; i < len; i++) printf("%02x ", dst[i]);
    //  printf("\n");
#ifdef _MSC_VER
    _freea(plain);
#else
    free(plain);
#endif
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
    //    pr_info("%s %lu", __FUNCTION__, encryptl);
    //    cipher_t * cipher = shadow->cipher;
//    unsigned char * plain = 0;

    uint8_t * src;

    //if (!cipher.decrypt.init) {
    //if (!c->init) {
    if (c->request.len < cipher.ivl)
    {
        c->request.base = malloc(cipher.ivl);
        if ( c->request.len + encryptl < cipher.ivl )
        {

            memcpy(c->request.base + c->request.len, encrypt, encryptl);
            c->request.len += encryptl;
            c->process_text = 0;
            c->cipher_len = 0;
            return;
        }
        else
        {
            memcpy(cipher.decrypt.iv,c->request.base,c->request.len);
            //     int ivl;
            //        uint8_t * iv = malloc(ivl);
//        cipher.decrypt.iv.base = malloc(cipher.decrypt.iv.len);
            memcpy(cipher.decrypt.iv + c->request.len, encrypt, cipher.ivl - c->request.len);
#if defined(NDEBUG)
#else
            dump("Decryption IV",cipher.decrypt.iv,cipher.ivl);
#endif
            if (strcmp(config.method, "rc4-md5") == 0)
            {
//              EVP_CipherInit_ex(&cipher.decrypt.ctx, cipher.type, 0, create_key(cipher.decrypt.iv.base, cipher.decrypt.iv.len), 0, 0);
//                arcfour_setkey(&cipher.decrypt.ctx, create_key(cipher.decrypt.iv, cipher.ivl), cipher.keyl);
                wc_Arc4SetKey(&cipher.decrypt.arc4,create_key(cipher.decrypt.iv, cipher.ivl) , cipher.keyl);
            }
//            else if (strcmp(config.method, "chacha20-ietf") == 0)
//            {
//               wc_ Chacha_SetIV(&cipher.decrypt.chacha, cipher.decrypt.iv, c->counter / SODIUM_BLOCK_SIZE);
//            }
            else if (strcmp(config.method, "hc128") == 0)
            {
                wc_Hc128_SetKey(&cipher.decrypt.hc128, cipher.key, cipher.decrypt.iv);
            }
            else if (strcmp(config.method, "rabbit") == 0)
            {
                wc_RabbitSetKey(&cipher.decrypt.rabbit, cipher.key, cipher.decrypt.iv);
            }

            //    if (c->request.base == 0) {

            *plainl = encryptl - cipher.ivl - c->request.len;
//          plain = malloc(*plainl);
            src = (uint8_t *) encrypt + cipher.ivl - c->request.len;
//          printf("---iv---\n");
//          for (i = 0; i < ivl; i++) printf("%02x ", iv[i]);
//          printf("\n");
//
//          printf("---key---\n");
            //    for (i = 0; i < cipher->keyl; i++) printf("%02x ", cipher->key[i]);
            //    printf("\n");
//            c->request.base = malloc(cipher.ivl);
            memcpy(c->request.base, cipher.decrypt.iv, cipher.ivl);
            c->request.len = cipher.ivl;
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
	    memcpy(c->cipher_buf + padding, src,*plainl);
	    wc_Chacha_Process(&cipher.decrypt.chacha, c->plain_buf, c->cipher_buf, padding + *plainl);
	    memcpy(c->process_text,c->plain_buf + padding, *plainl);
	}
	else
	{
            wc_Chacha_Process(&cipher.decrypt.chacha, c->process_text, src, *plainl);
	}
        c->counter += *plainl;
	pr_info("%s %u",__FUNCTION__,c->counter);
    }
    else if (strcmp(config.method, "hc128") == 0)
    {
        wc_Hc128_Process(&cipher.decrypt.hc128, c->process_text, src, *plainl);
    }
    else if (strcmp(config.method, "rabbit") == 0)
    {
        wc_RabbitProcess(&cipher.decrypt.rabbit, c->process_text, src, *plainl);
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

char * create_key(unsigned char * iv, int ivl)
{

    unsigned char *true_key = malloc(MD5_DIGEST_LENGTH);
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
    return (char *)true_key;
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
