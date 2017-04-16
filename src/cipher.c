/*
 * File:   cipher.c
 * Author: lizhou
 *
 * Created on 2017年3月31日, 下午 9:55
 */

#include <stddef.h>
#include <string.h>
#include <time.h>
#if defined(__linux__)
/* Linux. --------------------------------------------------- */
#include <linux/random.h>
#include <features.h>
#endif
#ifdef _MSC_VER
#include <malloc.h>
#define _CRT_RAND_S
#include <stdlib.h>
#else
#include <stdlib.h>
#endif
#include "md5.h"
#include "arcfour.h"
#include "defs.h"
#include "cipher.h"

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
                    const unsigned char * plain, size_t plainl)
#else
void cipher_encrypt(conn* c, size_t * encryptl,
                    const unsigned char * plain, size_t plainl)
#endif
{


    //    pr_info("%s %lu", __FUNCTION__, plainl);
    //    cipher_t * cipher = shadow->cipher;
    //unsigned char * encrypt = 0;

//    uint8_t * plainptr;
//    uint8_t *dst;
    //    int l;
    // if (!cipher.encrypt.init) {
    if (c->request_length)
    {

        //            int ivl;
        size_t prepend;
//#if defined (_MSC_VER)
//        uint8_t * src, * ptr;
//#else
//		unsigned int srcl,ptrl;
//		uint8_t src[srcl],ptr[ptrl];
//#endif

        //            uint8_t * iv = malloc(ivl);
//        cipher.encrypt.iv = malloc(cipher.ivl);
        //        RAND_bytes(cipher.encrypt.iv.base, cipher.encrypt.iv.len);

#ifdef _MSC_VER
        msc_getentropy(cipher.encrypt.iv);
#endif
#if !defined(_WIN32) && (defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__)))
        /* UNIX-style OS. ------------------------------------------- */
#include <unistd.h>
#if defined (__GLIBC__) && (__GLIBC_MINOR__ >= 25)
        getentropy(cipher.encrypt.iv.base, cipher.encrypt.iv.len);
#else
        double d1 = drand48();
        double d2 = drand48();
        memcpy(cipher.encrypt.iv, &d1, sizeof (d1));
        memcpy(cipher.encrypt.iv + sizeof (d1), &d2, sizeof (d2));
#endif
#endif
        char *true_key = malloc(MD5_DIGEST_LENGTH);
        create_key(cipher.encrypt.iv, cipher.ivl,true_key);
        arcfour_setkey(&cipher.encrypt.ctx, true_key, cipher.keyl);
        free(true_key);
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

        //ASSERT(c->request != 0);
        //if( c->request_length )
        // {
        //        size_t prepend = shadow->socks5->len - 3
        //                pr_info("%s %lu", __FUNCTION__, c->request_length);

        prepend = c->request_length - 3;

//        src = malloc(prepend + plainl);
//#if defined (_MSC_VER)
//             src = _malloca(prepend + plainl);
//#else
//             src = malloc(prepend + plainl);
//#endif
        //        src = malloc(plainl);
//             ptr = src + prepend;
//	     ptr = c->process_text + prepend;
        //memcpy(src, &shadow->socks5->data->atyp, prepend);
        /*
        #if defined(NDEBUG)
        #else
                dump("REQUEST", c->request, c->request_length);
                dump("REQUEST2", c->request + 3, prepend);
        #endif
         */
//             memcpy(src, c->request + 3, prepend);
        memcpy(c->process_text, cipher.encrypt.iv, cipher.ivl);
        memcpy(c->process_text + cipher.ivl ,c->request + 3, prepend);
        memcpy(c->process_text + cipher.ivl + prepend, plain, plainl);
        plainl += prepend;
        arcfour_stream(&cipher.encrypt.ctx, c->process_text + cipher.ivl, c->process_text + cipher.ivl, plainl);
        *encryptl = cipher.ivl + plainl;
//        encrypt = malloc(*encryptl);
//        memcpy(encrypt, cipher.encrypt.iv, cipher.ivl);
//             memcpy(c->process_text, cipher.encrypt.iv, cipher.ivl);
//        dst = (uint8_t *) encrypt + cipher.ivl;
//             dst = (uint8_t *) c->process_text + cipher.ivl;
        //    printf("---iv---\n");
        //    for (i = 0; i < ivl; i++) printf("%02x ", iv[i]);
        //    printf("\n");
        //
        //    printf("---key---\n");
        //    for (i = 0; i < cipher->keyl; i++) printf("%02x ", cipher->key[i]);
        //    printf("\n");

        //        free(iv);
//             plain = (char *) src;
//        plainptr = src;
        //cipher.encrypt.init = 1
        //        c->init = 1;
//        c->request = 0;
//             if (c->request)
//    {
//        free(c->request);
//        }
        c->request_length = 0;
    }
    else
    {
        //        pr_info("%s",__FUNCTION__);

        *encryptl = plainl;
//		plainptr = plain;
//        encrypt = malloc(*encryptl);
//        dst = (uint8_t *) encrypt;
//        dst = (uint8_t *) c->process_text;
        //    EVP_CipherUpdate(&cipher.encrypt.ctx, dst, &l, (uint8_t *) plain, (int) plainl);
        arcfour_stream(&cipher.encrypt.ctx, plain, c->process_text, plainl);
        //  printf("---encrypt count---\n");
        //  printf("%d %lu %lu\n", _, *encryptl, plainl);

        //  printf("---encrypt plain---\n");
        //  for (i = 0; i < 20; i++) printf("%02x ", src[i]);
        //  printf("\n");

        //  printf("---encrypt---\n");
        //  for (i = 0; i < len; i++) printf("%02x ", dst[i]);
        //  printf("\n");
    }
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
void cipher_decrypt(conn *c, ULONG * plainl, const unsigned char * encrypt, size_t encryptl)
#else
void cipher_decrypt(conn *c, size_t * plainl, const unsigned char * encrypt, size_t encryptl)
#endif
{
    //    pr_info("%s %lu", __FUNCTION__, encryptl);
    //    cipher_t * cipher = shadow->cipher;
//    unsigned char * plain = 0;

    uint8_t * src;

    //if (!cipher.decrypt.init) {
    //if (!c->init) {
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
            memcpy(cipher.decrypt.iv + c->request_length, encrypt, cipher.ivl - c->request_length);
            if (strcmp(config.method, "rc4-md5") == 0)
            {
                unsigned char *true_key = malloc(MD5_DIGEST_LENGTH);
                create_key(cipher.decrypt.iv, cipher.ivl,true_key);
                arcfour_setkey(&cipher.decrypt.ctx, true_key, cipher.keyl);
                free(true_key);
            }

            //    if (c->request == 0) {

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
//            c->request = malloc(cipher.ivl);
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

    //    int _;
    //    EVP_CipherUpdate(&cipher.decrypt.ctx, (uint8_t *) plain, &_, src, (int) *plainl);
//    arcfour_stream(&cipher.decrypt.ctx, src, plain, *plainl);
    arcfour_stream(&cipher.decrypt.ctx, src, c->process_text, *plainl);

    //  printf("---decrypt plain---\n");
    //  for (i = 0; i < 5; i++) printf("%02x ", (unsigned char)plain[i]);
    //  printf("\n");

    //free(encrypt);

//    return plain;
}

#if defined(NDEBUG)
#else

void dump(unsigned char *tag, unsigned char *text, unsigned int len)
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

void create_key(unsigned char * iv, int ivl,char * true_key)
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
void md5(const uint8_t *text, size_t len, char *digest)
{
    md5_state_t state;
    md5_init(&state);
    md5_append(&state, text, len);
    md5_finish(&state, digest);
}

#ifdef _MSC_VER
int msc_getentropy(void *buf)
{
    unsigned int i;
    unsigned int j;
//    srand((unsigned) time(NULL));
    errno_t         err;
    for (i = 0; i < 4; i++)
    {
        err = rand_s( &j );
        memcpy((char *) buf + i * sizeof (j), &j, sizeof (j));
    }
    return 0;
}
#endif

int bytes_to_key(const uint8_t *pass, int datal, uint8_t *key, uint8_t *iv)
{
    unsigned char md_buf[MD5_DIGEST_LENGTH];
    int niv;
    int nkey;
    int addmd;
    unsigned int mds;
    unsigned int i;
    int rv;
    md5_state_t hash_state;
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
            md5_init(&hash_state);
            if (addmd)
            {
                md5_append(&hash_state, &(md_buf[0]), mds);
            }
            else
            {
                addmd = 1;
            }
            md5_append(&hash_state, pass, datal);

            md5_finish(&hash_state, &(md_buf[0]));
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
