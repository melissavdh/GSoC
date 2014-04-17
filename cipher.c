#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include "openssl/rc4.h"
#include "openssl/evp.h"

void OpenSSL_add_all_algorithms();

typedef struct gsoc_xio_cipher_s
{
    int                                 type;
    int                                 mode;
    char                                key[EVP_MAX_KEY_LENGTH];
    char                                iv[EVP_MAX_IV_LENGTH];
    EVP_CIPHER_CTX                      ctx;
    RC4_KEY                             rc4key;
} gsoc_xio_cipher_t;

static int
gsoc_open(
    gsoc_xio_cipher_t *                 out_cipher_type,
    char *                              type,
    char *                              mode)
{
    char                                key[EVP_MAX_KEY_LENGTH];
    char                                iv[EVP_MAX_IV_LENGTH];
    int                                 i, keylen = 0;
    RC4_KEY                             rc4key;

    EVP_CIPHER_CTX_init(&out_cipher_type->ctx);

    if (strcmp(type, "rc4") == 0)
    {
        printf("enter key\n");
        scanf("%s", key);
        for (i=0; key[i]!='\0'; i++)
            keylen++;
        printf("key = %s, length = %d\n", key, keylen);
        RC4_set_key(&out_cipher_type->rc4key,keylen,key);
        printf("rc4key = %s\n",&out_cipher_type->rc4key);
    }
    else
    {
        scanf("%s", out_cipher_type->key);
        printf("enter key\n");
        printf("(OPEN) key = %x\n", out_cipher_type->key);
        printf("enter iv \n");
        scanf("%s", out_cipher_type->iv);
        printf("(OPEN) iv = %s\n", out_cipher_type->iv);
    }

    out_cipher_type->type = type;
    out_cipher_type->mode = mode;

    if (strcmp(type, "rc4") == 0)
    {
        printf("\nSTRUCTURE \ntype: %s\nmode: %s\nkey: %x\n\n",out_cipher_type->type, out_cipher_type->mode, &out_cipher_type->rc4key);
    }
    else
    {
        printf("\nSTRUCTURE \ntype: %s\nmode: %s\nkey: %s\niv: %s\n\n",out_cipher_type->type, out_cipher_type->mode, out_cipher_type->key, out_cipher_type->iv);
    }

}

/*************************************************************/
/*                      WRITE (ENCRYPT)                      */
/*************************************************************/

/**  
*  This function encrypts the data, with any cipher type and any mode specified.
*  The encryption is from any file specified at run time by the user into 
*  ciphertext.  The ciphertext is stored in a file also specified at runtime.
*/

int
gsoc_write(
    FILE *                              in, 
    FILE *                              out, 
    int                                 cipher, 
    int                                 do_encrypt,
    gsoc_xio_cipher_t *                 cipher_type)
{
    unsigned char                       inbuf[1024];
    unsigned char                       outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int                                 outlen, inlen;
    int                                 type;

    printf("write function\n");

    if (strcmp(cipher_type->type, "rc4") == 0)
    {
        printf("\nSTRUCTURE (write)\ntype: %s\nmode: %s\nkey: %x\n\n",cipher_type->type, cipher_type->mode, &cipher_type->rc4key);
    }
    else
    {
        printf("\nSTRUCTURE (write)\ntype: %s\nmode: %s\nkey: %s\niv: %s\n\n",cipher_type->type, cipher_type->mode, cipher_type->key, cipher_type->iv);
    }

    if (cipher == 0)
    {
        printf("write recognises bf_cbc\n");
        EVP_EncryptInit_ex(&cipher_type->ctx, EVP_bf_cbc(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
    }
    else if (cipher == 1)
    {
        printf("write recognises bf_cfb\n");
        EVP_EncryptInit_ex(&cipher_type->ctx, EVP_bf_cfb(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
    }
    else if (cipher == 2)
    {
        printf("write recognises bf_ofb\n");
        EVP_EncryptInit_ex(&cipher_type->ctx, EVP_bf_ofb(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
    }
    else if (cipher == 3)
    {
        printf("write recognises cast5_cbc\n");
        EVP_EncryptInit_ex(&cipher_type->ctx, EVP_cast5_cbc(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
    }
    else if (cipher == 4)
    {
        printf("write recognises cast5_cfb\n");
        EVP_EncryptInit_ex(&cipher_type->ctx, EVP_cast5_cfb(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
    }
    else if (cipher == 5)
    {
        printf("write recognises cast5_ofb\n");
        EVP_EncryptInit_ex(&cipher_type->ctx, EVP_cast5_ofb(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
    }
    else if (cipher == 6)
    {
        printf("write recognises idea_cbc\n");
        //EVP_EncryptInit_ex(&cipher_type->ctx, EVP_idea_cbc(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
    }
    else if (cipher == 7)
    {
        printf("write recognises idea_cfb\n");
        //EVP_EncryptInit_ex(&cipher_type->ctx, EVP_idea_cfb(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
    }
    else if (cipher == 8)
    {
        printf("write recognises idea_ofb\n");
        //EVP_EncryptInit_ex(&cipher_type->ctx, EVP_idea_ofb(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
    }
    else if (cipher == 9)
    {
        printf("write recognises rc2_cbc\n");
        EVP_CipherInit_ex(&cipher_type->ctx, EVP_rc2_cbc(), NULL, NULL, NULL, do_encrypt);
        type = 1;
    }
    else if (cipher == 10)
    {
        printf("write recognises rc2_cfb\n");
        EVP_CipherInit_ex(&cipher_type->ctx, EVP_rc2_cfb(), NULL, NULL, NULL, do_encrypt);
        type = 1;
    }
    else if (cipher == 11)
    {
        printf("write recognises rc2_ofb\n");
        EVP_CipherInit_ex(&cipher_type->ctx, EVP_rc2_ofb(), NULL, NULL, NULL, do_encrypt);
        type = 1;
    }
    else if (cipher == 12)
    {
        printf("write recognises rc4\n");
        EVP_CipherInit_ex(&cipher_type->ctx, EVP_rc4(), NULL, &cipher_type->rc4key, NULL, do_encrypt);
        type = 2;
    }
    if (type == 1)
    {
        EVP_CIPHER_CTX_set_key_length(&cipher_type->ctx, 10);
        EVP_CipherInit_ex(&cipher_type->ctx, NULL, NULL, cipher_type->key, cipher_type->iv, do_encrypt);
    }
    if (type == 0)
    {
        for(;;)
        {
            inlen = fread(inbuf, 1, 1024, in);
            if(inlen <= 0) break;
            if(!EVP_EncryptUpdate(&cipher_type->ctx, outbuf, &outlen, inbuf, inlen))
            {
                /* Error */
                EVP_CIPHER_CTX_cleanup(&cipher_type->ctx);
                return 0;
            }
            fwrite(outbuf, 1, outlen, out);
        }
        if(!EVP_EncryptFinal_ex(&cipher_type->ctx, outbuf, &outlen))
        {
            /* Error */
            EVP_CIPHER_CTX_cleanup(&cipher_type->ctx);
            return 0;
        }
    }
    else if (type == 1 || type == 2)
    {
        for(;;)
        {
            inlen = fread(inbuf, 1, 1024, in);
            if(inlen <= 0) break;
            if(!EVP_CipherUpdate(&cipher_type->ctx, outbuf, &outlen, inbuf, inlen))
            {
                /* Error */
                EVP_CIPHER_CTX_cleanup(&cipher_type->ctx);
                return 0;
            }
            fwrite(outbuf, 1, outlen, out);
        }
        if(!EVP_CipherFinal_ex(&cipher_type->ctx, outbuf, &outlen))
        {
            /* Error */
            EVP_CIPHER_CTX_cleanup(&cipher_type->ctx);
            return 0;
        }   
    }
    fwrite(outbuf, 1, outlen, out);
    EVP_CIPHER_CTX_cleanup(&cipher_type->ctx);
    printf("end of write\n");
    return 1;
}
/* gsoc_write() */


/*************************************************************/
/*                      READ (DECRYPT)                       */
/*************************************************************/

/**  
*  This function decrypts the data, with any cipher type and any mode specified.
*  The encryption is from any file specified at run time by the user into 
*  ciphertext.  The ciphertext is stored in a file also specified at runtime.
*/

int
gsoc_read(
    FILE *                              in, 
    FILE *                              out, 
    int                                 cipher, 
    int                                 do_encrypt,
    gsoc_xio_cipher_t *                 cipher_type)
{
    unsigned char                       inbuf[1024];
    unsigned char                       outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int                                 outlen, inlen;
    int                                 type;

    printf("read function\n");

    if (strcmp(cipher_type->type, "rc4") == 0)
    {
        printf("\nSTRUCTURE (read)\ntype: %s\nmode: %s\nkey: %x\n\n",cipher_type->type, cipher_type->mode, &cipher_type->rc4key);
    }
    else
    {
        printf("\nSTRUCTURE (read)\ntype: %s\nmode: %s\nkey: %s\niv: %s\n\n",cipher_type->type, cipher_type->mode, cipher_type->key, cipher_type->iv);
    }

    if (cipher == 0)
    {
        printf("read recognises DECRYPT bf_cbc\n");
        EVP_DecryptInit_ex(&cipher_type->ctx, EVP_bf_cbc(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
        //printf("type = %d\n",type);
        //EVP_CipherInit_ex(&cipher_type->ctx, EVP_bf_cbc(), NULL, cipher_type->key, cipher_type->iv, do_encrypt);
        //type = 3;
    }
    else if (cipher == 1)
    {
        printf("read recognises DECRYPT bf_cfb\n");
        EVP_DecryptInit_ex(&cipher_type->ctx, EVP_bf_cfb(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
    }
    else if (cipher == 2)
    {
        printf("read recognises DECRYPT bf_ofb\n");
        EVP_DecryptInit_ex(&cipher_type->ctx, EVP_bf_ofb(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
    }
    else if (cipher == 3)
    {
        printf("read recognises DECRYPT cast5_cbc\n");
        EVP_DecryptInit_ex(&cipher_type->ctx, EVP_cast5_cbc(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
    }
    else if (cipher == 4)
    {
        printf("read recognises DECRYPT cast5_cfb\n");
        EVP_DecryptInit_ex(&cipher_type->ctx, EVP_cast5_cfb(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
    }
    else if (cipher == 5)
    {
        printf("read recognises DECRYPT cast5_ofb\n");
        EVP_DecryptInit_ex(&cipher_type->ctx, EVP_cast5_ofb(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
    }
    else if (cipher == 6)
    {
        printf("read recognises DECRYPT idea_cbc\n");
        //EVP_DecryptInit_ex(&cipher_type->ctx, EVP_idea_cbc(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
    }
    else if (cipher == 7)
    {
        printf("read recognises DECRYPT idea_cfb\n");
        //EVP_DecryptInit_ex(&cipher_type->ctx, EVP_idea_cfb(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
    }
    else if (cipher == 8)
    {
        printf("read recognises DECRYPT idea_ofb\n");
        //EVP_DecryptInit_ex(&cipher_type->ctx, EVP_idea_ofb(), NULL, cipher_type->key, cipher_type->iv);
        type = 0;
    }
    else if (cipher == 9)
    {
        printf("read recognises rc2_cbc\n");
        EVP_CipherInit_ex(&cipher_type->ctx, EVP_rc2_cbc(), NULL, NULL, NULL, do_encrypt);
        type = 1;
    }
    else if (cipher == 10)
    {
        printf("read recognises rc2_cfb\n");
        EVP_CipherInit_ex(&cipher_type->ctx, EVP_rc2_cfb(), NULL, NULL, NULL, do_encrypt);
        type = 1;
    }
    else if (cipher == 11)
    {
        printf("read recognises rc2_ofb\n");
        EVP_CipherInit_ex(&cipher_type->ctx, EVP_rc2_ofb(), NULL, NULL, NULL, do_encrypt);
        type = 1;
    }
    else if (cipher == 12)
    {
        printf("read recognises rc4\n");
        EVP_CipherInit_ex(&cipher_type->ctx, EVP_rc4(), NULL, &cipher_type->rc4key, NULL, do_encrypt);
        type = 2;
    }

    if (type == 1)
    {
        EVP_CIPHER_CTX_set_key_length(&cipher_type->ctx, 10);
        EVP_CipherInit_ex(&cipher_type->ctx, NULL, NULL, cipher_type->key, cipher_type->iv, do_encrypt);
    }

    if (type == 0)
    {
        for(;;)
        {
            inlen = fread(inbuf, 1, 1024, in);
            printf("inlen = %d\n",inlen);
            if(inlen <= 0) break;
            if(!EVP_DecryptUpdate(&cipher_type->ctx, outbuf, &outlen, inbuf, inlen))
            {
                /* Error */
                printf("4\n");
                EVP_CIPHER_CTX_cleanup(&cipher_type->ctx);
                return 0;
            }
            printf("orig outlen = %d\n",outlen);
            fwrite(outbuf, 1, outlen, out);
        }
        if(!EVP_DecryptFinal_ex(&cipher_type->ctx, outbuf, &outlen))
        {
            /* Error */
            printf("error outlen = %d\n",outlen);
            EVP_CIPHER_CTX_cleanup(&cipher_type->ctx);
            return 0;
        }
        printf("outlen = %d\n",outlen);
    }
    else if (type == 1 || type == 2)
    {
        for(;;)
        {
            inlen = fread(inbuf, 1, 1024, in);
            printf("inlen = %d\n",inlen);
            if(inlen <= 0) break;
            if(!EVP_CipherUpdate(&cipher_type->ctx, outbuf, &outlen, inbuf, inlen))
            {
                /* Error */
                printf("5\n");
                EVP_CIPHER_CTX_cleanup(&cipher_type->ctx);
                return 0;
            }
            printf("orig outlen = %d\n",outlen);
            fwrite(outbuf, 1, outlen, out);
        }
        if(!EVP_CipherFinal_ex(&cipher_type->ctx, outbuf, &outlen))
        {
            printf("7\n");
            /* Error */
            EVP_CIPHER_CTX_cleanup(&cipher_type->ctx);
            return 0;
        }
        printf("final outlen = %d\n",outlen);
    }
    fwrite(outbuf, 1, outlen, out);
    EVP_CIPHER_CTX_cleanup(&cipher_type->ctx);
    printf("end of read function\n");
    return 1;
}
/* gsoc_read() */


/*************************************************************/
/*                           MAIN                            */
/*************************************************************/

typedef int
(*gsoc_crypto_func_t)(
    FILE *                              in,
    FILE *                              out,
    int                                 cipher,
    int                                 do_encrypt,
    gsoc_xio_cipher_t *                 cipher_type);

typedef struct gsoc_type_table_s
{
    char *                      name;
    gsoc_crypto_func_t          func;
    int                         base;
} gsoc_type_table_t;

typedef struct gsoc_mode_table_s
{
    char *                      name;
    int                         bump;
} gsoc_mode_table_t;


static gsoc_type_table_t                gsoc_enc_lookup[] =
{
    {"bf", gsoc_write, 0},
    {"cast", gsoc_write, 3},
    {"idea", gsoc_write, 6},
    {"rc2", gsoc_write, 9},
    {"rc4", gsoc_write, 12},
    NULL
};

static gsoc_type_table_t                gsoc_dec_lookup[] =
{
    {"bf", gsoc_read, 0},
    {"cast", gsoc_read, 3},
    {"idea", gsoc_read, 6},
    {"rc2", gsoc_read, 9},
    {"rc4", gsoc_read, 12},
    NULL
};

static gsoc_mode_table_t                gsoc_mode_lookup[] =
{
    {"cbc", 0},
    {"cfb", 1},
    {"ofb", 2},
    {"rc4", 0},
    NULL
};


static void
gsoc_help()
{
    fprintf(stderr, "cipher "
        "<encryption/decryption> <type> <mode> <input file> <output file>\n");
    exit(1);
}


static
gsoc_type_table_t *
gsoc_lookup_dec_type(
    char *                              type)
{
    gsoc_type_table_t *                 alg_entry = NULL;
    int                                 i;

    for(i = 0; gsoc_dec_lookup[i].name != NULL; i++)
    {
        if(strcmp(gsoc_dec_lookup[i].name, type) == 0)
        {
            alg_entry = &gsoc_dec_lookup[i];
        }
    }

    return alg_entry;
}

static
gsoc_type_table_t *
gsoc_lookup_enc_type(
    char *                              type)
{
    gsoc_type_table_t *                 alg_entry = NULL;
    int                                 i;

    for(i = 0; gsoc_enc_lookup[i].name != NULL; i++)
    {
        if(strcmp(gsoc_enc_lookup[i].name, type) == 0)
        {
            alg_entry = &gsoc_enc_lookup[i];
        }
    }

    return alg_entry;
}

static
gsoc_mode_table_t *
gsoc_lookup_mode(
    char *                              mode)
{
    gsoc_mode_table_t *                 mode_entry = NULL;
    int                                 i;

    for(i = 0; gsoc_mode_lookup[i].name != NULL; i++)
    {
        if(strcmp(gsoc_mode_lookup[i].name, mode) == 0)
        {
            mode_entry = &gsoc_mode_lookup[i];
        }
    }

    return mode_entry;
}

static int
do_it(
    char *                              type,
    char *                              mode,
    FILE *                              in,
    FILE *                              out,
    int                                 do_encrypt,
    gsoc_xio_cipher_t *                 cipher_type)
{
    gsoc_type_table_t *                 alg_entry;
    gsoc_mode_table_t *                 mode_entry;
    struct timeval                      tv1;
    struct timeval                      tv2;
    struct timezone                     tz1;
    struct timezone                     tz2;
    int                                 cipher;

    if(do_encrypt)
    {
        printf("ENCRYPTING: ");
        alg_entry = gsoc_lookup_enc_type(type);
    }
    else
    {
        printf("DECRYPTING: ");
        alg_entry = gsoc_lookup_dec_type(type);
    }
    if(alg_entry == NULL)
    {
        fprintf(stderr, "No such type: %s\n", type);
        return 1;
    }

    mode_entry = gsoc_lookup_mode(mode);
    if(mode_entry == NULL)
    {
        fprintf(stderr, "No such mode: %s\n", mode);
        return 1;
    }

    cipher = alg_entry->base + mode_entry->bump;

    gettimeofday(&tv1,&tz1);
    alg_entry->func(in, out, cipher, do_encrypt, cipher_type);
    gettimeofday(&tv2,&tz2);
    printf("Time taken to encrypt: %ld microseconds\n",
        ((tv2.tv_sec - tv1.tv_sec) * 1000000 + (tv2.tv_usec - tv1.tv_usec)));

    return 0;
}


int
main(int argc, char *argv[])
{
    int                                 cipher;
    char                                key[EVP_MAX_KEY_LENGTH];
    char                                iv[EVP_MAX_IV_LENGTH];
    struct timeval                      tv1,tv2;
    struct timezone                     tz1,tz2;
    gsoc_crypto_func_t                  c_func;
    int                                 enc;
    FILE *                              in;
    FILE *                              out;
    char *                              type;
    char *                              mode;
    gsoc_xio_cipher_t                   out_cipher_type;

    if(argc < 6)
    {
        gsoc_help();
    }

    type = argv[2];
    mode = argv[3];

    in = fopen(argv[4], "rb");
    if(in == NULL)
    {
        gsoc_help();
    }
    out = fopen(argv[5], "wb");
    if(out == NULL)
    {
        gsoc_help();
    }
    if(strcmp(argv[1], "e") == 0)
    {
        enc = 1;
    }
    else if(strcmp(argv[1], "d") == 0)
    {
        enc = 0;
    }
    else
    {
        gsoc_help();
    }

    gsoc_open(&out_cipher_type, type, mode);

    if (strcmp(type, "rc4") == 0)
    {
        printf("STRUCTURE (main)\ntype: %s\nmode: %s\nkey: %x\n",out_cipher_type.type, out_cipher_type.mode, &out_cipher_type.rc4key);
    }
    else
    {
        printf("STRUCTURE (main)\ntype: %s\nmode: %s\nkey: %s\niv: %s\n\n",out_cipher_type.type, out_cipher_type.mode, out_cipher_type.key, out_cipher_type.iv);
    }

    do_it(out_cipher_type.type, out_cipher_type.mode, in, out, enc,&out_cipher_type);
    printf("end of main\n");

    return 0;
}
