/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "gssapi.h"
#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_common.h"
#include "globus_xio_psk_driver.h"
#include "version.h"
#include "globus_gss_assist.h"
#include "globus_error_gssapi.h"
#include "openssl/evp.h"

GlobusDebugDefine(GLOBUS_XIO_PSK);
GlobusXIODeclareDriver(psk);

#define GlobusXIOPSKDebugdbug(level, message)                  \
    GlobusDebugdbug(GLOBUS_XIO_psk, level, message)

#define GlobusXIOPSKDebugEnter()                                 \
    GlobusXIOPSKDebugdbug(                                     \
        GLOBUS_XIO_psk_DEBUG_TRACE,                              \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIOPSKDebugExit()                                  \
    GlobusXIOPSKDebugdbug(                                     \
        GLOBUS_XIO_psk_DEBUG_TRACE,                              \
        ("[%s] Exiting\n", _xio_name))

#define GLOBUS_XIO_PSK_BLOCKSIZE 1024

typedef enum
{
    GLOBUS_XIO_PSK_DEBUG_ERROR = 1,
    GLOBUS_XIO_PSK_DEBUG_WARNING = 2,
    GLOBUS_XIO_PSK_DEBUG_TRACE = 4,
    GLOBUS_XIO_PSK_DEBUG_INFO = 8,
} globus_xio_psk_debug_levels_t;

	
/* Function declarations */

static int
globus_l_xio_psk_activate();

static int
globus_l_xio_psk_deactivate();

static globus_result_t
globus_l_xio_psk_init(globus_xio_driver_t * out_driver);

static void
globus_l_xio_psk_destroy(globus_xio_driver_t driver);

static
globus_result_t
globus_l_xio_psk_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op);

static
globus_result_t
globus_l_xio_psk_close(
    void *                              driver_specific_handle,
    void *                              attr,
    globus_xio_operation_t              op);

static
globus_result_t
globus_l_xio_psk_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op);

static
void
globus_l_xio_psk_final_write_cb(
	globus_xio_operation_t				op,
	globus_result_t						result,
	globus_size_t						nbytes,
	void *								user_arg);

static
globus_result_t
globus_l_xio_psk_write(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op);

static
globus_result_t
globus_l_xio_psk_attr_init(
    void **                             out_attr);

static
globus_result_t
globus_l_xio_psk_attr_copy(
    void **                             dst,
    void *                              src);

static
globus_result_t
globus_l_xio_psk_attr_destroy(
    void *                              driver_attr);

static
globus_result_t
globus_l_xio_psk_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap);


/* Activation and deactivation code:
 * When the driver is loaded the activate() function below is called. If any
 * global initializations are needed, they should be done in this function.
 * Conversly, when the driver is unloaded or the driver exits, deactivate
 * is called. The time between activate() and deactivate() should be seen
 * as the lifetime of the driver.
 */
GlobusXIODefineModule(psk) =
{
    "globus_xio_psk",
    globus_l_xio_psk_activate,
    globus_l_xio_psk_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static
int
globus_l_xio_psk_activate(void)
{
    int                                 rc;

    GlobusDebugInit(GLOBUS_XIO_PSK, TRACE);

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
        GlobusXIORegisterDriver(psk);
        return rc;
    }
    rc = globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    if(rc == GLOBUS_SUCCESS)
    {
        globus_module_deactivate(GLOBUS_XIO_MODULE);
        GlobusXIORegisterDriver(psk);
    }
    
    return rc;
}

static
int
globus_l_xio_psk_deactivate(void)
{
	int									rc;

	GlobusXIOUnRegisterDriver(psk);
    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    rc = globus_module_deactivate(GLOBUS_GSI_GSS_ASSIST_MODULE);

	return rc;	
}

/* Initialization and deinitialization code:
 * The init() function below is called whenever the user calls 
 * globus_xio_driver_load(). This is when the user start explicitly
 * making use of the driver.
 *
 * The _init() and _destroy() functions can be called serveral times in the
 * same process space (thereby separating them from _activate and
 * _deactivate()).
 */
GlobusXIODefineDriver(
    psk,
    globus_l_xio_psk_init,
    globus_l_xio_psk_destroy);

static globus_xio_string_cntl_table_t psk_l_string_opts_table[] =

{
    {"key", GLOBUS_XIO_PSK_SET_KEY,
        globus_xio_string_cntl_string},
    {"iv", GLOBUS_XIO_PSK_SET_IV,
        globus_xio_string_cntl_string},
    {0}
};
static
globus_result_t
globus_l_xio_psk_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;

    res = globus_xio_driver_init(&driver, "psk", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_psk_open,
        globus_l_xio_psk_close,
        globus_l_xio_psk_read,
        globus_l_xio_psk_write,
        NULL,
        NULL);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_psk_attr_init,
        globus_l_xio_psk_attr_copy,
        globus_l_xio_psk_attr_cntl,
        globus_l_xio_psk_attr_destroy);

    globus_xio_driver_string_cntl_set_table(
        driver,
        psk_l_string_opts_table);


    *out_driver = driver;

    return GLOBUS_SUCCESS;
}

typedef struct xio_l_psk_attr_s
{
    char *                              key;
    char *                              iv;
} xio_l_psk_attr_t;




static
globus_result_t
globus_l_xio_psk_attr_init(
    void **                             out_attr)
{
    xio_l_psk_attr_t *                  dst_attr;

    dst_attr = (xio_l_psk_attr_t *) globus_calloc(1, sizeof(xio_l_psk_attr_t));
    dst_attr->key = strdup("0123456789");
    dst_attr->iv = strdup("12345678");

    *out_attr = dst_attr;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_psk_attr_copy(
    void **                             dst,
    void *                              src)
{
    xio_l_psk_attr_t *                  src_attr;
    xio_l_psk_attr_t *                  dst_attr;

    src_attr = (xio_l_psk_attr_t *) src;

    dst_attr = (xio_l_psk_attr_t *) globus_calloc(1, sizeof(xio_l_psk_attr_t));
    dst_attr->key = strdup(src_attr->key);
    dst_attr->iv = strdup(src_attr->iv);

    *dst = dst_attr;
    
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_psk_attr_destroy(
    void *                              driver_attr)
{
    xio_l_psk_attr_t *                  attr;

    attr = (xio_l_psk_attr_t *) driver_attr;

    globus_free(attr->key);
    globus_free(attr->iv);

    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_xio_psk_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    char *                              tmp_s;
    xio_l_psk_attr_t *                  attr;

    attr = (xio_l_psk_attr_t *) driver_attr;

    switch(cmd)
    {
        case GLOBUS_XIO_PSK_SET_KEY:
            tmp_s = va_arg(ap, char*);
            globus_free(attr->key);
            attr->key = strdup(tmp_s);
            break;

        case GLOBUS_XIO_PSK_SET_IV:
            tmp_s = va_arg(ap, char*);
            globus_free(attr->iv);
            attr->iv = strdup(tmp_s);
            break;
    }

    return GLOBUS_SUCCESS;
}


static
void
globus_l_xio_psk_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}

// using rc2 (block cipher) in cbc mode with static key and iv

typedef struct xio_l_psk_info_s
{
    char                                key[32];
    char                                iv[32];
    EVP_CIPHER_CTX                      ctx;
    EVP_CIPHER_CTX                      ctxR;
    globus_byte_t                       write_buffer[GLOBUS_XIO_PSK_BLOCKSIZE
                                            + EVP_MAX_BLOCK_LENGTH];
    globus_size_t                       write_buffer_offset;
    globus_xio_iovec_t                  write_iovec[1];
    globus_size_t                       write_buffer_nbytes;

    globus_byte_t                       read_buffer[GLOBUS_XIO_PSK_BLOCKSIZE
                                            + EVP_MAX_BLOCK_LENGTH];
    globus_size_t                       read_buffer_offset;
    globus_xio_iovec_t *                read_iovec;
//    globus_size_t                       read_buffer_nbytes;
    globus_xio_iovec_t                  dec_iovec[1];
} xio_l_psk_info_t;

static
void
globus_l_xio_psk_open_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    xio_l_psk_info_t *                  psk_info;

    psk_info = (xio_l_psk_info_t *) user_arg;
    
    globus_xio_driver_finished_open(psk_info, op, result);
}

static
globus_result_t
globus_l_xio_psk_open(
    const globus_xio_contact_t *        contact_info,
    void *                              driver_link,
    void *                              driver_attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    xio_l_psk_info_t *                  psk_info;
    xio_l_psk_attr_t *                  attr;

    psk_info = (xio_l_psk_info_t *) globus_calloc(1, sizeof(xio_l_psk_info_t));

    psk_info->read_buffer_offset = 0;

    EVP_CIPHER_CTX_init(&psk_info->ctx);
    EVP_CIPHER_CTX_init(&psk_info->ctxR);

    attr = (xio_l_psk_attr_t *) driver_attr;
    if(attr == NULL)
    {
        strcpy(psk_info->key, "0123456789");
        strcpy(psk_info->iv, "12345678");
    }
    else
    {
        strcpy(psk_info->key, attr->key);
        strcpy(psk_info->iv, attr->iv);
    }

    /*setting up cipher for encryption*/
    EVP_CipherInit_ex(&psk_info->ctx, EVP_rc2_cbc(), NULL, NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_key_length(&psk_info->ctx, 10);
    EVP_CipherInit_ex(&psk_info->ctx, NULL, NULL, 
        (unsigned char *)psk_info->key, (unsigned char *)psk_info->iv, 1);

    /*setting up cipher for decryption*/
    EVP_CipherInit_ex(&psk_info->ctxR, EVP_rc2_cbc(), NULL, NULL, NULL, NULL);
    EVP_CIPHER_CTX_set_key_length(&psk_info->ctxR, 10);
    EVP_CipherInit_ex(&psk_info->ctxR, NULL, NULL, 
        (unsigned char *)psk_info->key, (unsigned char *)psk_info->iv, 0);

	res = globus_xio_driver_pass_open(
        op, contact_info, globus_l_xio_psk_open_cb, psk_info);

    return res;
}

static
void
globus_l_xio_psk_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    xio_l_psk_info_t *                  psk_info;
//    globus_byte_t *                     outbuf;
//    int                                 outlen;

    psk_info = (xio_l_psk_info_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    //outbuf = globus_calloc(1, 
    //    (GLOBUS_XIO_PSK_BLOCKSIZE + EVP_MAX_BLOCK_LENGTH));
    //if(!EVP_CipherFinal_ex(&psk_info->ctx, outbuf, &outlen))
    //{
    //    EVP_CIPHER_CTX_cleanup(&psk_info->ctx);
    //}

    globus_free(psk_info);
    globus_xio_driver_finished_close(op, result);

    return;
error:
    globus_xio_driver_finished_close(op, result);
    
}


static
void
globus_l_xio_psk_close_write_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    xio_l_psk_info_t *                  psk_info;
    globus_byte_t *                     outbuf;
    int                                 outlen;

    psk_info = (xio_l_psk_info_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    outbuf = globus_calloc(1, 
        (GLOBUS_XIO_PSK_BLOCKSIZE + EVP_MAX_BLOCK_LENGTH));
    /* If there was data left in buffer, encrypted in close (where no padding was added), this adds the necessary padding */
    if(!EVP_CipherFinal_ex(&psk_info->ctx, outbuf, &outlen))
    {
        EVP_CIPHER_CTX_cleanup(&psk_info->ctx);
    }
    psk_info->write_iovec[0].iov_len = outlen;
    psk_info->write_iovec[0].iov_base = outbuf;

    result = globus_xio_driver_pass_write(op, psk_info->write_iovec, 
        1, outlen, globus_l_xio_psk_final_write_cb, psk_info);

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    return;

error:
    globus_l_xio_psk_final_write_cb(op, result, 0, user_arg);
}

static
void
globus_l_xio_psk_final_write_cb(
	globus_xio_operation_t				op,
	globus_result_t						result,
	globus_size_t						nbytes,
	void *								user_arg)
{
    xio_l_psk_info_t *                  psk_info;


    psk_info = (xio_l_psk_info_t *) user_arg;

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    globus_free(psk_info->write_iovec[0].iov_base);

    result = globus_xio_driver_pass_close(
        op, globus_l_xio_psk_close_cb, psk_info);

    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    return;

error:
    globus_l_xio_psk_close_cb(op, result, user_arg);

}

static
void
globus_l_xio_psk_write_cb(
	globus_xio_operation_t				op,
	globus_result_t						result,
	globus_size_t						nbytes,
	void *								user_arg)
{
    xio_l_psk_info_t *                  psk_info;

    psk_info = (xio_l_psk_info_t *) user_arg;

    globus_free(psk_info->write_iovec[0].iov_base);

    globus_xio_driver_finished_write(op, result, psk_info->write_buffer_nbytes);
}


static
globus_result_t
globus_l_xio_psk_close(
    void *                              user_arg,
    void *                              attr,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    xio_l_psk_info_t *                  psk_info;
    int                                 outlen;
    globus_byte_t *                     outbuf;

    psk_info = (xio_l_psk_info_t *) user_arg;

    if (psk_info->write_buffer_offset != 0)
    {
        /* data left in buffer needing to be encrypted, padding not added here */
        outbuf = globus_calloc(1, 
            (GLOBUS_XIO_PSK_BLOCKSIZE + EVP_MAX_BLOCK_LENGTH));
        if(!EVP_CipherUpdate(&psk_info->ctx, outbuf, &outlen, 
            psk_info->write_buffer, psk_info->write_buffer_offset))
        {
            EVP_CIPHER_CTX_cleanup(&psk_info->ctx);
        }
        psk_info->write_iovec[0].iov_len = outlen;
        psk_info->write_buffer_offset = 0;
        psk_info->write_iovec[0].iov_base = outbuf;
        res = globus_xio_driver_pass_write(op, psk_info->write_iovec, 
            1, outlen, globus_l_xio_psk_close_write_cb, psk_info);
    }
    else
    {
        outbuf = globus_calloc(1, 
            (GLOBUS_XIO_PSK_BLOCKSIZE + EVP_MAX_BLOCK_LENGTH));
        /* If all the data has already been encrypted, this encrypts the remaining <= 8 bytes and pads it out to 8 bytes */
        if(!EVP_CipherFinal_ex(&psk_info->ctx, outbuf, &outlen))
        {
            EVP_CIPHER_CTX_cleanup(&psk_info->ctx);
        }
        psk_info->write_iovec[0].iov_len = outlen;
        psk_info->write_iovec[0].iov_base = outbuf;

        res = globus_xio_driver_pass_write(op, psk_info->write_iovec, 
            1, outlen, globus_l_xio_psk_final_write_cb, psk_info);
    }
    return res;
}

static
void
globus_l_xio_psk_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_result_t                     res;
    xio_l_psk_info_t *                  psk_info;
    int                                 outlen;
    globus_byte_t *                     outbuf;
    int                                 copy_amt;
    int                                 final_outlen;
    globus_byte_t *                     final_outbuf;
    int                                 offset;

    psk_info = (xio_l_psk_info_t *) user_arg;

    printf("\nread cb: %d bytes in\n",nbytes);

    if (psk_info->read_buffer_offset == 0)
    {
        printf("nothing in buffer\n");
        if (nbytes >= GLOBUS_XIO_PSK_BLOCKSIZE)
        {
            printf("enough data to decrypt\n");

            outbuf = globus_calloc(1, (GLOBUS_XIO_PSK_BLOCKSIZE + EVP_MAX_BLOCK_LENGTH));

            if(!EVP_CipherUpdate(&psk_info->ctxR, outbuf, &outlen, psk_info->read_iovec[0].iov_base, GLOBUS_XIO_PSK_BLOCKSIZE))
            {
                printf("error decrypting 1\n");
                EVP_CIPHER_CTX_cleanup(&psk_info->ctxR);
                //res = 0x1;
                //goto error;
            }
            printf("data decrypted: %d bytes in, %d bytes out\n",GLOBUS_XIO_PSK_BLOCKSIZE,outlen);

            psk_info->dec_iovec[0].iov_len = outlen;
            psk_info->dec_iovec[0].iov_base = outbuf;

            memcpy(psk_info->read_iovec[0].iov_base, psk_info->dec_iovec[0].iov_base,outlen);
            globus_xio_driver_finished_read(op, GLOBUS_SUCCESS,outlen);
        }
        else
        {
            printf("not enough data read in to decrypt\n");
            printf("%d bytes currently in buffer, reading in nbytes = %d\n",psk_info->read_buffer_offset,nbytes);
            memcpy(psk_info->read_buffer, psk_info->read_iovec[0].iov_base, nbytes);
            psk_info->read_buffer_offset += nbytes;
            printf("%d bytes now in buffer\n",psk_info->read_buffer_offset);

            globus_xio_driver_finished_read(op, GLOBUS_SUCCESS, nbytes);
        }
    }
    else
    {
        printf("\nabout to read into buffer: %d bytes already\n",psk_info->read_buffer_offset);
        copy_amt = nbytes;
        if (copy_amt + psk_info->read_buffer_offset > GLOBUS_XIO_PSK_BLOCKSIZE)
        {
            copy_amt = GLOBUS_XIO_PSK_BLOCKSIZE - psk_info->read_buffer_offset;
        }
        memcpy(&psk_info->read_buffer[psk_info->read_buffer_offset], psk_info->read_iovec[0].iov_base, copy_amt);
        printf("copying %d bytes into buffer\n",copy_amt);
        psk_info->read_buffer_offset += copy_amt;
        printf("%d bytes now in buffer\n",psk_info->read_buffer_offset);
        if (psk_info->read_buffer_offset == GLOBUS_XIO_PSK_BLOCKSIZE)
        {
            printf("buffer full, can now decrypt contents\n");

            outbuf = globus_calloc(1, (GLOBUS_XIO_PSK_BLOCKSIZE + EVP_MAX_BLOCK_LENGTH));

            if(!EVP_CipherUpdate(&psk_info->ctxR, outbuf, &outlen, psk_info->read_buffer, GLOBUS_XIO_PSK_BLOCKSIZE))
            {
                printf("error decrypting 2\n");
                EVP_CIPHER_CTX_cleanup(&psk_info->ctxR);
                //res = 0x1;
                //goto error;
            }
            printf("data decrypted: %d bytes in, %d bytes out\n",GLOBUS_XIO_PSK_BLOCKSIZE,outlen);

            psk_info->read_buffer_offset = 0;
            psk_info->dec_iovec[0].iov_len = outlen;
            psk_info->dec_iovec[0].iov_base = outbuf;

            memcpy(psk_info->read_iovec[0].iov_base, psk_info->dec_iovec[0].iov_base,outlen);
            globus_xio_driver_finished_read(op, GLOBUS_SUCCESS, outlen);

        }
        else
        {
            globus_xio_driver_finished_read(op, result, nbytes);
        }
    }
}

static
globus_result_t
globus_l_xio_psk_read(
    void *                              user_arg,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;
    xio_l_psk_info_t *                  psk_info;
    
    psk_info = (xio_l_psk_info_t *) user_arg;

    psk_info->read_iovec = globus_calloc(iovec_count, sizeof(globus_xio_iovec_t));
    psk_info->read_iovec[0].iov_base = iovec[0].iov_base;
    psk_info->read_iovec[0].iov_len = iovec[0].iov_len;

    psk_info->dec_iovec[0].iov_base = globus_malloc(GLOBUS_XIO_PSK_BLOCKSIZE);
    psk_info->dec_iovec[0].iov_len = GLOBUS_XIO_PSK_BLOCKSIZE;

    wait_for = globus_xio_operation_get_wait_for(op);
	res = globus_xio_driver_pass_read(op, psk_info->read_iovec, iovec_count, wait_for, globus_l_xio_psk_read_cb, psk_info);

    return res;
}

static
globus_result_t
globus_l_xio_psk_write(
    void *                              user_arg,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    xio_l_psk_info_t *                  psk_info;
    int                                 outlen;
    globus_byte_t *                     outbuf;
    int                                 copy_amt;

    psk_info = (xio_l_psk_info_t *) user_arg;

    /*if nothing in the buffer*/
    if (psk_info->write_buffer_offset == 0)
    {
        /*if user gave enough data so write_buffer can be filled*/
        if (iovec[0].iov_len >= GLOBUS_XIO_PSK_BLOCKSIZE)
        {
            outbuf = globus_calloc(1, 
                (GLOBUS_XIO_PSK_BLOCKSIZE + EVP_MAX_BLOCK_LENGTH));
            if(!EVP_CipherUpdate(&psk_info->ctx, outbuf, 
                &outlen, iovec[0].iov_base, GLOBUS_XIO_PSK_BLOCKSIZE))
            {
                /* Error */
                EVP_CIPHER_CTX_cleanup(&psk_info->ctx);
                res = 0x1;
                goto error;
            }
            psk_info->write_iovec[0].iov_len = outlen;
            psk_info->write_iovec[0].iov_base = outbuf;
            psk_info->write_buffer_nbytes = GLOBUS_XIO_PSK_BLOCKSIZE;
            
            res = globus_xio_driver_pass_write(op, 
                psk_info->write_iovec, 1, outlen,
                globus_l_xio_psk_write_cb, psk_info);
            if(res != GLOBUS_SUCCESS)
            {
                /* must handle all error case */
                goto error;
            }
        }
        /*if not enough data to fill buffer - copy data into write_buffer
            and tell xio we are done so more data can come and can fill up
            buffer*/
        else
        {
            memcpy(psk_info->write_buffer, iovec[0].iov_base, iovec[0].iov_len);
            psk_info->write_buffer_offset += iovec[0].iov_len;
            globus_xio_driver_finished_write(op, GLOBUS_SUCCESS,
                iovec[0].iov_len);
        }
    }
    /* if buffer contains data from previous block but isnt full so needs
        more data*/
    else
    {
        copy_amt = iovec[0].iov_len;

        /*make sure dont over run buffer by copying too much into it*/
        if (copy_amt + psk_info->write_buffer_offset > GLOBUS_XIO_PSK_BLOCKSIZE)
        {
            copy_amt = GLOBUS_XIO_PSK_BLOCKSIZE - psk_info->write_buffer_offset;
        }
        memcpy(&psk_info->write_buffer[psk_info->write_buffer_offset], 
            iovec[0].iov_base, copy_amt);

        /*adjust write_offset to reflect new position*/
        psk_info->write_buffer_offset += copy_amt;

        /*test to see if have enough data in write_buffer to encrypt*/
        if (psk_info->write_buffer_offset == GLOBUS_XIO_PSK_BLOCKSIZE)
        {
            outbuf = globus_calloc(1, 
                (GLOBUS_XIO_PSK_BLOCKSIZE + EVP_MAX_BLOCK_LENGTH));
            /* write_buffer is full, have enough data to encrypt*/
            psk_info->write_buffer_offset = 0; //reset offset
            if(!EVP_CipherUpdate(&psk_info->ctx, outbuf, &outlen, 
                psk_info->write_buffer, GLOBUS_XIO_PSK_BLOCKSIZE))
            {
                /* Error */
                EVP_CIPHER_CTX_cleanup(&psk_info->ctx);
            }
            psk_info->write_iovec[0].iov_base = outbuf;
            psk_info->write_iovec[0].iov_len = outlen;
            psk_info->write_buffer_nbytes = copy_amt;

            res = globus_xio_driver_pass_write(op, psk_info->write_iovec, 1, 
                outlen, globus_l_xio_psk_write_cb, psk_info);
            if(res != GLOBUS_SUCCESS)
            {
                /* must handle all error case */
                goto error;
            }
        }
        else
        {
            /* not enough data in write_buffer to encrypt so signal that 
                need more data by finishing write*/
            globus_xio_driver_finished_write(op, GLOBUS_SUCCESS, copy_amt);
        }
    }

    return GLOBUS_SUCCESS;

error:
    return res;

}

