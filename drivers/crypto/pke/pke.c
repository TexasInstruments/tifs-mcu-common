/*
 *  Copyright (C) 2024 Texas Instruments Incorporated
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *    Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 *    Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the
 *    distribution.
 *
 *    Neither the name of Texas Instruments Incorporated nor the names of
 *    its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 *  \file   pke.c
 *
 *  \brief  This file contains the implementation of PKE ( Ultra lite Security Accelerator)(Public Key Accelerator) driver
 */

/* ========================================================================== */
/*                             Include Files                                  */
/* ========================================================================== */

#include <string.h>
#include <stddef.h>
#include <crypto/asym_crypt.h>
#include <crypto/rng/rng.h>

/* ========================================================================== */
/*                           Macros & Typedefs                                */
/* ========================================================================== */

/*
 * Timeout values in microsecs
 */
/**
 * Timeout for register updates to take effect - 10us
 */
#define PKE_REG_TIMEOUT                            (10U)

/**
 * Timeout for compare of 2 bignums - 100us
 */
#define PKE_COMPARE_TIMEOUT                        (100U)

/**
 * Timeout for modexp CRT operation - 50ms
 */
#define PKE_MODEXP_CRT_TIMEOUT                     (50000U)

/**
 * Timeout for modexp operation - 10ms
 */
#define PKE_MODEXP_TIMEOUT                         (10000U)

/**
 * Timeout for ECDSA verify operation - 10ms
 */
#define PKE_ECDSA_VERIFY_TIMEOUT                   (10000U)

/**
 * Timeout for ECDSA sign operation - 10ms
 */
#define PKE_ECDSA_SIGN_TIMEOUT                     (10000U)

/** \brief device type HSSE */
#define DEVTYPE_HSSE         (0x0AU)

/* ========================================================================== */
/*                         Structure Declarations                             */
/* ========================================================================== */

/* ========================================================================== */
/*                 Internal Function Declarations                             */
/* ========================================================================== */

cri_pke_context_t 	gPKEContext;
cri_pke_t 			gPKE;

RNG_Handle     pke_rng_handle   = NULL;

uint32_t pke_temp_buff[RSA_MAX_LENGTH] = {0U};

/* ========================================================================== */
/*                          Function Definitions                              */
/* ========================================================================== */

AsymCrypt_Handle AsymCrypt_open(uint32_t index)
{
    AsymCrypt_Handle handle;

    /* Open rng instance */
    pke_rng_handle = RNG_open(0);
    DebugP_assert(pke_rng_handle != NULL);

    RNG_setup(pke_rng_handle);

    gPKEContext.copy_flags = 0U;
    gPKEContext.resp_flags = 0U;

    gPKE = cri_pke_open(&gPKEContext);
    if(gPKE == NULL)
    {
        handle = NULL;
    }
    else
    {
        handle = &gPKE;
    }

    return handle;
}

AsymCrypt_Return_t AsymCrypt_close(AsymCrypt_Handle handle)
{
    AsymCrypt_Return_t status  = ASYM_CRYPT_RETURN_FAILURE;

    /* Open rng instance */
    if(RNG_RETURN_FAILURE != RNG_close(pke_rng_handle))
    {
        status  = ASYM_CRYPT_RETURN_SUCCESS;
    }
    else
    {
        status  = ASYM_CRYPT_RETURN_FAILURE;
    }

    return (status);
}

AsymCrypt_Return_t AsymCrypt_RSAPrivate(AsymCrypt_Handle handle,
                    const uint32_t m[RSA_MAX_LENGTH],
                    const struct AsymCrypt_RSAPrivkey *k,
                    uint32_t result[RSA_MAX_LENGTH])
{
    AsymCrypt_Return_t status  = ASYM_CRYPT_RETURN_FAILURE;
    int pkeStatus = -1;
    uint32_t pubmod_bitsize = k->n[0]*4U;
    uint32_t exp_size = k->e[0]*4U;
    uint32_t size = k->p[0];

    struct cri_rsa_key pke_rsa_key_ctx = {
        .bits = (pubmod_bitsize*8U),
        .flags = 0,
        .n = (uint8_t *)&k->n[1],
        .e = (uint8_t *)&k->e[1],
        .elength = exp_size,
        .d1 = (uint8_t *)&k->d[1],
        .d2 = NULL,
        .message = (uint8_t *)&m[1U],
        .signature = (uint8_t *)&result[1U]
    };

    /* check sizes, sizes of s and n must match. */
    if ((!((size <= 1U) || (size > ((RSA_MAX_LENGTH - 1U) >> 1)) ||
           (k->q[0] > size) || (k->dp[0] > size) || (k->dq[0] > size) ||
           (k->coefficient[0] > size) || (m[0] > (size * 2U)))))
    {
        /* Checking handle is opened or not */
        if(NULL != handle)
        {
            status = ASYM_CRYPT_RETURN_SUCCESS;
        }
    }
    if(ASYM_CRYPT_RETURN_SUCCESS == status)
    {
        pkeStatus = cri_pke_rsa_sign(&gPKEContext, &pke_rsa_key_ctx);
        if (pkeStatus == 0)
        {
            result[0] = k->n[0];
            status  = ASYM_CRYPT_RETURN_SUCCESS;
        }
        else
        {
            status  = ASYM_CRYPT_RETURN_FAILURE;
        }
    }

    return (status);
}

AsymCrypt_Return_t AsymCrypt_RSAPublic(AsymCrypt_Handle handle, 
                    const uint32_t m[RSA_MAX_LENGTH],
                    const struct AsymCrypt_RSAPubkey *k,
                    uint32_t result[RSA_MAX_LENGTH])
{
    AsymCrypt_Return_t status  = ASYM_CRYPT_RETURN_FAILURE;
    int pkeStatus = -1;
    uint32_t pubmod_bitsize = k->n[0]*4U;
    uint32_t exp_size = k->e[0]*4U;
    uint32_t size = k->n[0];

    struct cri_rsa_key pke_rsa_key_ctx = {
        .bits = (pubmod_bitsize*8U),
        .flags = 0,
        .n = (uint8_t *)&k->n[1],
        .e = (uint8_t *)&k->e[1],
        .elength = exp_size,
        .d1 = NULL,
        .d2 = NULL,
        .signature = (uint8_t *)&m[1U],
        .message = (uint8_t *)&result[1U]
    };

    /* check sizes, sizes of s and n must match. */
    if ((!((size <= 1U) || (size > (RSA_MAX_LENGTH - 1U)) ||
           (m[0] != size) || (k->e[0] > (RSA_MAX_LENGTH - 1U)))))
    {
        /* Checking handle is opened or not */
        if(NULL != handle)
        {
            status = ASYM_CRYPT_RETURN_SUCCESS;
        }
    }

    if(status == ASYM_CRYPT_RETURN_SUCCESS)
    {
        pkeStatus = cri_pke_rsa_pub(&gPKEContext, &pke_rsa_key_ctx);
        if (pkeStatus == 0)
        {
            result[0] = k->n[0];
            status  = ASYM_CRYPT_RETURN_SUCCESS;
        }
        else
        {
            status  = ASYM_CRYPT_RETURN_FAILURE;
        }
    }

    return (status);
}

AsymCrypt_Return_t AsymCrypt_ECDSASign(AsymCrypt_Handle handle, 
                    const struct AsymCrypt_ECPrimeCurveP *cp, 
                    const uint32_t priv[ECDSA_MAX_LENGTH], 
                    const uint32_t k[ECDSA_MAX_LENGTH], 
                    const uint32_t h[ECDSA_MAX_LENGTH], 
                    struct AsymCrypt_ECDSASig *sig)
{
    AsymCrypt_Return_t status  = ASYM_CRYPT_RETURN_SUCCESS;
    return (status);
}

AsymCrypt_Return_t AsymCrypt_ECDSAVerify(AsymCrypt_Handle handle,
                        const struct AsymCrypt_ECPrimeCurveP *cp, 
                        const struct AsymCrypt_ECPoint *pub, 
                        const struct AsymCrypt_ECDSASig *sig, 
                        const uint32_t h[ECDSA_MAX_LENGTH])
{
    AsymCrypt_Return_t status  = ASYM_CRYPT_RETURN_SUCCESS;
    return (status);
}
