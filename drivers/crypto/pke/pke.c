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
#include <modules/ecdsa/ecdsa.h>
#include <crypto/asym_crypt.h>
#include <crypto/rng/rng.h>
#include <modules/crypto/crypto_rng_interface.h>

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

static uint32_t PKE_bigIntBitLen(const uint32_t bn[ECDSA_MAX_LENGTH]);
static AsymCrypt_Return_t PKE_isBigIntZero(const uint32_t bn[RSA_MAX_LENGTH]);

cri_pke_context_t 	gPKEContext;
cri_pke_t 			gPKE;

RNG_Handle     pke_rng_handle   = NULL;
uint8_t signatureRPrime[68];

uint32_t pke_temp_buff[RSA_MAX_LENGTH] = {0U};

extern const uint32_t numPrimeCurves;
extern const ECDSA_primeCurve primeCurves[];

/* ========================================================================== */
/*                          Function Definitions                              */
/* ========================================================================== */

AsymCrypt_Return_t PKE_getPrimeCurveId (const struct AsymCrypt_ECPrimeCurveP *curveParams, uint32_t *pkeCurveType)
{
    AsymCrypt_Return_t retVal = ASYM_CRYPT_RETURN_SUCCESS;
    uint32_t i = 0U;

    if(ASYM_CRYPT_RETURN_SUCCESS == retVal)
    {
        /* Check if the curveId is supported */
        for (i = 0; i < numPrimeCurves; i++) {
            if (memcmp(&curveParams->prime[0], primeCurves[i].prime, 4U*curveParams->prime[0]) != 0)
            {
                retVal = ASYM_CRYPT_RETURN_FAILURE;
            }
            else
            {
                /* Check if the curveId is supported */
                if (memcmp(&curveParams->a[0], primeCurves[i].A, 4U*curveParams->a[0]) != 0)
                {
                    retVal = ASYM_CRYPT_RETURN_FAILURE;
                }

                if (memcmp(&curveParams->b[0], primeCurves[i].B, 4U*curveParams->b[0]) != 0)
                {
                    retVal = ASYM_CRYPT_RETURN_FAILURE;
                }

                if (memcmp(&curveParams->order[0], primeCurves[i].order, 4U*curveParams->order[0]) != 0)
                {
                    retVal = ASYM_CRYPT_RETURN_FAILURE;
                }
                else
                {
                    retVal = ASYM_CRYPT_RETURN_SUCCESS;
                    *pkeCurveType = primeCurves[i].curveType;
                    break;
                }
            }
        }
    }

    return retVal;
}

AsymCrypt_Handle AsymCrypt_open(uint32_t index)
{
    AsymCrypt_Handle handle;

    /* Open rng instance */
    pke_rng_handle = gRngHandle;
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
    AsymCrypt_Return_t status  = ASYM_CRYPT_RETURN_FAILURE;
    int pkeStatus = -1;
    uint32_t curveType = 0;
    cri_ecc_curve_t curve;
    uint32_t bigEndianHash[ECDSA_MAX_LENGTH];
    uint32_t size = cp->prime[0];
    uint32_t curvelen = 0;

    /* check sizes */
    if ((!((size <= 2U) || (size > (ECDSA_MAX_LENGTH - 1U)) ||
           (size != cp->order[0]) || (size < cp->a[0]) ||
           (size < cp->b[0]) || (size < cp->g.x[0]) ||
           (size < cp->g.y[0]) || (size < priv[0]) ||
           (size < h[0]) || (size < k[0]))) &&
           (PKE_bigIntBitLen(cp->order) >= PKE_bigIntBitLen(h)))
    {
        /* Checking handle is opened or not */
        if(NULL != handle)
        {
            status = ASYM_CRYPT_RETURN_SUCCESS;
        }
    }

    if(status == ASYM_CRYPT_RETURN_SUCCESS)
    {
        /* Get the size of input hash */
        size = h[0];

        /* PKE only supports Hash as a BigEndian input */
        Crypto_bigIntToUint32((uint32_t *)&h[0], size, (uint32_t *)&bigEndianHash[0]);
        
        /* Mapping the curve parameters as input to curve type */
        status = PKE_getPrimeCurveId(cp, &curveType);
        if(status == ASYM_CRYPT_RETURN_SUCCESS)
        {
            /* Get curve id based on the cri_ecc_curve_t param set */
            curve = cri_pke_get_curve(curveType);

            if (curve->curve == NIST_SECP521r1)
            {
                /* Incase of Sec521, the hashlen > curvelen and that should be input to the PKE function */
                curvelen = size*4U;
            }
            else
            {
                /* Get curve length */
                curvelen = cri_pke_get_curve_length(curve);
            }

            /* Call the ECDSA Sign function */
            pkeStatus = cri_pke_ecdsa_sign_hash(gPKE, curve, &priv[1U], &bigEndianHash[0], curvelen, &sig->r[1U], &sig->s[1U]);

            sig->r[0] = cp->prime[0];
            sig->s[0] = cp->prime[0];

            /* Revert the input back to original state */
            Crypto_Uint32ToBigInt((uint32_t *)&bigEndianHash, size, (uint32_t *)&h[0]);

            if (pkeStatus == 0)
            {
                status  = ASYM_CRYPT_RETURN_SUCCESS;
            }
            else
            {
                status  = ASYM_CRYPT_RETURN_FAILURE;
            }
        }
    }

    return (status);
}

AsymCrypt_Return_t AsymCrypt_ECDSAVerify(AsymCrypt_Handle handle,
                        const struct AsymCrypt_ECPrimeCurveP *cp, 
                        const struct AsymCrypt_ECPoint *pub, 
                        const struct AsymCrypt_ECDSASig *sig, 
                        const uint32_t h[ECDSA_MAX_LENGTH])
{
    AsymCrypt_Return_t status  = ASYM_CRYPT_RETURN_FAILURE;
    int pkeStatus = -1;
    uint32_t curveType = 0;
    cri_ecc_curve_t curve;
    uint32_t bigEndianHash[ECDSA_MAX_LENGTH];
    uint32_t size = cp->prime[0];
    uint32_t curvelen = 0;

    /* check sizes */
    if ((!((size <= 2U) || (size > (ECDSA_MAX_LENGTH - 1U)) ||
           (size != cp->order[0]) || (size < cp->a[0]) ||
           (size < cp->b[0]) || (size < cp->g.x[0]) ||
           (size < cp->g.y[0]) || (size < pub->x[0]) ||
           (size < pub->y[0]) || (size < sig->r[0]) ||
           (size < sig->s[0]) || (size < h[0]))) &&
            (PKE_bigIntBitLen(cp->order) >= PKE_bigIntBitLen(h)) &&
            PKE_isBigIntZero(sig->r) && PKE_isBigIntZero(sig->s))
    {
        /* Checking handle is opened or not */
        if(NULL != handle)
        {
            status = ASYM_CRYPT_RETURN_SUCCESS;
        }
    }

    if(status == ASYM_CRYPT_RETURN_SUCCESS)
    {
        /* Get the size of input hash */
        size = h[0];

        /* PKE only supports Hash as a BigEndian input */
        Crypto_bigIntToUint32((uint32_t *)&h[0], size, (uint32_t *)&bigEndianHash[0]);
        
        /* Mapping the curve parameters as input to curve type */
        status = PKE_getPrimeCurveId(cp, &curveType);
        if(status == ASYM_CRYPT_RETURN_SUCCESS)
        {
            /* Get curve id based on the cri_ecc_curve_t param set */
            curve = cri_pke_get_curve(curveType);

            if (curve->curve == NIST_SECP521r1)
            {
                /* Incase of Sec521, the hashlen > curvelen and that should be input to the PKE function */
                curvelen = size*4U;
            }
            else
            {
                /* Get curve length */
                curvelen = cri_pke_get_curve_length(curve);
            }

            /* Call the ECDSA Verify function */
            pkeStatus = cri_pke_ecdsa_verify_hash(gPKE, curve, &pub->x[1U], &pub->y[1U], &bigEndianHash[0U], curvelen, &sig->r[1U], &sig->s[1U], &signatureRPrime);

            /* Revert the input back to original state */
            Crypto_Uint32ToBigInt((uint32_t *)&bigEndianHash, size, (uint32_t *)&h[0]);

            if (pkeStatus == 0)
            {
                status  = ASYM_CRYPT_RETURN_SUCCESS;
            }
            else
            {
                status  = ASYM_CRYPT_RETURN_FAILURE;
            }
        }
    }

    return (status);
}

uint32_t PKE_countLeadingZeros(uint32_t x)
{
    uint32_t bit_count = 0, lz = 0;

    bit_count = sizeof(x)*8;

    /* Left shift until Most significant bit doesn become 1 */

    while( (x & (1 << (bit_count - 1))) == 0)
    {
        x <<= 1;
        lz++;
    }

    return (lz);
}

/**
 * \brief Return the size in bits of a bigint
 *
 * \param bn Input number
 *
 * \return Length in bits of the big number
 */
static uint32_t PKE_bigIntBitLen(const uint32_t bn[ECDSA_MAX_LENGTH])
{
    uint32_t i, status;

    for (i = bn[0]; i > 0U; i--)
    {
        if (bn[i] != 0U)
        {
            break;
        }
    }
    if (i == 0U)
    {
        status = 0U;
    }
    else
    {
        status = (i * 32U) - PKE_countLeadingZeros((int32_t) bn[i]);
    }
    return (status);
}

/**
 * \brief Check if the bigint is zero
 *
 * \param bn Input number
 *
 * \return ASYM_CRYPT_RETURN_SUCCESS if the number if zero
 */
static AsymCrypt_Return_t PKE_isBigIntZero(const uint32_t bn[RSA_MAX_LENGTH])
{
    uint32_t i;
    AsymCrypt_Return_t ret = ASYM_CRYPT_RETURN_SUCCESS;

    for (i = 0U; i <= bn[0]; i++)
    {
        if (bn[i] != 0U)
        {
            ret = ASYM_CRYPT_RETURN_FAILURE;
            break;
        }
    }
    return (ret);
}
