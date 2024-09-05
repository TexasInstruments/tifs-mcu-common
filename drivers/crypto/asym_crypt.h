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
 *  \defgroup SECURITY_ASYMCRYPT_MODULE APIs for ASYMMETRIC CRYPTOGRAPHY
 *  \ingroup  SECURITY_MODULE
 *
 *  This module contains APIs to program and use the ASYMMETRIC CRYPTOGRAPHY.
 *
 *  @{
 */

/**
 *  \file asym_crypt.h
 *
 *  \brief This file contains the prototype of ASYMMETRIC CRYPTOGRAPHY driver APIs
 */

#ifndef ASYM_CRYPT_H_
#define ASYM_CRYPT_H_

/* ========================================================================== */
/*                             Include Files                                  */
/* ========================================================================== */

#include <stdint.h>
#include <kernel/dpl/SystemP.h>
#include <security_common/drivers/crypto/crypto_util.h>

#if defined (SOC_AM64X) || defined (SOC_AM243X)\
	|| defined(SOC_AM263X) || defined(SOC_AM263PX)\
	|| defined (SOC_AM273X) || defined (SOC_AWR294X)
#include <security_common/drivers/crypto/pka/pka.h>
#endif

#if defined(SOC_F29H85X) || defined (SOC_AM261X)
#include <security_common/drivers/crypto/pke/hw_include/pke_hw/inc/pke.h>
#include <security_common/drivers/crypto/pke/hw_include/pke_hw/src/pke4_driver.h>
#include <security_common/drivers/crypto/pke/hw_include/pke_hw/inc/pke_dpasl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/*                           Macros & Typedefs                                */
/* ========================================================================== */

/**
 * \brief
 *  ASYM CRYPTO Driver Error code
 *
 * \details
 *  The enumeration describes all the possible return and error codes which
 *  the ASYM CRYPTO Driver can return
 */
typedef enum AsymCrypt_Return_e
{
    ASYM_CRYPT_RETURN_SUCCESS                  = 0xCEF6A572U, /*!< Success/pass return code */
    ASYM_CRYPT_RETURN_FAILURE                  = 0xD20341DDU, /*!< General or unspecified failure/error */
}AsymCrypt_Return_t;

/** \brief Handle to the AsymCrypt driver */
typedef void *AsymCrypt_Handle;

/** Max size of AsymCrypt Data in words - for RSA */
#define RSA_MAX_LENGTH                      (130U)

/** Max size of AsymCrypt Data in words - for ECDSA */
#define ECDSA_MAX_LENGTH                    (18U)

/**
 * Maximum length of a AsymCrypt data used in EC crypto in bytes, enough to
 * accommodate 521-bit prime curves
 */
#define EC_PARAM_MAXLEN						(68U)

/**
 * Length of a data array in words
 */
#define ASYM_CRYPT_LEN(bytelen)                 		(((bytelen) / 4U) + 1U)

/** RSA KEY E maximun length */
#define RSA_KEY_E_MAXLEN                    (8U)
/** RSA KEY N maximun length */
#define RSA_KEY_N_MAXLEN                    (520U)
/** RSA KEY PQ maximun length */
#define RSA_KEY_PQ_MAXLEN                   ((RSA_KEY_N_MAXLEN / 2U) + 4U)
/** RSA KEY SIG maximun length */
#define RSA_SIG_MAXLEN                      RSA_KEY_N_MAXLEN

/* ========================================================================== */
/*                         Structure Declarations                             */
/* ========================================================================== */

/**
 * \brief RSA public key. All values are in biginteger format (size followed
 *        by word value array, least significant word first)
 *
 * \param n RSA modulus (n)
 * \param e Public exponent (e)
 */
struct AsymCrypt_RSAPubkey {
	/** RSA modulus (n) */
	uint32_t	n[ASYM_CRYPT_LEN(RSA_KEY_N_MAXLEN)];
	/** Public exponent (e) */
	uint32_t	e[ASYM_CRYPT_LEN(RSA_KEY_E_MAXLEN)];
};

/**
 * \brief RSA private key. All values are in biginteger format (size followed
 *        by word value array, least significant word first)
 *
 * \param n RSA modulus (n)
 * \param e Public exponent (e)
 * \param d Private exponent (d)
 * \param p Prime 1 (p)
 * \param q Prime 2 (q)
 * \param dp d mod (p-1)
 * \param dq d mod (q-1)
 * \param coefficient crt coefficient q^(-1) mod p
 */
struct AsymCrypt_RSAPrivkey {
	/** RSA modulus (n) */
	uint32_t	n[ASYM_CRYPT_LEN(RSA_KEY_N_MAXLEN)];
	/** Public exponent (e) */
	uint32_t	e[ASYM_CRYPT_LEN(RSA_KEY_E_MAXLEN)];
	/** Private exponent (d) */
	uint32_t	d[ASYM_CRYPT_LEN(RSA_KEY_N_MAXLEN)];
	/** Prime 1 (p) */
	uint32_t	p[ASYM_CRYPT_LEN(RSA_KEY_PQ_MAXLEN)];
	/** Prime 2 (q) */
	uint32_t	q[ASYM_CRYPT_LEN(RSA_KEY_PQ_MAXLEN)];
	/** d mod (p-1) */
	uint32_t	dp[ASYM_CRYPT_LEN(RSA_KEY_PQ_MAXLEN)];
	/** d mod (q-1) */
	uint32_t	dq[ASYM_CRYPT_LEN(RSA_KEY_PQ_MAXLEN)];
	/** crt coefficient q^(-1) mod p */
	uint32_t	coefficient[ASYM_CRYPT_LEN(RSA_KEY_PQ_MAXLEN)];
};

/**
 * \brief EC Point, also the public key
 *
 * \param x x-coordinate
 * \param y y-coordinate
 */
struct AsymCrypt_ECPoint {
	/** x-coordinate */
	uint32_t	x[ASYM_CRYPT_LEN(EC_PARAM_MAXLEN)];
	/** y-coordinate */
	uint32_t	y[ASYM_CRYPT_LEN(EC_PARAM_MAXLEN)];
};

/**
 * \brief EC prime curve parameters
 *
 * \param prime Prime number for the group
 * \param order Order of the group
 * \param a "a" parameter in the equation x^3 + ax + b = y
 * \param b "b" parameter in the equation x^3 + ax + b = y
 * \param g Generator point on the Elliptic curve
 */
struct AsymCrypt_ECPrimeCurveP {
	/** Prime number for the group */
	uint32_t		prime[ASYM_CRYPT_LEN(EC_PARAM_MAXLEN)];
	/** Order of the group */
	uint32_t		order[ASYM_CRYPT_LEN(EC_PARAM_MAXLEN)];
	/** "a" parameter in the equation x^3 + ax + b = y */
	uint32_t		a[ASYM_CRYPT_LEN(EC_PARAM_MAXLEN)];
	/** "b" parameter in the equation x^3 + ax + b = y */
	uint32_t		b[ASYM_CRYPT_LEN(EC_PARAM_MAXLEN)];
	/** Generator point on the Elliptic curve */
	struct AsymCrypt_ECPoint g;
};

/**
 * \brief ECDSA signature
 *
 * \param r "r" value in ECDSA signature
 * \param s "s" value in ECDSA signature
 */
struct AsymCrypt_ECDSASig {
	/** "r" value in ECDSA signature */
	uint32_t	r[ASYM_CRYPT_LEN(EC_PARAM_MAXLEN)];
	/** "s" value in ECDSA signature */
	uint32_t	s[ASYM_CRYPT_LEN(EC_PARAM_MAXLEN)];
};

/* ========================================================================== */
/*                            Global Variables                                */
/* ========================================================================== */

/* ========================================================================== */
/*                              Function Definitions                          */
/* ========================================================================== */

/**
 * \brief Function to Open AsymCrypt instance, enable AsymCrypt engine, Initialize clocks
 *
 * \return        A #AsymCrypt_Handle on success or a NULL on an error or if it has been
 *				  opened already
 */
AsymCrypt_Handle AsymCrypt_open(uint32_t index);

/**
 *  \brief  Function to close a AsymCrypt module specified by the AsymCrypt handle
 *
 *  \param  handle  #AsymCrypt_Handle returned from #AsymCrypt_open()
 */
AsymCrypt_Return_t AsymCrypt_close(AsymCrypt_Handle handle);

/**
 * \brief This Function performs Decryption or Signing operations
 *
 * \param  handle  #AsymCrypt_Handle returned from #AsymCrypt_open()
 * 
 * \param m       m value in bigint format.
 * \param k       RSA private key
 *
 * \param result  Result of the operation in bigint format. caller must allocate
 *                memory size of (2 * sizeof(p)) for the result.
 *
 * \return        #ASYM_CRYPT_RETURN_SUCCESS if requested operation completed.
 *                #ASYM_CRYPT_RETURN_FAILURE if requested operation not completed.
 */
AsymCrypt_Return_t AsymCrypt_RSAPrivate(AsymCrypt_Handle handle, const uint32_t m[RSA_MAX_LENGTH], const struct AsymCrypt_RSAPrivkey *k, uint32_t result[RSA_MAX_LENGTH]);

/**
 * \brief This Function performs Encryption or Verification operations
 *
 * \param  handle  #AsymCrypt_Handle returned from #AsymCrypt_open()
 * 
 * \param m       m value in bigint format.
 * \param k       RSA public key
 * \param result  Result of the operation in bigint format. caller must allocate
 *                the same memory as s and n for this array.
 *
 * \return        #ASYM_CRYPT_RETURN_SUCCESS if requested operation completed.
 *                #ASYM_CRYPT_RETURN_FAILURE if requested operation not completed.
 */
AsymCrypt_Return_t AsymCrypt_RSAPublic(AsymCrypt_Handle handle, const uint32_t m[RSA_MAX_LENGTH], const struct AsymCrypt_RSAPubkey *k, uint32_t result[RSA_MAX_LENGTH]);

/**
 * \brief ECDSA sign primitive function
 *
 * \param  handle  #AsymCrypt_Handle returned from #AsymCrypt_open()
 * 
 * \param cp      EC curve parameters
 * \param priv    EC private key
 * \param k       Random number for each signing
 * \param h       Hash value of message to sign in bigint format
 * \param sig     ECDSA Signature - 'r' and 's' values
 * \return        #ASYM_CRYPT_RETURN_SUCCESS if requested operation completed.
 *                #ASYM_CRYPT_RETURN_FAILURE if requested operation not completed.
 */
AsymCrypt_Return_t AsymCrypt_ECDSASign(AsymCrypt_Handle handle, 
                    const struct AsymCrypt_ECPrimeCurveP *cp, 
                    const uint32_t priv[ECDSA_MAX_LENGTH], 
                    const uint32_t k[ECDSA_MAX_LENGTH], 
                    const uint32_t h[ECDSA_MAX_LENGTH], 
                    struct AsymCrypt_ECDSASig *sig);

/**
 * \brief ECDSA verify primitive function
 *
 * \param  handle  #AsymCrypt_Handle returned from #AsymCrypt_open()
 * 
 * \param cp      EC curve parameters
 * \param pub     EC Public key
 * \param sig     ECDSA Signature - 'r' & 's' value in bigint format
 * \param h       Hash value of message to verify in bigint format
 *
 * \return        #ASYM_CRYPT_RETURN_SUCCESS if requested operation completed.
 *                #ASYM_CRYPT_RETURN_FAILURE if requested operation not completed.
 */
AsymCrypt_Return_t AsymCrypt_ECDSAVerify(AsymCrypt_Handle handle,
                        const struct AsymCrypt_ECPrimeCurveP *cp, 
                        const struct AsymCrypt_ECPoint *pub, 
                        const struct AsymCrypt_ECDSASig *sig, 
                        const uint32_t h[ECDSA_MAX_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif /* ASYM_CRYPT_H_ */

/** @} */
