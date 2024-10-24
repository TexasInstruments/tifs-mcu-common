/*
 * pke_baseaddress.h SOC specific File
 *
 * This file contains base addresses for PKE
 *
 * Copyright (C) 2024 Texas Instruments Incorporated - http://www.ti.com/
 * ALL RIGHTS RESERVED
 *
 */


/**
 *  \defgroup SECURITY_PKE_MODULE APIs for PKE
 *  \ingroup  SECURITY_MODULE
 *
 *  This module contains APIs to program and use the PKE.
 *
 *  @{
 */

/**
 *  \file pke_baseaddress.h
 *
 *  \brief This file contains the prototype of PKE driver APIs
 */

#ifndef PKE_BASEADDRESS_H_
#define PKE_BASEADDRESS_H_

/**
 * @brief Base Address
 * @details Note: This is CRI specific.
 * Register addresses are derived
 * using this address
 */
#define CRI_PKE_REGISTER_BASE_ADDRESS 0xCE010000

/**
 * @brief Base Address of MAU SRAM
 * @details Note: This is CRI specific.
 * PKE RAM addresses are derived
 * using this address.
 */
#define CRI_PKE_SRAM_BASE_ADDRESS 0xCE012000

#endif // PKE_BASEADDRESS_H_
