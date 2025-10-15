/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @addtogroup RDB
 * @{
 *
 * @brief The relational database (RDB) store manages data based on relational models.
 * With the underlying SQLite database, the RDB store provides a complete mechanism for managing local databases.
 * To satisfy different needs in complicated scenarios, the RDB store offers a series of APIs for performing operations
 * such as adding, deleting, modifying, and querying data, and supports direct execution of SQL statements.
 *
 * @since 10
 */

/**
 * @file oh_rdb_crypto_param.h
 *
 * @brief Provides functions and enumerations related to cryptographic parameters of the relational database.
 *
 * @kit ArkData
 * @library libnative_rdb_ndk.z.so
 * @syscap SystemCapability.DistributedDataManager.RelationalStore.Core
 *
 * @since 20
 */

#ifndef OH_RDB_CRYPTO_PARAM_H
#define OH_RDB_CRYPTO_PARAM_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumerates the database encryption algorithms.
 *
 * @since 20
 */
typedef enum Rdb_EncryptionAlgo {
    /**
     * @brief Indicates the database is encrypted using RDB_AES_256_GCM.
     *
     * @since 20
     */
    RDB_AES_256_GCM = 0,
    /**
     * @brief Indicates the database is encrypted using RDB_AES_256_CBC.
     *
     * @since 20
     */
    RDB_AES_256_CBC,
    /**
     * @brief Indicates the database is encrypted using RDB_PLAIN_TEXT.
     *
     * @since 22
     */
    RDB_PLAIN_TEXT,
} Rdb_EncryptionAlgo;

/**
 * @brief Enumerates the supported HMAC algorithm when opening a database.
 *
 * @since 20
 */
typedef enum Rdb_HmacAlgo {
    /**
     * @brief RDB_HMAC_SHA1 algorithm.
     *
     * @since 20
     */
    RDB_HMAC_SHA1 = 0,
    /**
     * @brief RDB_HMAC_SHA256 algorithm.
     *
     * @since 20
     */
    RDB_HMAC_SHA256,
    /**
     * @brief RDB_HMAC_SHA512 algorithm.
     *
     * @since 20
     */
    RDB_HMAC_SHA512,
} Rdb_HmacAlgo;

/**
 * @brief Enumerates the supported KDF algorithm when opening a database.
 *
 * @since 20
 */
typedef enum Rdb_KdfAlgo {
    /**
     * @brief RDB_KDF_SHA1 algorithm.
     *
     * @since 20
     */
    RDB_KDF_SHA1 = 0,
    /**
     * @brief RDB_KDF_SHA256 algorithm.
     *
     * @since 20
     */
    RDB_KDF_SHA256,
    /**
     * @brief RDB_KDF_SHA512 algorithm.
     *
     * @since 20
     */
    RDB_KDF_SHA512,
} Rdb_KdfAlgo;

/**
 * @brief Specifies the cryptographic parameters used when opening an encrypted database.
 *
 * @since 20
 */
typedef struct OH_Rdb_CryptoParam OH_Rdb_CryptoParam;

/**
 * @brief Creates an OH_Rdb_CryptoParam instance object.
 *
 * @return Returns a pointer to OH_Rdb_CryptoParam instance when the execution is successful.
 * Otherwise, nullptr is returned. The memory must be released through the OH_Rdb_DestroyCryptoParam
 * interface after the use is complete.
 * @see OH_Rdb_DestroyCryptoParam.
 * @since 20
 */
OH_Rdb_CryptoParam *OH_Rdb_CreateCryptoParam(void);

/**
 * @brief Destroys an OH_Rdb_CryptoParam instance object.
 *
 * @param param Represents a pointer to an instance of OH_Rdb_CryptoParam.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 20
 */
int OH_Rdb_DestroyCryptoParam(OH_Rdb_CryptoParam *param);

/**
 * @brief Sets key data to the OH_Rdb_CryptoParam object.
 *
 * @param param Represents a pointer to an instance of OH_Rdb_CryptoParam.
 * @param key Represents a pointer to array data.
 * @param length Represents the size of key array.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 20
 */
int OH_Crypto_SetEncryptionKey(OH_Rdb_CryptoParam *param, const uint8_t *key, int32_t length);

/**
 * @brief Sets the number of KDF iterations used when opening an encrypted database.
 *
 * @param param Represents a pointer to an instance of OH_Rdb_CryptoParam.
 * @param iteration Represents a pointer to array data.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 20
 */
int OH_Crypto_SetIteration(OH_Rdb_CryptoParam *param, int64_t iteration);

/**
 * @brief Sets the encryption algorithm when opening an encrypted database.
 *
 * @param param Represents a pointer to an instance of OH_Rdb_CryptoParam.
 * @param algo Represents the encryption algorithm.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 20
 */
int OH_Crypto_SetEncryptionAlgo(OH_Rdb_CryptoParam *param, int32_t algo);

/**
 * @brief Sets the HMAC algorithm when opening an encrypted database.
 *
 * @param param Represents a pointer to an instance of OH_Rdb_CryptoParam.
 * @param algo Represents the HMAC algorithm.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 20
 */
int OH_Crypto_SetHmacAlgo(OH_Rdb_CryptoParam *param, int32_t algo);

/**
 * @brief Sets the KDF algorithm when opening an encrypted database.
 *
 * @param param Represents a pointer to an instance of OH_Rdb_CryptoParam.
 * @param algo Represents the KDF algorithm.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 20
 */
int OH_Crypto_SetKdfAlgo(OH_Rdb_CryptoParam *param, int32_t algo);

/**
 * @brief Sets the page size used when opening an encrypted database.
 *
 * @param param Represents a pointer to an instance of OH_Rdb_CryptoParam.
 * @param size Represents the page size.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 20
 */
int OH_Crypto_SetCryptoPageSize(OH_Rdb_CryptoParam *param, int64_t size);

#ifdef __cplusplus
};
#endif
#endif
/** @} */
