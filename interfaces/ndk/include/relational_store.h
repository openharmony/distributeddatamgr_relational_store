/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef RELATIONAL_STORE_H
#define RELATIONAL_STORE_H

/**
 * @addtogroup RDB
 * @{
 *
 * @brief The relational database (RDB) store manages data based on relational models.
 * With the underlying SQLite database, the RDB store provides a complete mechanism for managing local databases.
 * To satisfy different needs in complicated scenarios, the RDB store offers a series of APIs for performing operations
 * such as adding, deleting, modifying, and querying data, and supports direct execution of SQL statements.
 *
 * @syscap SystemCapability.DistributedDataManager.RelationalStore.Core
 * @since 10
 */

/**
 * @file relational_store.h
 *
 * @brief Provides database related functions and enumerations.
 *
 * @since 10
 */

#include "oh_cursor.h"
#include "oh_predicates.h"
#include "oh_value_object.h"
#include "oh_values_bucket.h"
#include "oh_rdb_transaction.h"
#include "oh_rdb_types.h"
#include "oh_rdb_crypto_param.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Describe the security level of the database.
 *
 * @since 10
 */
typedef enum OH_Rdb_SecurityLevel {
    /**
     * @brief Low-level security. Data leaks have a minor impact.
     */
    S1 = 1,
    /**
     * @brief Medium-level security. Data leaks have a major impact.
     */
    S2,
    /**
     * @brief High-level security. Data leaks have a severe impact.
     */
    S3,
    /**
     * @brief Critical-level security. Data leaks have a critical impact.
     */
    S4
} OH_Rdb_SecurityLevel;

/**
 * @brief Describe the security area of the database.
 *
 * @since 11
 */
typedef enum Rdb_SecurityArea {
    /**
     * @brief Security Area 1.
     */
    RDB_SECURITY_AREA_EL1 = 1,
    /**
     * @brief Security Area 2.
     */
    RDB_SECURITY_AREA_EL2,
    /**
     * @brief Security Area 3.
     */
    RDB_SECURITY_AREA_EL3,
    /**
     * @brief Security Area 4.
     */
    RDB_SECURITY_AREA_EL4,
    /**
     * @brief Security Area 5.
     *
     * @since 12
     */
    RDB_SECURITY_AREA_EL5,
} Rdb_SecurityArea;

/**
 * @brief Manages relational database configurations.
 *
 * @since 10
 */
#pragma pack(1)
typedef struct {
    /**
     * Indicates the size of the {@link OH_Rdb_Config}. It is mandatory.
     */
    int selfSize;
    /**
     * Indicates the directory of the database.
     */
    const char *dataBaseDir;
    /**
     * Indicates the name of the database.
     */
    const char *storeName;
    /**
     * Indicates the bundle name of the application.
     */
    const char *bundleName;
    /**
     * Indicates the module name of the application.
     */
    const char *moduleName;
    /**
     * Indicates whether the database is encrypted.
     */
    bool isEncrypt;
    /**
     * Indicates the security level {@link OH_Rdb_SecurityLevel} of the database.
     */
    int securityLevel;
    /**
     * Indicates the security area {@link Rdb_SecurityArea} of the database.
     *
     * @since 11
     */
    int area;
} OH_Rdb_Config;
#pragma pack()

/**
 * @brief Define OH_Rdb_Store type.
 *
 * @since 10
 */
typedef struct {
    /**
     * The id used to uniquely identify the OH_Rdb_Store struct.
     */
    int64_t id;
} OH_Rdb_Store;

/**
 * @brief Define OH_Rdb_ConfigV2 type.
 *
 * @since 14
 */
typedef struct OH_Rdb_ConfigV2 OH_Rdb_ConfigV2;

/**
 * @brief Define Rdb_DBType type.
 *
 * @since 14
 */
typedef enum Rdb_DBType {
    /**
     * @brief Means using SQLITE as the db kernal
     */
    RDB_SQLITE = 1,
    /**
     * @brief Means using CARLEY_DB as the db kernal
     */
    RDB_CAYLEY = 2,
    /**
     * @brief Means largest value for Rdb_DBType
     */
    DBTYPE_BUTT = 64,
} Rdb_DBType;

/**
 * @brief Define Rdb_Tokenizer type.
 *
 * @since 16
 */
typedef enum Rdb_Tokenizer {
    /**
     * @brief Means not using tokenizer.
     */
    RDB_NONE_TOKENIZER = 1,
    /**
     * @brief Means using native icu tokenizer.
     */
    RDB_ICU_TOKENIZER = 2,
    /**
     * @brief Means using self-developed enhance tokenizer.
     */
    RDB_CUSTOM_TOKENIZER = 3,
} Rdb_Tokenizer;

/**
 * @brief Create OH_Rdb_ConfigV2 which is used to open store
 *
 * @return Returns the newly created OH_Rdb_ConfigV2 object. If NULL is returned, the creation fails.
 * The possible cause is that the address space of the application is full, As a result, the space
 * cannot be allocated.
 * @see OH_Rdb_ConfigV2
 * @since 14
 */
OH_Rdb_ConfigV2 *OH_Rdb_CreateConfig();

/**
 * @brief Destroy OH_Rdb_ConfigV2 which is created by OH_Rdb_CreateConfig
 *
 * @param config Represents a pointer to {@link OH_Rdb_ConfigV2} instance.
 * Indicates the configuration of the database related to this RDB store.
 * @return Returns the status code of the execution. Successful execution returns RDB_OK,
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @since 14
 */
int OH_Rdb_DestroyConfig(OH_Rdb_ConfigV2 *config);

/**
 * @brief Set property databaseDir into config
 *
 * @param config Represents a pointer to {@link OH_Rdb_ConfigV2} instance.
 * Indicates the configuration of the database related to this RDB store.
 * @param dataBaseDir Indicates the directory of the database.
 * @return Returns the status code of the execution. Successful execution returns RDB_OK,
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @since 14
 */
int OH_Rdb_SetDatabaseDir(OH_Rdb_ConfigV2 *config, const char *databaseDir);

/**
 * @brief Set property storeName into config
 *
 * @param config Represents a pointer to {@link OH_Rdb_ConfigV2} instance.
 * Indicates the configuration of the database related to this RDB store.
 * @param storeName Indicates the name of the database.
 * @return Returns the status code of the execution. Successful execution returns RDB_OK,
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @since 14
 */
int OH_Rdb_SetStoreName(OH_Rdb_ConfigV2 *config, const char *storeName);

/**
 * @brief Set property bundleName into config
 *
 * @param config Represents a pointer to {@link OH_Rdb_ConfigV2} instance.
 * Indicates the configuration of the database related to this RDB store.
 * @param bundleName Indicates the bundle name of the application
 * @return Returns the status code of the execution. Successful execution returns RDB_OK,
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @since 14
 */
int OH_Rdb_SetBundleName(OH_Rdb_ConfigV2 *config, const char *bundleName);

/**
 * @brief Set property moduleName into config
 *
 * @param config Represents a pointer to {@link OH_Rdb_ConfigV2} instance.
 * Indicates the configuration of the database related to this RDB store.
 * @param moduleName Indicates the module name of the application.
 * @return Returns the status code of the execution. Successful execution returns RDB_OK,
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @since 14
 */
int OH_Rdb_SetModuleName(OH_Rdb_ConfigV2 *config, const char *moduleName);

/**
 * @brief Set property isEncrypted into config
 *
 * @param config Represents a pointer to {@link OH_Rdb_ConfigV2} instance.
 * Indicates the configuration of the database related to this RDB store.
 * @param isEncrypted Indicates whether the database is encrypted.
 * @return Returns the status code of the execution. Successful execution returns RDB_OK,
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @since 14
 */
int OH_Rdb_SetEncrypted(OH_Rdb_ConfigV2 *config, bool isEncrypted);

/**
 * @brief Set property securityLevel into config
 *
 * @param config Represents a pointer to {@link OH_Rdb_ConfigV2} instance.
 * Indicates the configuration of the database related to this RDB store.
 * @param securityLevel Indicates the security level {@link OH_Rdb_SecurityLevel} of the database.
 * @return Returns the status code of the execution. Successful execution returns RDB_OK,
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @since 14
 */
int OH_Rdb_SetSecurityLevel(OH_Rdb_ConfigV2 *config, int securityLevel);

/**
 * @brief Set property area into config
 *
 * @param config Represents a pointer to {@link OH_Rdb_ConfigV2} instance.
 * Indicates the configuration of the database related to this RDB store
 * @param area Represents the security area of the database.
 * @return Returns the status code of the execution. Successful execution returns RDB_OK,
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @since 14
 */
int OH_Rdb_SetArea(OH_Rdb_ConfigV2 *config, int area);

/**
 * @brief Set whether the database enable the capabilities for semantic indexing processing.
 *
 * @param config Represents a pointer to {@link OH_Rdb_ConfigV2} instance.
 * Indicates the configuration of the database related to this RDB store.
 * @param enableSemanticIndex Indicates whether the database enable the capabilities for semantic indexing processing.
 * @return Returns the status code of the execution. Successful execution returns RDB_OK,
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @since 20
 */
int OH_Rdb_SetSemanticIndex(OH_Rdb_ConfigV2 *config, bool enableSemanticIndex);

/**
 * @brief Set property dbType into config
 * @param config Represents a pointer to {@link OH_Rdb_ConfigV2} instance.
 * @param dbType Indicates the dbType {@link Rdb_DBType} of the database
 * @return Returns the status code of the execution. Successful execution returns RDB_OK,
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 *     {@link RDB_E_NOT_SUPPORTED} - The error code for not support db types.
 * @since 14
 */
int OH_Rdb_SetDbType(OH_Rdb_ConfigV2 *config, int dbType);

/**
 * @brief Sets the customized directory relative to the database.
 *
 * @param config Represents a pointer to a configuration of the database related to this relation database store.
 * @param customDir Represents the customized relative to the database directory, the value cannot exceed 128 bytes.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 20
 */
int OH_Rdb_SetCustomDir(OH_Rdb_ConfigV2 *config, const char *customDir);

/**
 * @brief Sets the relation database store is read-only mode.
 *
 * @param config Represents a pointer to a configuration of the database related to this relation database store.
 * @param readOnly Represents whether the relation database store is read-only.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 20
 */
int OH_Rdb_SetReadOnly(OH_Rdb_ConfigV2 *config, bool readOnly);

/**
 * @brief Sets the dynamic libraries with capabilities such as Full-Text Search (FTS).
 *
 * @param config Represents a pointer to a configuration of the database related to this relation database store.
 * @param plugins Represents the dynamic libraries.
 * @param length the size of plugins that the maximum value is 16.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 20
 */
int OH_Rdb_SetPlugins(OH_Rdb_ConfigV2 *config, const char **plugins, int32_t length);

/**
 * @brief Sets the custom encryption parameters.
 *
 * @param config Represents a pointer to a configuration of the database related to this relation database store.
 * @param cryptoParam Represents the custom encryption parameters.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 20
 */
int OH_Rdb_SetCryptoParam(OH_Rdb_ConfigV2 *config, const OH_Rdb_CryptoParam *cryptoParam);

/**
 * @brief Check if a tokenizer is supported or not.
 *
 * @param tokenizer the tokenizer type of {@Link Rdb_Tokenizer}.
 * @param isSupported Pointer to the Boolean value obtained.
 * @return Returns the status code of the execution.
 *         {@link RDB_OK} indicates the operation is successful.
 *         {@link RDB_E_INVALID_ARGS} indicates invalid args are passed in.
 * @since 16
 */
int OH_Rdb_IsTokenizerSupported(Rdb_Tokenizer tokenizer, bool *isSupported);

/**
 * @brief Set property tokenizer into config
 * @param config Represents a pointer to {@link OH_Rdb_ConfigV2} instance.
 * @param tokenizer Indicates the tokenizer {@link Rdb_Tokenizer} of the database
 * @return Returns the status code of the execution. Successful execution returns RDB_OK,
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 *     {@link RDB_E_NOT_SUPPORTED} - The error code for not support tokenizer.
 * @since 16
 */
int OH_Rdb_SetTokenizer(OH_Rdb_ConfigV2 *config, Rdb_Tokenizer tokenizer);

/**
 * @brief Set property isPersistent into config
 *
 * @param config Represents a pointer to {@link OH_Rdb_ConfigV2} instance.
 * Indicates the configuration of the database related to this RDB store.
 * @param isPersistent Indicates whether the database need persistence.
 * @return Returns the status code of the execution. Successful execution returns RDB_OK,
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @since 18
 */
int OH_Rdb_SetPersistent(OH_Rdb_ConfigV2 *config, bool isPersistent);

/**
 * @brief Get support db type list
 * @param typeCount The output parameter, which is used to receive the length of the support db type array.
 * @return Return Rdb_DBType array contains supported db type, array length is number of support type
 * @since 14
 */
const int *OH_Rdb_GetSupportedDbType(int *typeCount);

/**
 * @brief Creates an {@link OH_VObject} instance.
 *
 * @return If the creation is successful, a pointer to the instance of the @link OH_VObject} structure is returned,
 * otherwise NULL is returned.
 * @see OH_VObject.
 * @since 10
 */
OH_VObject *OH_Rdb_CreateValueObject();

/**
 * @brief Creates an {@link OH_VBucket} object.
 *
 * @return If the creation is successful, a pointer to the instance of the @link OH_VBucket} structure is returned,
 * otherwise NULL is returned.
 * @see OH_VBucket.
 * @since 10
 */
OH_VBucket *OH_Rdb_CreateValuesBucket();

/**
 * @brief Creates an {@link OH_Predicates} instance.
 *
 * @param table Indicates the table name.
 * @return If the creation is successful, a pointer to the instance of the @link OH_Predicates} structure is returned.
 *         If the table name is nullptr, nullptr is returned.
 * @see OH_Predicates.
 * @since 10
 */
OH_Predicates *OH_Rdb_CreatePredicates(const char *table);

/**
 * @brief Obtains an RDB store.
 *
 * You can set parameters of the RDB store as required. In general,
 * this method is recommended to obtain a rdb store.
 *
 * @param config Represents a pointer to an {@link OH_Rdb_Config} instance.
 * Indicates the configuration of the database related to this RDB store.
 * @param errCode This parameter is the output parameter,
 * and the execution status of a function is written to this variable.
 * @return If the creation is successful, a pointer to the instance of the @link OH_Rdb_Store} structure is returned.
 *         If the Config is empty, config.size does not match, or errCode is empty.
 * Get database path failed.Get RDB Store fail. Nullptr is returned.
 * @see OH_Rdb_Config, OH_Rdb_Store.
 * @since 10
 */
OH_Rdb_Store *OH_Rdb_GetOrOpen(const OH_Rdb_Config *config, int *errCode);

/**
 * @brief Obtains an RDB store with OH_Rdb_ConfigV2.
 *
 * You can set parameters of the RDB store as required. In general,
 * this method is recommended to obtain a rdb store.
 *
 * @param config Represents a pointer to an {@link OH_Rdb_ConfigV2} instance.
 * Indicates the configuration of the database related to this RDB store.
 * @param errCode This parameter is the output parameter,
 * and the execution status of a function is written to this variable.
 * @return If the creation is successful, a pointer to the instance of the @link OH_Rdb_Store} structure is returned.
 *         If the Config is empty, config.size does not match, or errCode is empty.
 * Get database path failed.Get RDB Store fail. Nullptr is returned.
 * @see OH_Rdb_ConfigV2, OH_Rdb_Store.
 * @since 14
 */
OH_Rdb_Store *OH_Rdb_CreateOrOpen(const OH_Rdb_ConfigV2 *config, int *errCode);

/**
 * @brief Close the {@link OH_Rdb_Store} object and reclaim the memory occupied by the object.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @return Returns the status code of the execution. Successful execution returns RDB_OK,
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * while failure returns a specific error code. Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_Store, OH_Rdb_ErrCode.
 * @since 10
 */
int OH_Rdb_CloseStore(OH_Rdb_Store *store);

/**
 * @brief Deletes the database with a specified path.
 *
 * @param config Represents a pointer to an {@link OH_Rdb_Config} instance.
 * Indicates the configuration of the database related to this RDB store.
 * @return Returns the status code of the execution. Successful execution returns RDB_OK,
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * while failure returns a specific error code. Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_ErrCode.
 * @since 10
 */
int OH_Rdb_DeleteStore(const OH_Rdb_Config *config);

/**
 * @brief Deletes the database with a specified path.
 *
 * @param config Represents a pointer to an {@link OH_Rdb_ConfigV2} instance.
 * Indicates the configuration of the database related to this RDB store.
 * @return Returns the status code of the execution. Successful execution returns RDB_OK,
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * while failure returns a specific error code. Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_ErrCode.
 * @since 14
 */
int OH_Rdb_DeleteStoreV2(const OH_Rdb_ConfigV2 *config);

/**
 * @brief Inserts a row of data into the target table.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param table Indicates the target table.
 * @param valuesBucket Indicates the row of data {@link OH_VBucket} to be inserted into the table.
 * @return Returns the rowId if success, returns a specific error code.
 *     {@link RDB_ERR} - Indicates that the function execution exception.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_Store, OH_VBucket, OH_Rdb_ErrCode.
 * @since 10
 */
int OH_Rdb_Insert(OH_Rdb_Store *store, const char *table, OH_VBucket *valuesBucket);

/**
 * @brief Inserts a row of data into the target table and support conflict resolution.
 *
 * @param store Represents a pointer to an OH_Rdb_Store instance.
 * @param table Represents the target table.
 * @param row Represents the row data to be inserted into the table.
 * @param resolution Represents the resolution when conflict occurs.
 * @param rowId Represents the number of successful insertion.
 * @return Returns the status code of the execution.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_ERROR} database common error.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_ALREADY_CLOSED} database already closed.
 *         Returns {@link RDB_E_WAL_SIZE_OVER_LIMIT} the WAL file size over default limit.
 *         Returns {@link RDB_E_SQLITE_FULL} SQLite: The database is full.
 *         Returns {@link RDB_E_SQLITE_CORRUPT} database corrupted.
 *         Returns {@link RDB_E_SQLITE_PERM} SQLite: Access permission denied.
 *         Returns {@link RDB_E_SQLITE_BUSY} SQLite: The database file is locked.
 *         Returns {@link RDB_E_SQLITE_LOCKED} SQLite: A table in the database is locked.
 *         Returns {@link RDB_E_SQLITE_NOMEM} SQLite: The database is out of memory.
 *         Returns {@link RDB_E_SQLITE_READONLY} SQLite: Attempt to write a readonly database.
 *         Returns {@link RDB_E_SQLITE_IOERR} SQLite: Some kind of disk I/O error occurred.
 *         Returns {@link RDB_E_SQLITE_TOO_BIG} SQLite: TEXT or BLOB exceeds size limit.
 *         Returns {@link RDB_E_SQLITE_MISMATCH} SQLite: Data type mismatch.
 *         Returns {@link RDB_E_SQLITE_CONSTRAINT} SQLite: Abort due to constraint violation.
 * @since 20
 */
int OH_Rdb_InsertWithConflictResolution(OH_Rdb_Store *store, const char *table, OH_VBucket *row,
    Rdb_ConflictResolution resolution, int64_t *rowId);

/**
 * @brief Inserts a batch of data into the target table.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param table Represents the target table.
 * @param rows Represents the rows data to be inserted into the table.
 * @param resolution Represents the resolution when conflict occurs.
 * @param changes Represents the number of successful insertions.
 * @return Returns the status code of the execution.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_ERROR} database common error.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_ALREADY_CLOSED} database already closed.
 *         Returns {@link RDB_E_WAL_SIZE_OVER_LIMIT} the WAL file size over default limit.
 *         Returns {@link RDB_E_SQLITE_FULL} SQLite: The database is full.
 *         Returns {@link RDB_E_SQLITE_CORRUPT} database corrupted.
 *         Returns {@link RDB_E_SQLITE_PERM} SQLite: Access permission denied.
 *         Returns {@link RDB_E_SQLITE_BUSY} SQLite: The database file is locked.
 *         Returns {@link RDB_E_SQLITE_LOCKED} SQLite: A table in the database is locked.
 *         Returns {@link RDB_E_SQLITE_NOMEM} SQLite: The database is out of memory.
 *         Returns {@link RDB_E_SQLITE_READONLY} SQLite: Attempt to write a readonly database.
 *         Returns {@link RDB_E_SQLITE_IOERR} SQLite: Some kind of disk I/O error occurred.
 *         Returns {@link RDB_E_SQLITE_TOO_BIG} SQLite: TEXT or BLOB exceeds size limit.
 *         Returns {@link RDB_E_SQLITE_MISMATCH} SQLite: Data type mismatch.
 *         Returns {@link RDB_E_SQLITE_CONSTRAINT} SQLite: Abort due to constraint violation.
 * @since 16
 */
int OH_Rdb_BatchInsert(OH_Rdb_Store *store, const char *table,
    const OH_Data_VBuckets *rows, Rdb_ConflictResolution resolution, int64_t *changes);

/**
 * @brief Updates data in the database based on specified conditions.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param valuesBucket Indicates the row of data {@link OH__VBucket} to be updated in the database
 * @param predicates Represents a pointer to an {@link OH_Predicates} instance.
 * Indicates the specified update condition.
 * @return Returns the number of rows changed if success, otherwise, returns a specific error code.
 *     {@link RDB_ERR} - Indicates that the function execution exception.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_Store, OH_Bucket, OH_Predicates, OH_Rdb_ErrCode.
 * @since 10
 */
int OH_Rdb_Update(OH_Rdb_Store *store, OH_VBucket *valuesBucket, OH_Predicates *predicates);
/**
 * @brief Updates data in the database based on specified conditions and support conflict resolution.
 *
 * @param store Represents a pointer to an OH_Rdb_Store instance.
 * @param row Represents the row data to be inserted into the table.
 * @param predicates Represents  a pointer to an link OH_Predicates instance.
 * @param resolution Represents the resolution when conflict occurs.
 * @param changes Represents the number of successful update.
 * @return Returns the status code of the execution.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_ERROR} database common error.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_ALREADY_CLOSED} database already closed.
 *         Returns {@link RDB_E_WAL_SIZE_OVER_LIMIT} the WAL file size over default limit.
 *         Returns {@link RDB_E_SQLITE_FULL} SQLite: The database is full.
 *         Returns {@link RDB_E_SQLITE_CORRUPT} database corrupted.
 *         Returns {@link RDB_E_SQLITE_PERM} SQLite: Access permission denied.
 *         Returns {@link RDB_E_SQLITE_BUSY} SQLite: The database file is locked.
 *         Returns {@link RDB_E_SQLITE_LOCKED} SQLite: A table in the database is locked.
 *         Returns {@link RDB_E_SQLITE_NOMEM} SQLite: The database is out of memory.
 *         Returns {@link RDB_E_SQLITE_READONLY} SQLite: Attempt to write a readonly database.
 *         Returns {@link RDB_E_SQLITE_IOERR} SQLite: Some kind of disk I/O error occurred.
 *         Returns {@link RDB_E_SQLITE_TOO_BIG} SQLite: TEXT or BLOB exceeds size limit.
 *         Returns {@link RDB_E_SQLITE_MISMATCH} SQLite: Data type mismatch.
 *         Returns {@link RDB_E_SQLITE_CONSTRAINT} SQLite: Abort due to constraint violation.
 * @since 20
 */
int OH_Rdb_UpdateWithConflictResolution(OH_Rdb_Store *store, OH_VBucket *row, OH_Predicates *predicates,
    Rdb_ConflictResolution resolution, int64_t *changes);

/**
 * @brief Deletes data from the database based on specified conditions.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param predicates Represents a pointer to an {@link OH_Predicates} instance.
 * Indicates the specified delete condition.
 * @return Returns the number of rows changed if success, otherwise, returns a specific error code.
 *     {@link RDB_ERR} - Indicates that the function execution exception.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_Store, OH_Predicates, OH_Rdb_ErrCode.
 * @since 10
 */
int OH_Rdb_Delete(OH_Rdb_Store *store, OH_Predicates *predicates);

/**
 * @brief Queries data in the database based on specified conditions.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param predicates Represents a pointer to an {@link OH_Predicates} instance.
 * Indicates the specified query condition.
 * @param columnNames Indicates the columns to query. If the value is empty array, the query applies to all columns.
 * @param length Indicates the length of columnNames.
 * @return If the query is successful, a pointer to the instance of the @link OH_Cursor} structure is returned.
 *         If Get store failed or resultSet is nullptr, nullptr is returned.
 * @see OH_Rdb_Store, OH_Predicates, OH_Cursor.
 * @since 10
 */
OH_Cursor *OH_Rdb_Query(OH_Rdb_Store *store, OH_Predicates *predicates, const char *const *columnNames, int length);

/**
 * @brief Executes an SQL statement.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param sql Indicates the SQL statement to execute.
 * @return Returns the status code of the execution.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @see OH_Rdb_Store.
 * @since 10
 */
int OH_Rdb_Execute(OH_Rdb_Store *store, const char *sql);

/**
 * @brief Write operations are performed using the specified transaction represented by the transaction ID
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param trxId The transaction ID of the specified transaction, must be greater than 0
 * @param sql Indicates the SQL statement to execute.
 * @return Returns the status code of the execution.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 *     {@link RDB_E_NOT_SUPPORTED} - The error code for not support.
 * @see OH_Rdb_Store.
 * @since 14
 */
int OH_Rdb_ExecuteByTrxId(OH_Rdb_Store *store, int64_t trxId, const char *sql);

/**
 * @brief Queries data in the database based on an SQL statement.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param sql Indicates the SQL statement to execute.
 * @return If the query is successful, a pointer to the instance of the @link OH_Cursor} structure is returned.
 *         If Get store failed,sql is nullptr or resultSet is nullptr, nullptr is returned.
 * @see OH_Rdb_Store.
 * @since 10
 */
OH_Cursor *OH_Rdb_ExecuteQuery(OH_Rdb_Store *store, const char *sql);

/**
 * @brief Begins a transaction in EXCLUSIVE mode.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @return Returns the status code of the execution.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @see OH_Rdb_Store.
 * @since 10
 */
int OH_Rdb_BeginTransaction(OH_Rdb_Store *store);

/**
 * @brief Rolls back a transaction in EXCLUSIVE mode.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @return Returns the status code of the execution.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @see OH_Rdb_Store.
 * @since 10
 */
int OH_Rdb_RollBack(OH_Rdb_Store *store);

/**
 * @brief Commits a transaction in EXCLUSIVE mode.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @return Returns the status code of the execution.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @see OH_Rdb_Store.
 * @since 10
 */
int OH_Rdb_Commit(OH_Rdb_Store *store);

/**
 * @brief Begin a transaction and the transaction ID corresponding to the transaction.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param trxId The output parameter, which is used to receive the transaction ID corresponding to the transaction
 * @return Returns the status code of the execution.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 *     {@link RDB_E_NOT_SUPPORTED} - The error code for not support.
 * @see OH_Rdb_Store.
 * @since 14
 */
int OH_Rdb_BeginTransWithTrxId(OH_Rdb_Store *store, int64_t *trxId);

/**
 * @brief Roll back a transaction that is represented by a specified transaction ID
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param trxId The transaction ID of the specified transaction, must be greater than 0
 * @return Returns the status code of the execution.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 *     {@link RDB_E_NOT_SUPPORTED} - The error code for not support.
 * @see OH_Rdb_Store.
 * @since 14
 */
int OH_Rdb_RollBackByTrxId(OH_Rdb_Store *store, int64_t trxId);

/**
 * @brief Commit a transaction that is represented by a specified transaction ID
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param trxId The transaction ID of the specified transaction, must be greater than 0
 * @return Returns the status code of the execution.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 *     {@link RDB_E_NOT_SUPPORTED} - The error code for not support.
 * @see OH_Rdb_Store.
 * @since 14
 */
int OH_Rdb_CommitByTrxId(OH_Rdb_Store *store, int64_t trxId);

/**
 * @brief Backs up a database on specified path.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param databasePath Indicates the database file path.
 * @return Returns the status code of the execution.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @see OH_Rdb_Store.
 * @since 10
 */
int OH_Rdb_Backup(OH_Rdb_Store *store, const char *databasePath);

/**
 * @brief Restores a database from a specified database file.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param databasePath Indicates the database file path.
 * @return Returns the status code of the execution.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @see OH_Rdb_Store.
 * @since 10
 */
int OH_Rdb_Restore(OH_Rdb_Store *store, const char *databasePath);

/**
 * @brief Gets the version of a database.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param version Indicates the version number.
 * @return Returns the status code of the execution.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @see OH_Rdb_Store.
 * @since 10
 */
int OH_Rdb_GetVersion(OH_Rdb_Store *store, int *version);

/**
 * @brief Sets the version of a database.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param version Indicates the version number.
 * @return Returns the status code of the execution.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @see OH_Rdb_Store.
 * @since 10
 */
int OH_Rdb_SetVersion(OH_Rdb_Store *store, int version);

/**
 * @brief Describes the distribution type of the tables.
 *
 * @since 11
 */
typedef enum Rdb_DistributedType {
    /**
     * @brief Indicates the table is distributed among the devices.
     */
    RDB_DISTRIBUTED_CLOUD
} Rdb_DistributedType;

/**
 * @brief Indicates version of {@link Rdb_DistributedConfig}
 *
 * @since 11
 */
#define DISTRIBUTED_CONFIG_VERSION 1
/**
 * @brief Manages the distributed configuration of the table.
 *
 * @since 11
 */
typedef struct Rdb_DistributedConfig {
    /**
     * The version used to uniquely identify the Rdb_DistributedConfig struct.
     */
    int version;
    /**
     * Specifies whether the table auto syncs.
     */
    bool isAutoSync;
} Rdb_DistributedConfig;

/**
 * @brief Set table to be distributed table.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param tables Indicates the table names you want to set.
 * @param count Indicates the count of tables you want to set.
 * @param type Indicates the distributed type {@link Rdb_DistributedType}.
 * @param config Indicates the distributed config of the tables. For details, see {@link Rdb_DistributedConfig}.
 * @return Returns the status code of the execution. See {@link OH_Rdb_ErrCode}.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @see OH_Rdb_Store.
 * @see Rdb_DistributedConfig.
 * @since 11
 */
int OH_Rdb_SetDistributedTables(OH_Rdb_Store *store, const char *tables[], uint32_t count, Rdb_DistributedType type,
    const Rdb_DistributedConfig *config);

/**
 * @brief Set table to be distributed table.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param tableName Indicates the name of the table to check.
 * @param columnName Indicates the name of the column corresponding to the primary key.
 * If the table has no primary key , please pass in "rowid".
 * @param values Indicates the primary keys of the rows to check.
 * If the table has no primary key , please pass in the row-ids of the rows to check.
 * @return If the operation is successful, a pointer to the instance of the @link OH_Cursor} structure is returned.
 *         If Get store failed, nullptr is returned.
 * There are two columns, "data_key" and "timestamp". Otherwise NULL is returned.
 * @see OH_Rdb_Store.
 * @see OH_VObject.
 * @see OH_Cursor.
 * @since 11
 */
OH_Cursor *OH_Rdb_FindModifyTime(
    OH_Rdb_Store *store, const char *tableName, const char *columnName, OH_VObject *values);

/**
 * @brief Describes the change type.
 *
 * @since 11
 */
typedef enum Rdb_ChangeType {
    /**
     * @brief Means the change type is data change.
     */
    RDB_DATA_CHANGE,
    /**
     * @brief Means the change type is asset change.
     */
    RDB_ASSET_CHANGE
} Rdb_ChangeType;

/**
 * @brief Describes the primary keys or row-ids of changed rows.
 *
 * @since 11
 */
typedef struct Rdb_KeyInfo {
    /**
     * Indicates the count of the primary keys or row-ids.
     */
    int count;

    /**
     * Indicates data type {@link OH_ColumnType} of the key.
     */
    int type;

    /**
     * Indicates the data of the key info.
     */
    union Rdb_KeyData {
        /**
         * Indicates uint64_t type of the data.
         */
        uint64_t integer;

        /**
         * Indicates double type of the data.
         */
        double real;

        /**
         * Indicates const char * type of the data.
         */
        const char *text;
    } *data;
} Rdb_KeyInfo;

/**
 * @brief Indicates version of {@link Rdb_ChangeInfo}
 *
 * @since 11
 */
#define DISTRIBUTED_CHANGE_INFO_VERSION 1

/**
 * @brief Describes the notify info of data change.
 *
 * @since 11
 */
typedef struct Rdb_ChangeInfo {
    /**
     * The version used to uniquely identify the Rdb_ChangeInfo struct.
     */
    int version;

    /**
     * The name of changed table.
     */
    const char *tableName;

    /**
     * The {@link Rdb_ChangeType} of changed table.
     */
    int ChangeType;

    /**
     * The {@link Rdb_KeyInfo} of inserted rows.
     */
    Rdb_KeyInfo inserted;

    /**
     * The {@link Rdb_KeyInfo} of updated rows.
     */
    Rdb_KeyInfo updated;

    /**
     * The {@link Rdb_KeyInfo} of deleted rows.
     */
    Rdb_KeyInfo deleted;
} Rdb_ChangeInfo;

/**
 * @brief Indicates the subscribe type.
 *
 * @since 11
 */
typedef enum Rdb_SubscribeType {
    /**
     * @brief Subscription to cloud data changes.
     */
    RDB_SUBSCRIBE_TYPE_CLOUD,

    /**
     * @brief Subscription to cloud data change details.
     */
    RDB_SUBSCRIBE_TYPE_CLOUD_DETAILS,

    /**
     * @brief Subscription to local data change details.
     * @since 12
     */
    RDB_SUBSCRIBE_TYPE_LOCAL_DETAILS,
} Rdb_SubscribeType;

/**
 * @brief The callback function of cloud data change event.
 *
 * @param context Represents the context of data observer.
 * @param values Indicates the cloud accounts that changed.
 * @param count The count of changed cloud accounts.
 * @see OH_VObject.
 * @since 11
 */
typedef void (*Rdb_BriefObserver)(void *context, const char *values[], uint32_t count);

/**
 * @brief The callback function of cloud data change details event.
 *
 * @param context Represents the context of data observer.
 * @param changeInfo Indicates the {@link Rdb_ChangeInfo} of changed tables.
 * @param count The count of changed tables.
 * @see Rdb_ChangeInfo.
 * @since 11
 */
typedef void (*Rdb_DetailsObserver)(void *context, const Rdb_ChangeInfo **changeInfo, uint32_t count);

/**
 * @brief The callback function of database corruption handle.
 *
 * @param context Represents the context corruption handler.
 * @param config Represents a pointer to an OH_Rdb_ConfigV2 configuration of the database related to this RDB store.
 * @param store Represents a pointer to an OH_Rdb_Store instance.
 * @since 22
 */
typedef void (*Rdb_CorruptedHandler)(void *context, OH_Rdb_ConfigV2 *config, OH_Rdb_Store *store);

/**
 * @brief Registers corrupted handler for the database.
 *
 * @param config Represents a pointer to an OH_Rdb_ConfigV2 configuration of the database related to this RDB store.
 * @param context Represents the context corruption handle.
 * @param handler The callback function of database corruption handle.
 * @return Returns a specific error code.
 *     {@link RDB_OK} if the execution is successful.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 *     {@link RDB_E_SUB_OVER_LIMIT} - Indicates the number of subscriptions exceeds the limit.
 * Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_RegisterCorruptedHandler.
 * @since 22
 */
int OH_Rdb_RegisterCorruptedHandler(const OH_Rdb_ConfigV2 *config, void *context, const Rdb_CorruptedHandler handler);

/**
 * @brief Unregisters corrupted handler for the database.
 *
 * @param config Represents a pointer to an OH_Rdb_ConfigV2 configuration of the database related to this RDB store.
 * @param context Represents the context corruption handle.
 * @param handler The callback function of database corruption handle.
 * @return Returns a specific error code.
 *     {@link RDB_OK} if the execution is successful.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_UnregisterCorruptedHandler.
 * @since 22
 */
int OH_Rdb_UnregisterCorruptedHandler(const OH_Rdb_ConfigV2 *config, void *context, const Rdb_CorruptedHandler handler);

/**
 * @brief Indicates the callback functions.
 *
 * @since 11
 */
typedef union Rdb_SubscribeCallback {
    /**
     * The callback function of cloud data change details event.
     */
    Rdb_DetailsObserver detailsObserver;

    /**
     * The callback function of cloud data change event.
     */
    Rdb_BriefObserver briefObserver;
} Rdb_SubscribeCallback;

/**
 * @brief Indicates the observer of data.
 *
 * @since 11
 */
typedef struct Rdb_DataObserver {
    /**
     * The context of data observer.
     */
    void *context;

    /**
     * The callback of data observer.
     */
    Rdb_SubscribeCallback callback;
} Rdb_DataObserver;

/**
 * @brief Registers an observer for the database.
 * When data in the distributed database changes, the callback will be invoked.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param type Indicates the subscription type, which is defined in {@link Rdb_SubscribeType}.
 * @param observer The {@link Rdb_DataObserver} of change events in the database.
 * @return Returns the status code of the execution. See {@link OH_Rdb_ErrCode}.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @see OH_Rdb_Store.
 * @see Rdb_DataObserver.
 * @since 11
 */
int OH_Rdb_Subscribe(OH_Rdb_Store *store, Rdb_SubscribeType type, const Rdb_DataObserver *observer);

/**
 * @brief Remove specified observer of specified type from the database.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param type Indicates the subscription type, which is defined in {@link Rdb_SubscribeType}.
 * @param observer The {@link Rdb_DataObserver} of change events in the database.
 * If this is nullptr, remove all observers of the type.
 * @return Returns the status code of the execution. See {@link OH_Rdb_ErrCode}.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @see OH_Rdb_Store.
 * @see Rdb_DataObserver.
 * @since 11
 */
int OH_Rdb_Unsubscribe(OH_Rdb_Store *store, Rdb_SubscribeType type, const Rdb_DataObserver *observer);

/**
 * @brief Indicates the database synchronization mode.
 *
 * @since 11
 */
typedef enum Rdb_SyncMode {
    /**
     * @brief Indicates that data is synchronized from the end with the closest modification time
     * to the end with a more distant modification time.
     */
    RDB_SYNC_MODE_TIME_FIRST,
    /**
     * @brief Indicates that data is synchronized from local to cloud.
     */
    RDB_SYNC_MODE_NATIVE_FIRST,
    /**
     * @brief Indicates that data is synchronized from cloud to local.
     */
    RDB_SYNC_MODE_CLOUD_FIRST
} Rdb_SyncMode;

/**
 * @brief Describes the statistic of the cloud sync process.
 *
 * @since 11
 */
typedef struct Rdb_Statistic {
    /**
     * Describes the total number of data to sync.
     */
    int total;

    /**
     * Describes the number of successfully synced data.
     */
    int successful;

    /**
     * Describes the number of data failed to sync.
     */
    int failed;

    /**
     * Describes the number of data remained to sync.
     */
    int remained;
} Rdb_Statistic;

/**
 * @brief Describes the {@link Rdb_Statistic} details of the table.
 *
 * @since 11
 */
typedef struct Rdb_TableDetails {
    /**
     * Indicates the name of changed table.
     */
    const char *table;

    /**
     * Describes the {@link Rdb_Statistic} details of the upload process.
     */
    Rdb_Statistic upload;

    /**
     * Describes the {@link Rdb_Statistic} details of the download process.
     */
    Rdb_Statistic download;
} Rdb_TableDetails;

/**
 * The cloud sync progress
 *
 * @since 11
 */
typedef enum Rdb_Progress {
    /**
     * @brief Means the sync process begin.
     */
    RDB_SYNC_BEGIN,

    /**
     * @brief Means the sync process is in progress
     */
    RDB_SYNC_IN_PROGRESS,

    /**
     * @brief Means the sync process is finished
     */
    RDB_SYNC_FINISH
} Rdb_Progress;

/**
   * Describes the status of cloud sync progress.
   *
   * @since 11
   */
typedef enum Rdb_ProgressCode {
    /**
     * @brief Means the status of progress is success.
     */
    RDB_SUCCESS,

    /**
     * @brief Means the progress meets unknown error.
     */
    RDB_UNKNOWN_ERROR,

    /**
     * @brief Means the progress meets network error.
     */
    RDB_NETWORK_ERROR,

    /**
     * @brief Means cloud is disabled.
     */
    RDB_CLOUD_DISABLED,

    /**
     * @brief Means the progress is locked by others.
     */
    RDB_LOCKED_BY_OTHERS,

    /**
     * @brief Means the record exceeds the limit.
     */
    RDB_RECORD_LIMIT_EXCEEDED,

    /**
     * Means the cloud has no space for the asset.
     */
    RDB_NO_SPACE_FOR_ASSET
} Rdb_ProgressCode;

/**
 * @brief Indicates version of {@link Rdb_ProgressDetails}
 *
 * @since 11
 */
#define DISTRIBUTED_PROGRESS_DETAIL_VERSION 1

/**
 * @brief Describes detail of the cloud sync progress.
 *
 * @since 11
 */
typedef struct Rdb_ProgressDetails {
    /**
     * The version used to uniquely identify the Rdb_ProgressDetails struct.
     */
    int version;

    /**
     * Describes the status of data sync progress. Defined in {@link Rdb_Progress}.
     */
    int schedule;

    /**
     * Describes the code of data sync progress. Defined in {@link Rdb_ProgressCode}.
     */
    int code;

    /**
     * Describes the length of changed tables in data sync progress.
     */
    int32_t tableLength;
} Rdb_ProgressDetails;

/**
 * @brief Get table details from progress details.
 *
 * @param progress Represents a pointer to an {@link Rdb_ProgressDetails} instance.
 * @param version Indicates the version of current {@link Rdb_ProgressDetails}.
 * @return If the operation is successful, a pointer to the instance of the {@link Rdb_TableDetails}
 * structure is returned.If get details is failed, nullptr is returned.
 * @see Rdb_ProgressDetails
 * @see Rdb_TableDetails
 * @since 11
 */
Rdb_TableDetails *OH_Rdb_GetTableDetails(Rdb_ProgressDetails *progress, int32_t version);

/**
 * @brief The callback function of progress.
 *
 * @param progressDetails The details of the sync progress.
 * @see Rdb_ProgressDetails.
 * @since 11
 */
typedef void (*Rdb_ProgressCallback)(void *context, Rdb_ProgressDetails *progressDetails);

/**
 * @brief The callback function of sync.
 *
 * @param progressDetails The details of the sync progress.
 * @see Rdb_ProgressDetails.
 * @since 11
 */
typedef void (*Rdb_SyncCallback)(Rdb_ProgressDetails *progressDetails);

/**
 * @brief The observer of progress.
 *
 * @since 11
 */
typedef struct Rdb_ProgressObserver {
    /**
     * The context of progress observer.
     */
    void *context;

    /**
     * The callback function of progress observer.
     */
    Rdb_ProgressCallback callback;
} Rdb_ProgressObserver;

/**
 * @brief Sync data to cloud.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param mode Represents the {@link Rdb_SyncMode} of sync progress.
 * @param tables Indicates the names of tables to sync.
 * @param count The count of tables to sync. If value equals 0, sync all tables of the store.
 * @param observer The {@link Rdb_ProgressObserver} of cloud sync progress.
 * @return Returns the status code of the execution. See {@link OH_Rdb_ErrCode}.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @see OH_Rdb_Store.
 * @see Rdb_ProgressObserver.
 * @since 11
 */
int OH_Rdb_CloudSync(OH_Rdb_Store *store, Rdb_SyncMode mode, const char *tables[], uint32_t count,
    const Rdb_ProgressObserver *observer);

/**
* @brief Subscribes to the automatic synchronization progress of an RDB store.
* A callback will be invoked when there is a notification of the automatic synchronization progress.
*
* @param store Indicates the pointer to the target {@Link OH_Rdb_Store} instance.
* @param observer The {@link Rdb_SyncObserver} for the automatic synchronization progress
* Indicates the callback invoked to return the automatic synchronization progress.
* @return Returns the status code of the execution. See {@link OH_Rdb_ErrCode}.
*     {@link RDB_OK} - success.
*     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
* @see OH_Rdb_Store.
* @see Rdb_ProgressObserver.
* @since 11
*/
int OH_Rdb_SubscribeAutoSyncProgress(OH_Rdb_Store *store, const Rdb_ProgressObserver *observer);

/**
* @brief Unsubscribes from the automatic synchronization progress of an RDB store.
*
* @param store Indicates the pointer to the target {@Link OH_Rdb_Store} instance.
* @param observer Indicates the {@link Rdb_SyncObserver} callback for the automatic synchronization progress.
* If it is a null pointer, all callbacks for the automatic synchronization progress will be unregistered.
* @return Returns the status code of the execution. See {@link OH_Rdb_ErrCode}.
*     {@link RDB_OK} - success.
*     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
* @see OH_Rdb_Store.
* @see Rdb_ProgressObserver.
* @since 11
*/
int OH_Rdb_UnsubscribeAutoSyncProgress(OH_Rdb_Store *store, const Rdb_ProgressObserver *observer);

/**
 * @brief Lock data from the database based on specified conditions.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param predicates Represents a pointer to an {@link OH_Predicates} instance.
 * Indicates the specified lock condition.
 * @return Returns the status code of the execution. See {@link OH_Rdb_ErrCode}.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @see OH_Rdb_Store, OH_Predicates, OH_Rdb_ErrCode.
 * @since 12
 */
int OH_Rdb_LockRow(OH_Rdb_Store *store, OH_Predicates *predicates);

/**
 * @brief Unlock data from the database based on specified conditions.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param predicates Represents a pointer to an {@link OH_Predicates} instance.
 * Indicates the specified unlock condition.
 * @return Returns the status code of the execution. See {@link OH_Rdb_ErrCode}.
 *     {@link RDB_OK} - success.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 * @see OH_Rdb_Store, OH_Predicates, OH_Rdb_ErrCode.
 * @since 12
 */
int OH_Rdb_UnlockRow(OH_Rdb_Store *store, OH_Predicates *predicates);

/**
 * @brief Queries locked data in the database based on specified conditions.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param predicates Represents a pointer to an {@link OH_Predicates} instance.
 * Indicates the specified query condition.
 * @param columnNames Indicates the columns to query. If the value is empty array, the query applies to all columns.
 * @param length Indicates the length of columnNames.
 * @return If the query is successful, a pointer to the instance of the @link OH_Cursor} structure is returned.
 *         If Get store failed or resultSet is nullptr, nullptr is returned.
 * @see OH_Rdb_Store, OH_Predicates, OH_Cursor.
 * @since 12
 */
OH_Cursor *OH_Rdb_QueryLockedRow(
    OH_Rdb_Store *store, OH_Predicates *predicates, const char *const *columnNames, int length);

/**
 * @brief Creates an OH_Rdb_Transaction instance object.
 *
 * @param store Represents a pointer to an instance of OH_Rdb_Store.
 * @param options Represents a pointer to an instance of OH_RDB_TransOptions.
 * @param trans Represents a pointer to OH_Rdb_Transaction instance when the execution is successful.
 * Otherwise, nullptr is returned. The memory must be released through the OH_RdbTrans_Destroy
 * interface after the use is complete.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_ERROR} database common error.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_ALREADY_CLOSED} database already closed.
 *         Returns {@link RDB_E_DATABASE_BUSY} database does not respond.
 *         Returns {@link RDB_E_SQLITE_FULL} SQLite: The database is full.
 *         Returns {@link RDB_E_SQLITE_CORRUPT} database corrupted.
 *         Returns {@link RDB_E_SQLITE_PERM} SQLite: Access permission denied.
 *         Returns {@link RDB_E_SQLITE_BUSY} SQLite: The database file is locked.
 *         Returns {@link RDB_E_SQLITE_NOMEM} SQLite: The database is out of memory.
 *         Returns {@link RDB_E_SQLITE_IOERR} SQLite: Some kind of disk I/O error occurred.
 *         Returns {@link RDB_E_SQLITE_CANT_OPEN} SQLite: Unable to open the database file.
 * @see OH_RdbTrans_Destroy.
 * @since 16
 */
int OH_Rdb_CreateTransaction(OH_Rdb_Store *store, const OH_RDB_TransOptions *options, OH_Rdb_Transaction **trans);

/**
 * @brief Executes an SQL statement.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param sql Indicates the SQL statement to execute.
 * @param args Represents the values of the parameters in the SQL statement.
 * @param result Represents a pointer to OH_Data_Value instance when the execution is successful.
 * The memory must be released through the OH_Value_Destroy interface after the use is complete.
 * @return Returns the status code of the execution.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_ERROR} database common error.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_ALREADY_CLOSED} database already closed.
 *         Returns {@link RDB_E_WAL_SIZE_OVER_LIMIT} the WAL file size over default limit.
 *         Returns {@link RDB_E_SQLITE_FULL} SQLite: The database is full.
 *         Returns {@link RDB_E_SQLITE_CORRUPT} database corrupted.
 *         Returns {@link RDB_E_SQLITE_PERM} SQLite: Access permission denied.
 *         Returns {@link RDB_E_SQLITE_BUSY} SQLite: The database file is locked.
 *         Returns {@link RDB_E_SQLITE_LOCKED} SQLite: A table in the database is locked.
 *         Returns {@link RDB_E_SQLITE_NOMEM} SQLite: The database is out of memory.
 *         Returns {@link RDB_E_SQLITE_READONLY} SQLite: Attempt to write a readonly database.
 *         Returns {@link RDB_E_SQLITE_IOERR} SQLite: Some kind of disk I/O error occurred.
 *         Returns {@link RDB_E_SQLITE_TOO_BIG} SQLite: TEXT or BLOB exceeds size limit.
 *         Returns {@link RDB_E_SQLITE_MISMATCH} SQLite: Data type mismatch.
 * @see OH_Value_Destroy.
 * @since 16
 */
int OH_Rdb_ExecuteV2(OH_Rdb_Store *store, const char *sql, const OH_Data_Values *args, OH_Data_Value **result);

/**
 * @brief Queries data in the database based on an SQL statement.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param sql Indicates the SQL statement to execute.
 * @param args Represents a pointer to an instance of OH_Data_Values and  it is the selection arguments.
 * @return If the query is successful, a pointer to the instance of the @link OH_Cursor} structure is returned.
 *         If sql statement is invalid or the memory allocate failed, nullptr is returned.
 * @see OH_Rdb_Store.
 * @since 16
 */
OH_Cursor *OH_Rdb_ExecuteQueryV2(OH_Rdb_Store *store, const char *sql, const OH_Data_Values *args);

/**
 * @brief Attaches a database file to the currently linked database.
 *
 * @param store Represents a pointer to an OH_Rdb_Store instance.
 * @param config Represents a pointer to an OH_Rdb_ConfigV2 configuration of the database related to this RDB store.
 * @param attachName Represents the alias of the database.
 * @param waitTime Represents the maximum time allowed for attaching the database, valid range is 1 to 300.
 * @param attachedNumber Represents the number of attached databases, It is an output parameter.
 * @return Returns the status code of the execution.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_ERROR} database common error.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_ALREADY_CLOSED} database already closed.
 *         Returns {@link RDB_E_NOT_SUPPORTED} - The error code for not support.
 *         Returns {@link RDB_E_DATABASE_BUSY} database does not respond.
 *         Returns {@link RDB_E_SQLITE_FULL} SQLite: The database is full.
 *         Returns {@link RDB_E_SQLITE_CORRUPT} database corrupted.
 *         Returns {@link RDB_E_SQLITE_PERM} SQLite: Access permission denied.
 *         Returns {@link RDB_E_SQLITE_BUSY} SQLite: The database file is locked.
 *         Returns {@link RDB_E_SQLITE_LOCKED} SQLite: A table in the database is locked.
 *         Returns {@link RDB_E_SQLITE_NOMEM} SQLite: The database is out of memory.
 *         Returns {@link RDB_E_SQLITE_READONLY} SQLite: Attempt to write a readonly database.
 *         Returns {@link RDB_E_SQLITE_IOERR} SQLite: Some kind of disk I/O error occurred.
 *         Returns {@link RDB_E_SQLITE_TOO_BIG} SQLite: TEXT or BLOB exceeds size limit.
 *         Returns {@link RDB_E_SQLITE_MISMATCH} SQLite: Data type mismatch.
 *         Returns {@link RDB_E_SQLITE_CONSTRAINT} SQLite: Abort due to constraint violation.
 * @since 20
 */
int OH_Rdb_Attach(OH_Rdb_Store *store, const OH_Rdb_ConfigV2 *config, const char *attachName, int64_t waitTime,
    size_t *attachedNumber);

/**
 * @brief Detaches a database from this database.
 *
 * @param store Represents a pointer to an OH_Rdb_Store instance.
 * @param attachName Represents the alias of the database.
 * @param waitTime Represents the maximum time allowed for detaching the database, valid range is 1 to 300.
 * @param attachedNumber Represents the number of attached databases, It is an output parameter.
 * @return Returns the status code of the execution.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_ERROR} database common error.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_ALREADY_CLOSED} database already closed.
 *         Returns {@link RDB_E_NOT_SUPPORTED} - The error code for not support.
 *         Returns {@link RDB_E_DATABASE_BUSY} database does not respond.
 *         Returns {@link RDB_E_SQLITE_FULL} SQLite: The database is full.
 *         Returns {@link RDB_E_SQLITE_CORRUPT} database corrupted.
 *         Returns {@link RDB_E_SQLITE_PERM} SQLite: Access permission denied.
 *         Returns {@link RDB_E_SQLITE_BUSY} SQLite: The database file is locked.
 *         Returns {@link RDB_E_SQLITE_LOCKED} SQLite: A table in the database is locked.
 *         Returns {@link RDB_E_SQLITE_NOMEM} SQLite: The database is out of memory.
 *         Returns {@link RDB_E_SQLITE_READONLY} SQLite: Attempt to write a readonly database.
 *         Returns {@link RDB_E_SQLITE_IOERR} SQLite: Some kind of disk I/O error occurred.
 *         Returns {@link RDB_E_SQLITE_TOO_BIG} SQLite: TEXT or BLOB exceeds size limit.
 *         Returns {@link RDB_E_SQLITE_MISMATCH} SQLite: Data type mismatch.
 *         Returns {@link RDB_E_SQLITE_CONSTRAINT} SQLite: Abort due to constraint violation.
 * @see OH_Rdb_Store, OH_Rdb_ErrCode.
 * @since 20
 */
int OH_Rdb_Detach(OH_Rdb_Store *store, const char *attachName, int64_t waitTime, size_t *attachedNumber);

/**
 * @brief Support for collations in different languages.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param locale Language related to the locale, for example, zh. The value complies with the ISO 639 standard.
 * @return Returns a specific error code.
 *     {@link RDB_OK} if the execution is successful.
 *     {@link RDB_ERR} - Indicates that the function execution exception.
 *     {@link RDB_E_INVALID_ARGS} - The error code for common invalid args.
 *     {@link RDB_E_ALREADY_CLOSED} database already closed.
 *     {@link RDB_E_SQLITE_BUSY} SQLite: The database file is locked.
 *     {@link RDB_E_SQLITE_NOMEM} SQLite: The database is out of memory.
 * Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_Store.
 * @since 20
 */
int OH_Rdb_SetLocale(OH_Rdb_Store *store, const char *locale);

/**
 * @brief Change the encrypted database key.
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param param Represents a pointer to an instance of OH_Rdb_CryptoParam.
 * @return Returns the status code of the execution.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_ERROR} database common error.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_ALREADY_CLOSED} database already closed.
 *         Returns {@link RDB_E_SQLITE_CORRUPT} database corrupted.
 *         Returns {@link RDB_E_SQLITE_PERM} SQLite: Access permission denied.
 *         Returns {@link RDB_E_SQLITE_BUSY} SQLite: The database file is locked.
 *         Returns {@link RDB_E_SQLITE_NOMEM} SQLite: The database is out of memory.
 *         Returns {@link RDB_E_SQLITE_READONLY} SQLite: Attempt to write a readonly database.
 *         Returns {@link RDB_E_SQLITE_IOERR} SQLite: Some kind of disk I/O error occurred.
 *         Returns {@link RDB_E_SQLITE_FULL} SQLite: The database is full.
 * @since 22
 */
int OH_Rdb_RekeyEx(OH_Rdb_Store *store, OH_Rdb_CryptoParam *param);

#ifdef __cplusplus
};
#endif

#endif // RELATIONAL_STORE_H
