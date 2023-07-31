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
 * @return If the creation is successful, a pointer to the instance of the @link OH_Predicates} structure is returned,
 * otherwise NULL is returned.
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
 * @return If the creation is successful, a pointer to the instance of the @link OH_Rdb_Store} structure is returned,
 * otherwise NULL is returned.
 * @see OH_Rdb_Config, OH_Rdb_Store.
 * @since 10
 */
OH_Rdb_Store *OH_Rdb_GetOrOpen(const OH_Rdb_Config *config, int *errCode);

/**
 * @brief Close the {@link OH_Rdb_Store} object and reclaim the memory occupied by the object.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @return Returns the status code of the execution. Successful execution returns RDB_OK,
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
 * while failure returns a specific error code. Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_ErrCode.
 * @since 10
 */
int OH_Rdb_DeleteStore(const OH_Rdb_Config *config);

/**
 * @brief Inserts a row of data into the target table.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param table Indicates the target table.
 * @param valuesBucket Indicates the row of data {@link OH_VBucket} to be inserted into the table.
 * @return Returns the rowId if success, returns a specific error code.
 * Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_Store, OH_VBucket, OH_Rdb_ErrCode.
 * @since 10
 */
int OH_Rdb_Insert(OH_Rdb_Store *store, const char *table, OH_VBucket *valuesBucket);

/**
 * @brief Updates data in the database based on specified conditions.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param valuesBucket Indicates the row of data {@link OH__VBucket} to be updated in the database
 * @param predicates Represents a pointer to an {@link OH_Predicates} instance.
 * Indicates the specified update condition.
 * @return Returns the number of rows changed if success, otherwise, returns a specific error code.
 * Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_Store, OH_Bucket, OH_Predicates, OH_Rdb_ErrCode.
 * @since 10
 */
int OH_Rdb_Update(OH_Rdb_Store *store, OH_VBucket *valuesBucket, OH_Predicates *predicates);

/**
 * @brief Deletes data from the database based on specified conditions.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param predicates Represents a pointer to an {@link OH_Predicates} instance.
 * Indicates the specified delete condition.
 * @return Returns the number of rows changed if success, otherwise, returns a specific error code.
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
 * @return If the query is successful, a pointer to the instance of the @link OH_Cursor} structure is returned,
 * otherwise NULL is returned.
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
 * @see OH_Rdb_Store.
 * @since 10
 */
int OH_Rdb_Execute(OH_Rdb_Store *store, const char *sql);

/**
 * @brief Queries data in the database based on an SQL statement.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param sql Indicates the SQL statement to execute.
 * @return If the query is successful, a pointer to the instance of the @link OH_Cursor} structure is returned,
 * otherwise NULL is returned.
 * @see OH_Rdb_Store.
 * @since 10
 */
OH_Cursor *OH_Rdb_ExecuteQuery(OH_Rdb_Store *store, const char *sql);

/**
 * @brief Begins a transaction in EXCLUSIVE mode.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @return Returns the status code of the execution.
 * @see OH_Rdb_Store.
 * @since 10
 */
int OH_Rdb_BeginTransaction(OH_Rdb_Store *store);

/**
 * @brief Rolls back a transaction in EXCLUSIVE mode.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @return Returns the status code of the execution.
 * @see OH_Rdb_Store.
 * @since 10
 */
int OH_Rdb_RollBack(OH_Rdb_Store *store);

/**
 * @brief Commits a transaction in EXCLUSIVE mode.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @return Returns the status code of the execution.
 * @see OH_Rdb_Store.
 * @since 10
 */
int OH_Rdb_Commit(OH_Rdb_Store *store);

/**
 * @brief Backs up a database on specified path.
 *
 * @param store Represents a pointer to an {@link OH_Rdb_Store} instance.
 * @param databasePath Indicates the database file path.
 * @return Returns the status code of the execution.
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
 * @see OH_Rdb_Store.
 * @since 10
 */
int OH_Rdb_SetVersion(OH_Rdb_Store *store, int version);

#ifdef __cplusplus
};
#endif

#endif // RELATIONAL_STORE_H
