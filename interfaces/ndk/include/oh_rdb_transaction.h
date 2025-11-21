/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
 * @file oh_rdb_transaction.h
 *
 * @brief Provides database transaction related functions and enumerations.
 *
 * @kit ArkData
 * @library libnative_rdb_ndk.z.so
 * @syscap SystemCapability.DistributedDataManager.RelationalStore.Core
 *
 * @since 16
 */

#ifndef OH_RDB_TRANSACTION_H
#define OH_RDB_TRANSACTION_H
#include "oh_cursor.h"
#include "oh_predicates.h"
#include "oh_data_values.h"
#include "oh_values_bucket.h"
#include "oh_data_values_buckets.h"
#include "oh_rdb_types.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Indicates relation database transaction type.
 *
 * @since 16
 */
typedef enum OH_RDB_TransType {
    /**
     * @brief Indicates the transaction does not actually start until the database is first accessed. It's a default.
     */
    RDB_TRANS_DEFERRED = 0,
    /**
     * @brief Indicates the database connection to start a new write immediately, without waiting for a write statement.
     */
    RDB_TRANS_IMMEDIATE,
    /**
     * @brief Indicates it is similar to RDB_TRANS_IMMEDIATE in that a write transaction is started immediately.
     * RDB_TRANS_EXCLUSIVE and RDB_TRANS_IMMEDIATE are the same in WAL mode, but in other journaling modes,
     * EXCLUSIVE prevents other database connections from reading the database while the transaction is underway.
     */
    RDB_TRANS_EXCLUSIVE,
    /**
     * The largest value for rdb transaction type.
     */
    RDB_TRANS_BUTT,
} OH_RDB_TransType;

/**
 * @brief Define the OH_RDB_TransOptions structure type.
 *
 * @since 16
 */
typedef struct OH_RDB_TransOptions OH_RDB_TransOptions;

/**
 * @brief Define the OH_Rdb_Transaction structure type.
 *
 * @since 16
 */
typedef struct OH_Rdb_Transaction OH_Rdb_Transaction;

/**
 * @brief Creates an OH_RDB_TransOptions instance object.
 *
 * @return Returns a pointer to OH_RDB_TransOptions instance when the execution is successful.
 * Otherwise, nullptr is returned. The memory must be released through the OH_RdbTrans_DestroyOptions
 * interface after the use is complete.
 * @see OH_RdbTrans_DestroyOptions.
 * @since 16
 */
OH_RDB_TransOptions *OH_RdbTrans_CreateOptions(void);

/**
 * @brief Destroys an OH_RDB_TransOptions instance object.
 *
 * @param options Represents a pointer to an instance of OH_RDB_TransOptions.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_RdbTrans_DestroyOptions(OH_RDB_TransOptions *options);

/**
 * @brief Sets integer data to the options object.
 *
 * @param options Represents a pointer to an instance of OH_RDB_TransOptions.
 * @param type Represents relation database transaction type.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_RdbTransOption_SetType(OH_RDB_TransOptions *options, OH_RDB_TransType type);

/**
 * @brief Commits a transaction of a relational database.
 *
 * @param trans Represents a pointer to an instance of OH_Rdb_Transaction.
 * @return Returns the status code of the execution.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_ERROR} database common error.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_ALREADY_CLOSED} database already closed.
 *         Returns {@link RDB_E_SQLITE_FULL} SQLite: The database is full.
 *         Returns {@link RDB_E_SQLITE_CORRUPT} database corrupted.
 *         Returns {@link RDB_E_SQLITE_PERM} SQLite: Access permission denied.
 *         Returns {@link RDB_E_SQLITE_BUSY} SQLite: The database file is locked.
 *         Returns {@link RDB_E_SQLITE_NOMEM} SQLite: The database is out of memory.
 *         Returns {@link RDB_E_SQLITE_READONLY} SQLite: SQLite: Attempt to write a readonly database.
 *         Returns {@link RDB_E_SQLITE_IOERR} SQLite: Some kind of disk I/O error occurred.
 * @since 16
 */
int OH_RdbTrans_Commit(OH_Rdb_Transaction *trans);

/**
 * @brief Roll back a transaction of a relational database.
 *
 * @param trans Represents a pointer to an instance of OH_Rdb_Transaction.
 * @return Returns the status code of the execution.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_ERROR} database common error.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 *         Returns {@link RDB_E_ALREADY_CLOSED} database already closed.
 *         Returns {@link RDB_E_SQLITE_FULL} SQLite: The database is full.
 *         Returns {@link RDB_E_SQLITE_CORRUPT} database corrupted.
 *         Returns {@link RDB_E_SQLITE_PERM} SQLite: Access permission denied.
 *         Returns {@link RDB_E_SQLITE_BUSY} SQLite: The database file is locked.
 *         Returns {@link RDB_E_SQLITE_NOMEM} SQLite: The database is out of memory.
 *         Returns {@link RDB_E_SQLITE_READONLY} SQLite: Attempt to write a readonly database.
 *         Returns {@link RDB_E_SQLITE_IOERR} SQLite: Some kind of disk I/O error occurred.
 * @since 16
 */
int OH_RdbTrans_Rollback(OH_Rdb_Transaction *trans);

/**
 * @brief Inserts a row of data into the target table.
 *
 * @param trans Represents a pointer to an instance of OH_Rdb_Transaction.
 * @param table Represents the target table.
 * @param row Represents the row data to be inserted into the table.
 * @param rowId Represents row line number when insert successfully.
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

 * @since 16
 */
int OH_RdbTrans_Insert(OH_Rdb_Transaction *trans, const char *table, const OH_VBucket *row, int64_t *rowId);

/**
 * @brief Inserts a row of data into the target table and support conflict resolution.
 *
 * @param trans Represents a pointer to an instance of OH_Rdb_Transaction.
 * @param table Represents the target table.
 * @param row Represents the row data to be inserted into the table.
 * @param resolution Represents the resolution when conflict occurs.
 * @param rowId Represents row line number when insert successfully.
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
int OH_RdbTrans_InsertWithConflictResolution(OH_Rdb_Transaction *trans, const char *table, const OH_VBucket *row,
    Rdb_ConflictResolution resolution, int64_t *rowId);

/**
 * @brief Inserts a batch of data into the target table.
 *
 * @param trans Represents a pointer to an instance of OH_Rdb_Transaction.
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
int OH_RdbTrans_BatchInsert(OH_Rdb_Transaction *trans, const char *table, const OH_Data_VBuckets *rows,
    Rdb_ConflictResolution resolution, int64_t *changes);

/**
 * @brief Updates data in the database based on specified conditions.
 *
 * @param trans Represents a pointer to an instance of OH_Rdb_Transaction.
 * @param row Represents the row data to be updated into the table.
 * @param predicates Represents the specified update condition by the instance object of OH_Predicates.
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
 * @since 16
 */
int OH_RdbTrans_Update(OH_Rdb_Transaction *trans, const OH_VBucket *row, const OH_Predicates *predicates,
    int64_t *changes);
/**
 * @brief Updates data in the database based on specified conditions and support conflict resolution.
 *
 * @param trans Represents a pointer to an instance of OH_Rdb_Transaction.
 * @param row Represents the row data to be updated into the table.
 * @param predicates Represents the specified update condition by the instance object of OH_Predicates.
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
 * @since 20
 */
int OH_RdbTrans_UpdateWithConflictResolution(OH_Rdb_Transaction *trans, const OH_VBucket *row,
    const OH_Predicates *predicates, Rdb_ConflictResolution resolution, int64_t *changes);

/**
 * @brief Deletes data from the database based on specified conditions
 *
 * @param trans Represents a pointer to an instance of OH_Rdb_Transaction.
 * @param predicates Represents the specified update condition by the instance object of OH_Predicates.
 * @param changes Represents the number of successfully Deleted.
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
 * @since 16
 */
int OH_RdbTrans_Delete(OH_Rdb_Transaction *trans, const OH_Predicates *predicates, int64_t *changes);

/**
 * @brief Queries data in the database based on specified conditions without row count.
 *
 * @param trans Represents a pointer to an instance of OH_Rdb_Transaction.
 * @param predicates Represents the specified update condition by the instance object of OH_Predicates.
 * @param columns Represents the columns to query. If the value is empty array, the query applies to all columns.
 * @param len Represents the number of columns elements.
 * @return If the operation is successful, a pointer to the instance of the OH_Cursor structure is returned.
 * If database has closed or the database does not respond, nullptr is returned.
 * @since 23
 */
OH_Cursor *OH_RdbTrans_QueryWithoutRowCount(OH_Rdb_Transaction *trans, const OH_Predicates *predicates,
    const char * const columns[], int len);

/**
 * @brief Queries data in the database based on specified conditions.
 *
 * @param trans Represents a pointer to an instance of OH_Rdb_Transaction.
 * @param predicates Represents the specified update condition by the instance object of OH_Predicates.
 * @param columns Represents the columns to query. If the value is empty array, the query applies to all columns.
 * @param len Represents the number of columns elements.
 * @return If the operation is successful, a pointer to the instance of the OH_Cursor structure is returned.
 * If database has closed or the database does not respond, nullptr is returned.
 * @since 16
 */
OH_Cursor *OH_RdbTrans_Query(OH_Rdb_Transaction *trans, const OH_Predicates *predicates, const char *columns[],
    int len);

/**
 * @brief Queries data in the database based on SQL statement.
 *
 * @param trans Represents a pointer to an instance of OH_Rdb_Transaction.
 * @param sql Represents the SQL statement to execute.
 * @param args Represents a pointer to an instance of OH_Data_Values and  it is the selection arguments.
 * @return If the operation is successful, a pointer to the instance of the OH_Cursor structure is returned.
 * If database has closed or the database does not respond, nullptr is returned.
 * @since 16
 */
OH_Cursor *OH_RdbTrans_QuerySql(OH_Rdb_Transaction *trans, const char *sql, const OH_Data_Values *args);

/**
 * @brief Queries data in the database based on SQL statement without row count.
 *
 * @param trans Represents a pointer to an instance of OH_Rdb_Transaction.
 * @param sql Represents the SQL statement to execute.
 * @param args Represents a pointer to an instance of OH_Data_Values and  it is the selection arguments.
 * @return If the operation is successful, a pointer to the instance of the OH_Cursor structure is returned.
 * If database has closed or the database does not respond, nullptr is returned.
 * @since 23
 */
OH_Cursor *OH_RdbTrans_QuerySqlWithoutRowCount(OH_Rdb_Transaction *trans, const char *sql, const OH_Data_Values *args);

/**
 * @brief Executes an SQL statement that contains specified parameters.
 *
 * @param trans Represents a pointer to an instance of OH_Rdb_Transaction.
 * @param sql Represents the SQL statement to execute.
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
int OH_RdbTrans_Execute(OH_Rdb_Transaction *trans, const char *sql, const OH_Data_Values *args, OH_Data_Value **result);

/**
 * @brief Destroys an OH_Rdb_Transaction instance object.
 *
 * @param trans Represents a pointer to an instance of OH_Rdb_Transaction.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_RdbTrans_Destroy(OH_Rdb_Transaction *trans);

#ifdef __cplusplus
};
#endif
#endif // OH_RDB_TRANSACTION_H
/** @} */
