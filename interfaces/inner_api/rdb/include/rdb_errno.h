/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef NATIVE_RDB_RDB_ERRNO_H
#define NATIVE_RDB_RDB_ERRNO_H
#include <errors.h>
namespace OHOS {
namespace NativeRdb {

constexpr ErrCode DISTRIBUTEDDATAMGR_RDB_ERR_OFFSET = ErrCodeOffset(SUBSYS_DISTRIBUTEDDATAMNG, 2);
/**
* @brief The error code in the correct case.
*/
constexpr int E_OK = 0;

/**
* @brief The base code of the exception error code.
*/
constexpr int E_BASE = DISTRIBUTEDDATAMGR_RDB_ERR_OFFSET;

/**
* @brief The error when the capability not supported.
*/
constexpr int E_NOT_SUPPORT = (E_BASE + 801);

/**
* @brief The error code for common exceptions.
*/
constexpr int E_ERROR = E_BASE;

/**
* @brief The error code for common invalid args.
*/
constexpr int E_INVALID_ARGS = (E_BASE + 0x1);

/**
* @brief The error code for upgrade the read-only store.
*/
constexpr int E_CANNOT_UPDATE_READONLY = (E_BASE + 0x2);

/**
* @brief The error code when deleting a file fails.
*/
constexpr int E_REMOVE_FILE = (E_BASE + 0x3);

/**
* @brief The error code indicates that the SQL statement is incorrect.
*/
constexpr int E_INCORRECT_SQL = (E_BASE + 0x4);

/**
* @brief The error code for a table name is empty.
*/
constexpr int E_EMPTY_TABLE_NAME = (E_BASE + 0x5);

/**
* @brief The error code for a values bucket is empty.
*/
constexpr int E_EMPTY_VALUES_BUCKET = (E_BASE + 0x6);

/**
* @brief The error code when the sql is not select.
*/
constexpr int E_NOT_SELECT = (E_BASE + 0x7);

/**
* @brief The error code for the column out of bounds.
*/
constexpr int E_COLUMN_OUT_RANGE = (E_BASE + 0x8);

/**
* @brief The error code for the column type is invalid.
*/
constexpr int E_INVALID_COLUMN_TYPE = (E_BASE + 0x9);

/**
* @brief The error code for a file name is empty.
*/
constexpr int E_EMPTY_FILE_NAME = (E_BASE + 0xa);

/**
* @brief The error for the current file path is invalid.
*/
constexpr int E_INVALID_FILE_PATH = (E_BASE + 0xb);

/**
* @brief The error code when using transactions.
*/
constexpr int E_TRANSACTION_IN_EXECUTE = (E_BASE + 0xc);

/**
* @brief The error code for the row out of bounds.
*/
constexpr int E_ROW_OUT_RANGE = (E_BASE + 0xd);

/**
* @brief The error code when execute write operation in read connection.
*/
constexpr int E_EXECUTE_WRITE_IN_READ_CONNECTION = (E_BASE + 0xe);

/**
* @brief The error code for execute begin transaction operation in read connection.
*/
constexpr int E_BEGIN_TRANSACTION_IN_READ_CONNECTION = (E_BASE + 0xf);

/**
* @brief The error code for there are no transactions in this connection.
*/
constexpr int E_NO_TRANSACTION_IN_SESSION = (E_BASE + 0x10);

/**
* @brief The error code when begin more step query in one session.
*/
constexpr int E_MORE_STEP_QUERY_IN_ONE_SESSION = (E_BASE + 0x11);

/**
* @brief The error code when the current statement doesn't contains one row result data.
*/
constexpr int E_NO_ROW_IN_QUERY = (E_BASE + 0x12);

/**
* @brief The error code for the bind arguments count is invalid.
*/
constexpr int E_INVALID_BIND_ARGS_COUNT = (E_BASE + 0x13);

/**
* @brief The error code for the object type is invalid.
*/
constexpr int E_INVALID_OBJECT_TYPE = (E_BASE + 0x14);

/**
* @brief The error code for the conflict flag is invalid.
*/
constexpr int E_INVALID_CONFLICT_FLAG = (E_BASE + 0x15);

/**
* @brief The error code for having clause not in group.
*/
constexpr int E_HAVING_CLAUSE_NOT_IN_GROUP_BY = (E_BASE + 0x16);

/**
* @brief The error code for not supported by step result set.
*/
constexpr int E_NOT_SUPPORTED_BY_STEP_RESULT_SET = (E_BASE + 0x17);

/**
* @brief The error code for step result current tid not equal to object's tid.
*/
constexpr int E_STEP_RESULT_SET_CROSS_THREADS = (E_BASE + 0x18);

/**
* @brief The error code when the result query was not executed.
*/
constexpr int E_NOT_INIT = (E_BASE + 0x19);

/**
* @brief The error code for the result set cursor is after the last row.
*/
constexpr int E_NO_MORE_ROWS = (E_BASE + 0x1a);

/**
* @brief The error code for the result set query exceeded.
*/
constexpr int E_STEP_RESULT_QUERY_EXCEEDED = (E_BASE + 0x1b);

/**
* @brief The error code for the statement not prepared.
*/
constexpr int E_STATEMENT_NOT_PREPARED = (E_BASE + 0x1c);

/**
* @brief The error code for the result set is incorrect.
*/
constexpr int E_EXECUTE_RESULT_INCORRECT = (E_BASE + 0x1d);

/**
* @brief The error code when the result set is closed.
*/
constexpr int E_ALREADY_CLOSED = (E_BASE + 0x1e);

/**
* @brief The error code when input relative path.
*/
constexpr int E_RELATIVE_PATH = (E_BASE + 0x1f);

/**
* @brief The error code for the new encrypt key is empty.
*/
constexpr int E_EMPTY_NEW_ENCRYPT_KEY = (E_BASE + 0x20);

/**
* @brief The error code for change unencrypted to encrypted.
*/
constexpr int E_CHANGE_UNENCRYPTED_TO_ENCRYPTED = (E_BASE + 0x21);

/**
* @brief The error code for database busy.
*/
constexpr int E_DATABASE_BUSY = (E_BASE + 0x22);

/**
* @brief The error code when the statement not initialized.
*/
constexpr int E_STORE_CLOSED = (E_BASE + 0x23);

/**
* @brief The error code for the attach is not supported in WAL journal mode.
*/
constexpr int E_NOT_SUPPORTED_ATTACH_IN_WAL_MODE = (E_BASE + 0x24);

/**
* @brief The error code when create folder failed.
*/
constexpr int E_CREATE_FOLDER_FAIL = (E_BASE + 0x25);

/**
* @brief The error for SQL builder normalize failed.
*/
constexpr int E_SQLITE_SQL_BUILDER_NORMALIZE_FAIL = (E_BASE + 0x26);

/**
* @brief The error for store session not give connection temporarily.
*/
constexpr int E_STORE_SESSION_NOT_GIVE_CONNECTION_TEMPORARILY = (E_BASE + 0x27);

/**
* @brief The error for store session not current transaction.
*/
constexpr int E_STORE_SESSION_NO_CURRENT_TRANSACTION = (E_BASE + 0x28);

/**
* @brief The error for not supported the current operation.
*/
constexpr int E_NOT_SUPPORTED = (E_BASE + 0x29);

/**
* @brief The error for the current parcel is invalid.
*/
constexpr int E_INVALID_PARCEL = (E_BASE + 0x2a);

/**
* @brief The error code when using sqlite3_step function failed.
*/
constexpr int E_QUERY_IN_EXECUTE = (E_BASE + 0x2b);

/**
* @brief The error for set persist WAL.
*/
constexpr int E_SET_PERSIST_WAL = (E_BASE + 0x2c);

/**
* @brief The error when the database does not exist.
*/
constexpr int E_DB_NOT_EXIST = (E_BASE + 0x2d);

/**
* @brief The error when the read connection count is overload.
*/
constexpr int E_ARGS_READ_CON_OVERLOAD = (E_BASE + 0x2e);

/**
* @brief The error when the wal file size over default limit.
*/
static constexpr int E_WAL_SIZE_OVER_LIMIT = (E_BASE + 0x2f);

/**
* @brief The error when the connection count is used up.
*/
static constexpr int E_CON_OVER_LIMIT = (E_BASE + 0x30);

/**
* @brief The error when the sharedblock unit is null.
*/
static constexpr int E_NULL_OBJECT = (E_BASE + 0x31);

/**
* @brief Failed to get DataObsMgrClient.
*/
static constexpr int E_GET_DATAOBSMGRCLIENT_FAIL = (E_BASE + 0x32);

/**
 * @brief The error when the type of the distributed table does not match.
 */
static constexpr int E_TYPE_MISMATCH = (E_BASE + 0x33);

/**
 * @brief Insertion failed because database is full.
 */
static constexpr int E_SQLITE_FULL = (E_BASE + 0x34);

/**
 * @brief The error when sql is not supported in execute
 */
static constexpr int E_NOT_SUPPORT_THE_SQL = (E_BASE + 0x35);

/**
 * @brief The database alias already exists.
 */
static constexpr int E_ATTACHED_DATABASE_EXIST = (E_BASE + 0x36);

/**
 * @brief Generic error.
 */
static constexpr int E_SQLITE_ERROR = (E_BASE + 0x37);

/**
 * @brief The database disk image is malformed. Used by vector db, too.
 */
static constexpr int E_SQLITE_CORRUPT = (E_BASE + 0x38);

/**
 * @brief The error when unlocking data needs to be compensated sync
 */
static constexpr int E_WAIT_COMPENSATED_SYNC = (E_BASE + 0x39);

/**
 * @brief Callback routine requested an abort.
 */
static constexpr int E_SQLITE_ABORT = (E_BASE + 0x3a);

/**
 * @brief Access permission denied.
 */
static constexpr int E_SQLITE_PERM = (E_BASE + 0x3b);

/**
 * @brief The database file is locked.
 */
static constexpr int E_SQLITE_BUSY = (E_BASE + 0x3c);

/**
 * @brief A table in the database is locked.
 */
static constexpr int E_SQLITE_LOCKED = (E_BASE + 0x3d);

/**
 * @brief A malloc() failed.
 */
static constexpr int E_SQLITE_NOMEM = (E_BASE + 0x3e);

/**
 * @brief Attempt to write a readonly database.
 */
static constexpr int E_SQLITE_READONLY = (E_BASE + 0x3f);

/**
 * @brief Some kind of disk I/O error occurred.
 */
static constexpr int E_SQLITE_IOERR = (E_BASE + 0x40);

/**
 * @brief Unable to open the database file.
 */
static constexpr int E_SQLITE_CANTOPEN = (E_BASE + 0x41);

/**
 * @brief String or BLOB exceeds size limit.
 */
static constexpr int E_SQLITE_TOOBIG = (E_BASE + 0x42);

/**
 * @brief Abort due to constraint violation.
 */
static constexpr int E_SQLITE_CONSTRAINT = (E_BASE + 0x43);

/**
 * @brief Data type mismatch.
 */
static constexpr int E_SQLITE_MISMATCH = (E_BASE + 0x44);

/**
 * @brief Library used incorrectly.
 */
static constexpr int E_SQLITE_MISUSE = (E_BASE + 0x45);

/**
 * @brief Config changed.
 */
static constexpr int E_CONFIG_INVALID_CHANGE = (E_BASE + 0x46);

/**
 * @brief Not get service.
 */
static constexpr int E_SERVICE_NOT_FOUND = (E_BASE + 0x47);

/**
 * @brief Database schema has changed.
 */
static constexpr int E_SQLITE_SCHEMA = (E_BASE + 0x48);

/**
 * @brief Operation cancel.
 */
static constexpr int E_CANCEL = (E_BASE + 0x49);

/**
 * @brief The secret key is corrupted or lost.
 */
static constexpr int E_INVALID_SECRET_KEY = (E_BASE + 0x4a);

/**
 * @brief No space left on device
 */
static constexpr int E_SQLITE_IOERR_FULL = (E_BASE + 0x4b);

/**
 * @brief Do not use except relational_store
 */
static constexpr int E_INNER_WARNING = (E_BASE + 0x4c);

/**
 * @brief This is not a database file.
 */
static constexpr int E_SQLITE_NOT_DB = (E_BASE + 0x4d);

/**
 * @brief The root key of the encrypted database is faulty.
 */
static constexpr int E_ROOT_KEY_FAULT = (E_BASE + 0x4e);

/**
 * @brief The root key of the encrypted database cannot be loaded.
 */
static constexpr int E_ROOT_KEY_NOT_LOAD = (E_BASE + 0x4f);

/**
 * @brief The working key of the encrypted database is faulty.
 */
static constexpr int E_WORK_KEY_FAIL = (E_BASE + 0x50);

/**
 * @brief Failed to encrypt the working key.
 */
static constexpr int E_WORK_KEY_ENCRYPT_FAIL = (E_BASE + 0x51);

/**
 * @brief Failed to decrypt the working key.
 */
static constexpr int E_WORK_KEY_DECRYPT_FAIL = (E_BASE + 0x52);

/**
 * @brief Failed to open the sqlite database using the working key.
 */
static constexpr int E_SET_ENCRYPT_FAIL = (E_BASE + 0x53);

/**
 * @brief Failed to open the sqlite database using the working new key.
 */
static constexpr int E_SET_NEW_ENCRYPT_FAIL = (E_BASE + 0x54);

/**
 * @brief Failed to open the sqlite database using the working service key.
 */
static constexpr int E_SET_SERVICE_ENCRYPT_FAIL = (E_BASE + 0x55);

/**
 * @brief Database WAL file check point failed.
 */
static constexpr int E_CHECK_POINT_FAIL = (E_BASE + 0x56);

/**
 * @brief Database db meta recovered success.
 */
static constexpr int E_SQLITE_META_RECOVERED = (E_BASE + 0x57);

/**
* @brief The error code for common invalid args.
*/
static constexpr int E_INVALID_ARGS_NEW = (E_BASE + 0x58);

/**
* @brief The error code for the number of subscriptions exceeds the limit.
*/
static constexpr int E_SUB_LIMIT_REACHED = (E_BASE + 0x59);
} // namespace NativeRdb
} // namespace OHOS

#endif
