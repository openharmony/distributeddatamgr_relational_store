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

namespace OHOS {
namespace NativeRdb {

static constexpr int E_OK = 0;
static constexpr int E_BASE = 1000;
static constexpr int E_ERROR = (E_BASE + 1);
static constexpr int E_CANNOT_UPDATE_READONLY = (E_BASE + 2);
static constexpr int E_REMOVE_FILE = (E_BASE + 3);
static constexpr int E_EMPTY_FILE_NAME = (E_BASE + 4);
static constexpr int E_EMPTY_TABLE_NAME = (E_BASE + 5);
static constexpr int E_EMPTY_VALUES_BUCKET = (E_BASE + 6);
static constexpr int E_INVALID_STATEMENT = (E_BASE + 7);
static constexpr int E_INVALID_COLUMN_INDEX = (E_BASE + 8);
static constexpr int E_INVALID_COLUMN_TYPE = (E_BASE + 9);
static constexpr int E_INVALID_COLUMN_NAME = (E_BASE + 10);
static constexpr int E_QUERY_IN_EXECUTE = (E_BASE + 11);
static  constexpr int E_TRANSACTION_IN_EXECUTE = (E_BASE + 12);
static  constexpr int E_EXECUTE_IN_STEP_QUERY = (E_BASE + 13);
static  constexpr int E_EXECUTE_WRITE_IN_READ_CONNECTION = (E_BASE + 14);
static constexpr int E_BEGIN_TRANSACTION_IN_READ_CONNECTION = (E_BASE + 15);
static constexpr int E_NO_TRANSACTION_IN_SESSION = (E_BASE + 16);
static constexpr int E_MORE_STEP_QUERY_IN_ONE_SESSION = (E_BASE + 17);
static constexpr int E_NO_ROW_IN_QUERY = (E_BASE + 18);
static constexpr int E_INVALID_BIND_ARGS_COUNT = (E_BASE + 19);
static constexpr int E_INVALID_OBJECT_TYPE = (E_BASE + 20);
static constexpr int E_INVALID_CONFLICT_FLAG = (E_BASE + 21);
static constexpr int E_HAVING_CLAUSE_NOT_IN_GROUP_BY = (E_BASE + 22);
static constexpr int E_NOT_SUPPORTED_BY_STEP_RESULT_SET = (E_BASE + 23);
static constexpr int E_STEP_RESULT_SET_CROSS_THREADS = (E_BASE + 24);
static constexpr int E_STEP_RESULT_QUERY_NOT_EXECUTED = (E_BASE + 25);
static constexpr int E_STEP_RESULT_IS_AFTER_LAST = (E_BASE + 26);
static constexpr int E_STEP_RESULT_QUERY_EXCEEDED = (E_BASE + 27);
static constexpr int E_STATEMENT_NOT_PREPARED = (E_BASE + 28);
static constexpr int E_EXECUTE_RESULT_INCORRECT = (E_BASE + 29);
static constexpr int E_STEP_RESULT_CLOSED = (E_BASE + 30);
static constexpr int E_RELATIVE_PATH = (E_BASE + 31);
static constexpr int E_EMPTY_NEW_ENCRYPT_KEY = (E_BASE + 32);
static constexpr int E_CHANGE_UNENCRYPTED_TO_ENCRYPTED = (E_BASE + 33);
static constexpr int E_CHANGE_ENCRYPT_KEY_IN_BUSY = (E_BASE + 34);
static constexpr int E_STEP_STATEMENT_NOT_INIT = (E_BASE + 35);
static constexpr int E_NOT_SUPPORTED_ATTACH_IN_WAL_MODE = (E_BASE + 36);
static constexpr int E_CREATE_FOLDER_FAIL = (E_BASE + 37);
static constexpr int E_SQLITE_SQL_BUILDER_NORMALIZE_FAIL = (E_BASE + 38);
static constexpr int E_STORE_SESSION_NOT_GIVE_CONNECTION_TEMPORARILY = (E_BASE + 39);
static constexpr int E_STORE_SESSION_NO_CURRENT_TRANSACTION = (E_BASE + 40);
static constexpr int E_NOT_SUPPORT = (E_BASE + 41);
static constexpr int E_INVALID_PARCEL = (E_BASE + 42);
static constexpr int E_INVALID_FILE_PATH = (E_BASE + 43);
static constexpr int E_SET_PERSIST_WAL = (E_BASE + 44);
static constexpr int E_DB_NOT_EXIST = (E_BASE + 45);
static constexpr int E_ARGS_READ_CON_OVERLOAD = (E_BASE + 46);

/**
* @brief The error when the wal file size over default limit.
*/
static constexpr int E_WAL_SIZE_OVER_LIMIT = (E_BASE + 47);
} // namespace NativeRdb
} // namespace OHOS

#endif
