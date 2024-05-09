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

#include "convertor_error_code.h"
#include <algorithm>
#include "relational_store_error_code.h"
#include "rdb_errno.h"

namespace OHOS::RdbNdk {

struct NdkErrorCode {
    int nativeCode;
    int ndkCode;
};

static constexpr NdkErrorCode ERROR_CODE_MAP[] = {
    { OHOS::NativeRdb::E_OK, RDB_OK },
    { OHOS::NativeRdb::E_ERROR, RDB_E_ERROR },
    { OHOS::NativeRdb::E_INVALID_ARGS, RDB_E_INVALID_ARGS },
    { OHOS::NativeRdb::E_CANNOT_UPDATE_READONLY, RDB_E_CANNOT_UPDATE_READONLY },
    { OHOS::NativeRdb::E_REMOVE_FILE, RDB_E_REMOVE_FILE },
    { OHOS::NativeRdb::E_EMPTY_TABLE_NAME, RDB_E_EMPTY_TABLE_NAME },
    { OHOS::NativeRdb::E_EMPTY_VALUES_BUCKET, RDB_E_EMPTY_VALUES_BUCKET },
    { OHOS::NativeRdb::E_NOT_SELECT, RDB_E_EXECUTE_IN_STEP_QUERY },
    { OHOS::NativeRdb::E_COLUMN_OUT_RANGE, RDB_E_INVALID_COLUMN_INDEX },
    { OHOS::NativeRdb::E_INVALID_COLUMN_TYPE, RDB_E_INVALID_COLUMN_TYPE },
    { OHOS::NativeRdb::E_EMPTY_FILE_NAME, RDB_E_EMPTY_FILE_NAME },
    { OHOS::NativeRdb::E_INVALID_FILE_PATH, RDB_E_INVALID_FILE_PATH },
    { OHOS::NativeRdb::E_TRANSACTION_IN_EXECUTE, RDB_E_TRANSACTION_IN_EXECUTE },
    { OHOS::NativeRdb::E_EXECUTE_WRITE_IN_READ_CONNECTION, RDB_E_EXECUTE_WRITE_IN_READ_CONNECTION },
    { OHOS::NativeRdb::E_BEGIN_TRANSACTION_IN_READ_CONNECTION, RDB_E_BEGIN_TRANSACTION_IN_READ_CONNECTION },
    { OHOS::NativeRdb::E_NO_TRANSACTION_IN_SESSION, RDB_E_NO_TRANSACTION_IN_SESSION },
    { OHOS::NativeRdb::E_MORE_STEP_QUERY_IN_ONE_SESSION, RDB_E_MORE_STEP_QUERY_IN_ONE_SESSION },
    { OHOS::NativeRdb::E_NO_ROW_IN_QUERY, RDB_E_NO_ROW_IN_QUERY },
    { OHOS::NativeRdb::E_INVALID_BIND_ARGS_COUNT, RDB_E_INVALID_BIND_ARGS_COUNT },
    { OHOS::NativeRdb::E_INVALID_OBJECT_TYPE, RDB_E_INVALID_OBJECT_TYPE },
    { OHOS::NativeRdb::E_INVALID_CONFLICT_FLAG, RDB_E_INVALID_CONFLICT_FLAG },
    { OHOS::NativeRdb::E_HAVING_CLAUSE_NOT_IN_GROUP_BY, RDB_E_HAVING_CLAUSE_NOT_IN_GROUP_BY },
    { OHOS::NativeRdb::E_NOT_SUPPORTED_BY_STEP_RESULT_SET, RDB_E_NOT_SUPPORTED },
    { OHOS::NativeRdb::E_STEP_RESULT_SET_CROSS_THREADS, RDB_E_STEP_RESULT_SET_CROSS_THREADS },
    { OHOS::NativeRdb::E_NO_MORE_ROWS, RDB_E_STEP_RESULT_IS_AFTER_LAST },
    { OHOS::NativeRdb::E_STEP_RESULT_QUERY_EXCEEDED, RDB_E_STEP_RESULT_QUERY_EXCEEDED },
    { OHOS::NativeRdb::E_STATEMENT_NOT_PREPARED, RDB_E_STATEMENT_NOT_PREPARED },
    { OHOS::NativeRdb::E_EXECUTE_RESULT_INCORRECT, RDB_E_EXECUTE_RESULT_INCORRECT },
    { OHOS::NativeRdb::E_ALREADY_CLOSED, RDB_E_STEP_RESULT_CLOSED },
    { OHOS::NativeRdb::E_RELATIVE_PATH, RDB_E_RELATIVE_PATH },
    { OHOS::NativeRdb::E_EMPTY_NEW_ENCRYPT_KEY, RDB_E_EMPTY_NEW_ENCRYPT_KEY },
    { OHOS::NativeRdb::E_CHANGE_UNENCRYPTED_TO_ENCRYPTED, RDB_E_CHANGE_UNENCRYPTED_TO_ENCRYPTED },
    { OHOS::NativeRdb::E_DATABASE_BUSY, RDB_E_CON_OVER_LIMIT },
    { OHOS::NativeRdb::E_STORE_CLOSED, RDB_E_STEP_RESULT_CLOSED },
    { OHOS::NativeRdb::E_NOT_SUPPORTED_ATTACH_IN_WAL_MODE, RDB_E_NOT_SUPPORTED_ATTACH_IN_WAL_MODE },
    { OHOS::NativeRdb::E_CREATE_FOLDER_FAIL, RDB_E_CREATE_FOLDER_FAIL },
    { OHOS::NativeRdb::E_SQLITE_SQL_BUILDER_NORMALIZE_FAIL, RDB_E_SQLITE_SQL_BUILDER_NORMALIZE_FAIL },
    { OHOS::NativeRdb::E_STORE_SESSION_NOT_GIVE_CONNECTION_TEMPORARILY,
        RDB_E_STORE_SESSION_NOT_GIVE_CONNECTION_TEMPORARILY },
    { OHOS::NativeRdb::E_STORE_SESSION_NO_CURRENT_TRANSACTION, RDB_E_STORE_SESSION_NO_CURRENT_TRANSACTION },
    { OHOS::NativeRdb::E_NOT_SUPPORT, RDB_E_NOT_SUPPORTED },
    { OHOS::NativeRdb::E_INVALID_PARCEL, RDB_E_INVALID_PARCEL },
    { OHOS::NativeRdb::E_QUERY_IN_EXECUTE, RDB_E_QUERY_IN_EXECUTE },
    { OHOS::NativeRdb::E_SET_PERSIST_WAL, RDB_E_SET_PERSIST_WAL },
    { OHOS::NativeRdb::E_DB_NOT_EXIST, RDB_E_DB_NOT_EXIST },
    { OHOS::NativeRdb::E_ARGS_READ_CON_OVERLOAD, RDB_E_ARGS_READ_CON_OVERLOAD },
    { OHOS::NativeRdb::E_WAL_SIZE_OVER_LIMIT, RDB_E_WAL_SIZE_OVER_LIMIT },
    { OHOS::NativeRdb::E_CON_OVER_LIMIT, RDB_E_CON_OVER_LIMIT },
    { OHOS::NativeRdb::E_NOT_SUPPORTED, RDB_E_NOT_SUPPORTED },
};

int ConvertorErrorCode::NativeToNdk(int nativeErrCode)
{
    auto errorCode = NdkErrorCode{ nativeErrCode, -1 };
    auto iter = std::lower_bound(ERROR_CODE_MAP,
        ERROR_CODE_MAP + sizeof(ERROR_CODE_MAP) / sizeof(ERROR_CODE_MAP[0]),
        errorCode, [](const NdkErrorCode &errorCode1, const NdkErrorCode &errorCode2) {
            return errorCode1.nativeCode < errorCode2.nativeCode;
        });
    if (iter < ERROR_CODE_MAP + sizeof(ERROR_CODE_MAP) / sizeof(ERROR_CODE_MAP[0]) &&
        iter->nativeCode == nativeErrCode) {
        return iter->ndkCode;
    }
    return RDB_E_ERROR;
}
}