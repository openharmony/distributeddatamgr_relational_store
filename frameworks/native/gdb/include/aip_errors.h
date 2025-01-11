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

#ifndef OHOS_DISTRIBUTED_DATA_NATIVE_GDB_AIP_ERRORS_H
#define OHOS_DISTRIBUTED_DATA_NATIVE_GDB_AIP_ERRORS_H

#include "errors.h"

namespace OHOS {
namespace DistributedDataAip {
enum {
    AIP_MODULE_SERVICE_ID = 0x08,
};

constexpr ErrCode DISTRIBUTEDDATAMGR_GDB_ERR_OFFSET = ErrCodeOffset(SUBSYS_DISTRIBUTEDDATAMNG, AIP_MODULE_SERVICE_ID);

/**
* @brief The error code in the correct case.
*/
constexpr int E_OK = 0;

/**
* @brief The base code of the exception error code.
*/
constexpr int E_BASE = DISTRIBUTEDDATAMGR_GDB_ERR_OFFSET;

/**
* @brief The error code for common exceptions.
*/
constexpr int E_ERROR = E_BASE;

constexpr int E_INVALID_ARGS = (E_BASE + 0x1);
constexpr int E_NOT_SUPPORT = (E_BASE + 0x2);

/* GRD error */

constexpr int E_GRD_NO_DATA = (E_BASE + 0x3);
constexpr int E_GRD_DATA_CORRUPTED = (E_BASE + 0x4);
constexpr int E_GRD_DB_INSTANCE_ABNORMAL = (E_BASE + 0x5);
constexpr int E_DATABASE_BUSY = (E_BASE + 0x6);
constexpr int E_GRD_FAILED_MEMORY_ALLOCATE = (E_BASE + 0x7);
constexpr int E_GRD_DISK_SPACE_FULL = (E_BASE + 0x8);
constexpr int E_GRD_DUPLICATE_PARAM = (E_BASE + 0x9);
constexpr int E_GRD_UNDEFINED_PARAM = (E_BASE + 0xa);
constexpr int E_GRD_CONSTRAINT_CHECK_VIOLATION = (E_BASE + 0xb);
constexpr int E_GRD_SYNTAX_ERROR = (E_BASE + 0xc);
constexpr int E_GRD_SEMANTIC_ERROR = (E_BASE + 0xd);
constexpr int E_GRD_OVER_LIMIT = (E_BASE + 0xe);

constexpr int E_GRD_INVALID_ARGS = (E_BASE + 0xf);
constexpr int E_GRD_FAILED_FILE_OPERATION = (E_BASE + 0x10);
constexpr int E_GRD_CRC_CHECK_DISABLED = (E_BASE + 0x11);
constexpr int E_GRD_PERMISSION_DENIED = (E_BASE + 0x12);
constexpr int E_GRD_PASSWORD_UNMATCHED = (E_BASE + 0x13);
constexpr int E_GRD_PASSWORD_NEED_REKEY = (E_BASE + 0x14);
constexpr int E_GRD_WRONG_STMT_OBJECT = (E_BASE + 0x15);
constexpr int E_GRD_DATA_CONFLICT = (E_BASE + 0x16);
constexpr int E_GRD_INNER_ERR = (E_BASE + 0x17);
constexpr int E_GRD_FAILED_MEMORY_RELEASE = (E_BASE + 0x18);
constexpr int E_GRD_NOT_AVAILABLE = (E_BASE + 0x19);
constexpr int E_GRD_CIPHER_ERROR = (E_BASE + 0x1a);
constexpr int E_ARGS_READ_CON_OVERLOAD = (E_BASE + 0x1b);
constexpr int E_GRD_INVALID_FILE_FORMAT = (E_BASE + 0x1c);
constexpr int E_GRD_INVALID_BIND_VALUE = (E_BASE + 0x1d);
constexpr int E_GRD_DB_NOT_EXIST = (E_BASE + 0x1e);
constexpr int E_GRD_DATA_NOT_FOUND = (E_BASE + 0x1f);
constexpr int E_GRD_DATA_EXCEPTION = (E_BASE + 0x20);
constexpr int E_GRD_TRANSACTION_ROLLBACK = (E_BASE + 0x21);
constexpr int E_GRD_NO_ACTIVE_TRANSACTION = (E_BASE + 0x22);
constexpr int E_GRD_ACTIVE_TRANSACTION = (E_BASE + 0x23);

constexpr int E_ACQUIRE_CONN_FAILED = (E_BASE + 0x24);
constexpr int E_PREPARE_CHECK_FAILED = (E_BASE + 0x25);
constexpr int E_STEP_CHECK_FAILED = (E_BASE + 0x26);
constexpr int E_GETTED_COLNAME_EMPTY = (E_BASE + 0x27);
constexpr int E_PARSE_JSON_FAILED = (E_BASE + 0x28);
constexpr int E_INNER_ERROR = (E_BASE + 0x29);
constexpr int E_NO_DATA = (E_BASE + 0x2a);
constexpr int E_DBPATH_ACCESS_FAILED = (E_BASE + 0x2b);
constexpr int E_INIT_CONN_POOL_FAILED = (E_BASE + 0x2c);
constexpr int E_CONFIG_INVALID_CHANGE = (E_BASE + 0x2d);
constexpr int E_GRD_INVAILD_NAME_ERR = (E_BASE + 0x2e);
constexpr int E_CREATE_FOLDER_FAIT = (E_BASE + 0x3f);
constexpr int E_STATEMENT_EMPTY = (E_BASE + 0x30);
constexpr int E_STORE_HAS_CLOSED = (E_BASE + 0x31);
constexpr int E_GRD_NOT_SUPPORT = (E_BASE + 0x32);
} // namespace DistributedDataAip
} // namespace OHOS

#endif // OHOS_DISTRIBUTED_DATA_NATIVE_GDB_AIP_ERRORS_H