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
#ifndef DISTRIBUTEDDATAMGR_RDB_DFX_ERRNO_H
#define DISTRIBUTEDDATAMGR_RDB_DFX_ERRNO_H
#include <errors.h>
namespace OHOS {
namespace NativeRdb {

/**
* @brief The base code of the exception dfx error code, base value is 0x1A28000.
*/
constexpr int E_DFX_BASE = ErrCodeOffset(SUBSYS_DISTRIBUTEDDATAMNG, 2) + 0x8000;

/**
 * @brief Database db err message is not create.
 */
static constexpr int E_DFX_IS_NOT_CREATE = (E_DFX_BASE + 0x1);

/**
 * @brief Database db err message is delete.
 */
static constexpr int E_DFX_IS_DELETE = (E_DFX_BASE + 0x2);

/**
 * @brief Database db err message is rename.
 */
static constexpr int E_DFX_IS_RENAME = (E_DFX_BASE + 0x3);

/**
 * @brief Database db err message is not exist.
 */
static constexpr int E_DFX_IS_NOT_EXIST = (E_DFX_BASE + 0x4);

/**
 * @brief Only use for dfx, sqlite error log.
 */
static constexpr int E_DFX_SQLITE_LOG = (E_DFX_BASE + 0x5);

/**
 * @brief Only use for dfx, batch insert args size too big.
 */
static constexpr int E_DFX_BATCH_INSERT_ARGS_SIZE = (E_DFX_BASE + 0x6);

/**
 * @brief Only use for dfx, get journal mode fail.
 */
static constexpr int E_DFX_GET_JOURNAL_FAIL = (E_DFX_BASE + 0x7);

/**
 * @brief Only use for dfx, set journal mode fail.
 */
static constexpr int E_DFX_SET_JOURNAL_FAIL = (E_DFX_BASE + 0x8);

/**
 * @brief Only use for dfx, print dump info.
 */
static constexpr int E_DFX_DUMP_INFO = (E_DFX_BASE + 0x9);

/**
 * @brief Only use for dfx, print group id info.
 */
static constexpr int E_DFX_GROUPID_INFO = (E_DFX_BASE + 0xA);

/**
 * @brief Only use for dfx, print dump huks gen random failed.
 */
static constexpr int E_DFX_HUKS_GEN_RANDOM_FAIL = (E_DFX_BASE + 0xB);

/**
 * @brief Only use for dfx, print key upgrade failed.
 */
static constexpr int E_DFX_UPGRADE_KEY_FAIL = (E_DFX_BASE + 0xC);

/**
 * @brief Only use for dfx, print key file hmac failed.
 */
static constexpr int E_DFX_HMAC_KEY_FAIL = (E_DFX_BASE + 0xD);

/**
 * @brief Only use for dfx, print binlog relpay timeout.
 */
static constexpr int E_DFX_REPLAY_TIMEOUT_FAIL = (E_DFX_BASE + 0xE);

/**
 * @brief Only use for dfx, print visitor database verify.
 */
static constexpr int E_DFX_VISITOR_VERIFY_FAULT = (E_DFX_BASE + 0xF);

/**
 * @brief Only use for dfx, valueobject valueless_by_exception.
 */
static constexpr int E_DFX_VALUELESS_BY_EXCEPTION = (E_DFX_BASE + 0x11);

/**
 * @brief Only use for dfx, valueobject type index out of range.
 */
static constexpr int E_DFX_TYPE_INDEX_OUT_OF_RANGE = (E_DFX_BASE + 0x12);

} // namespace NativeRdb
} // namespace OHOS

#endif // DISTRIBUTEDDATAMGR_RDB_DFX_ERRNO_H