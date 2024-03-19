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
#define LOG_TAG "ModifyTimeCursor"
#include "modify_time_cursor.h"
#include "logger.h"
#include "relational_store_error_code.h"
#include "securec.h"
#include "traits.h"
namespace OHOS::RdbNdk {
ModifyTimeCursor::ModifyTimeCursor(ModifyTimeCursor::ModifyTime &&modifyTime)
    : RelationalCursor(modifyTime), modifyTime_(std::move(modifyTime))
{
}

int ModifyTimeCursor::GetSize(int32_t columnIndex, size_t *size)
{
    if (size == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    if (columnIndex == 0 && modifyTime_.NeedConvert()) {
        *size = modifyTime_.GetMaxOriginKeySize();
        return OH_Rdb_ErrCode::RDB_OK;
    }
    return RelationalCursor::GetSize(columnIndex, size);
}

int ModifyTimeCursor::GetText(int32_t columnIndex, char *value, int length)
{
    if (value == nullptr || length <= 0) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    if (columnIndex == 0 && modifyTime_.NeedConvert()) {
        auto priKey = ConvertPRIKey();
        auto *val = Traits::get_if<std::string>(&priKey);
        if (val == nullptr) {
            return OH_Rdb_ErrCode::RDB_ERR;
        }
        errno_t result = strcpy_s(value, length, val->data());
        if (result != EOK) {
            LOG_ERROR("strcpy_s failed, result is %{public}d", result);
            return OH_Rdb_ErrCode::RDB_ERR;
        }
        return OH_Rdb_ErrCode::RDB_OK;
    }
    return RelationalCursor::GetText(columnIndex, value, length);
}

int ModifyTimeCursor::GetInt64(int32_t columnIndex, int64_t *value)
{
    if (value == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    if (columnIndex == 0 && modifyTime_.NeedConvert()) {
        auto priKey = ConvertPRIKey();
        auto *val = Traits::get_if<int64_t>(&priKey);
        if (val == nullptr) {
            return OH_Rdb_ErrCode::RDB_ERR;
        }
        *value = *val;
        return OH_Rdb_ErrCode::RDB_OK;
    }
    return RelationalCursor::GetInt64(columnIndex, value);
}

int ModifyTimeCursor::GetReal(int32_t columnIndex, double *value)
{
    if (columnIndex == 0 && modifyTime_.NeedConvert()) {
        auto priKey = ConvertPRIKey();
        auto *val = Traits::get_if<double>(&priKey);
        if (val == nullptr) {
            return OH_Rdb_ErrCode::RDB_ERR;
        }
        *value = *val;
        return OH_Rdb_ErrCode::RDB_OK;
    }
    return RelationalCursor::GetReal(columnIndex, value);
}
} // namespace OHOS::RdbNdk
