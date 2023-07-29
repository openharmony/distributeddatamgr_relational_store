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

#include <iostream>
#include <sstream>
#include <string>
#include <utility>

#include "logger.h"
#include "oh_cursor.h"
#include "relational_cursor.h"
#include "relational_store_error_code.h"
#include "rdb_errno.h"
#include "securec.h"

namespace OHOS {
namespace RdbNdk {
int RelationalCursor::GetColumnCount(OH_Cursor *cursor, int *count)
{
    auto self = GetSelf(cursor);
    if (self == nullptr || count == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->resultSet_->GetColumnCount(*count);
}

int RelationalCursor::GetColumnType(OH_Cursor *cursor, int32_t columnIndex, OH_ColumnType *columnType)
{
    auto self = GetSelf(cursor);
    if (self == nullptr || columnType == nullptr || columnIndex < 0) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    OHOS::NativeRdb::ColumnType type;
    int result = self->resultSet_->GetColumnType(columnIndex, type);
    *columnType = static_cast<OH_ColumnType>(static_cast<int>(type));
    return result;
}

int RelationalCursor::GetColumnIndex(OH_Cursor *cursor, const char *name, int *columnIndex)
{
    auto self = GetSelf(cursor);
    if (self == nullptr || name == nullptr || columnIndex == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->resultSet_->GetColumnIndex(name, *columnIndex);
}

int RelationalCursor::GetColumnName(OH_Cursor *cursor, int32_t columnIndex, char *name, int length)
{
    auto self = GetSelf(cursor);
    if (self == nullptr || name == nullptr || length <= 0) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    std::string str;
    int errCode = self->resultSet_->GetColumnName(columnIndex, str);
    if (errCode != OHOS::NativeRdb::E_OK) {
        return errCode;
    }
    errno_t result = memcpy_s(name, length, str.c_str(), str.length());
    if (result != EOK) {
        LOG_ERROR("memcpy_s failed, result is %{public}d", result);
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int RelationalCursor::GetRowCount(OH_Cursor *cursor, int *count)
{
    auto self = GetSelf(cursor);
    if (self == nullptr || count == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->resultSet_->GetRowCount(*count);
}

int RelationalCursor::GoToNextRow(OH_Cursor *cursor)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->resultSet_->GoToNextRow();
}

int RelationalCursor::GetSize(OH_Cursor *cursor, int32_t columnIndex, size_t *size)
{
    auto self = GetSelf(cursor);
    if (self == nullptr || size == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->resultSet_->GetSize(columnIndex, *size);
}

int RelationalCursor::GetText(OH_Cursor *cursor, int32_t columnIndex, char *value, int length)
{
    auto self = GetSelf(cursor);
    if (self == nullptr || value == nullptr || length <= 0) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    std::string str;
    int errCode = self->resultSet_->GetString(columnIndex, str);
    if (errCode != OHOS::NativeRdb::E_OK) {
        return errCode;
    }
    errno_t result = memcpy_s(value, length, str.c_str(), str.length());
    if (result != EOK) {
        LOG_ERROR("memcpy_s failed, result is %{public}d", result);
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int RelationalCursor::GetInt64(OH_Cursor *cursor, int32_t columnIndex, int64_t *value)
{
    auto self = GetSelf(cursor);
    if (self == nullptr || value == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->resultSet_->GetLong(columnIndex, *value);
}

int RelationalCursor::GetReal(OH_Cursor *cursor, int32_t columnIndex, double *value)
{
    auto self = GetSelf(cursor);
    if (self == nullptr || value == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->resultSet_->GetDouble(columnIndex, *value);
}

int RelationalCursor::GetBlob(OH_Cursor *cursor, int32_t columnIndex, unsigned char *value, int length)
{
    auto self = GetSelf(cursor);
    if (self == nullptr || value == nullptr || length <= 0) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    std::vector<uint8_t> vec;
    int errCode = self->resultSet_->GetBlob(columnIndex, vec);
    if (errCode != OHOS::NativeRdb::E_OK) {
        return errCode;
    }
    errno_t result = memcpy_s(value, length, vec.data(), vec.size());
    if (result != EOK) {
        LOG_ERROR("memcpy_s failed, result is %{public}d", result);
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int RelationalCursor::IsNull(OH_Cursor *cursor, int32_t columnIndex, bool *isNull)
{
    auto self = GetSelf(cursor);
    if (self == nullptr || isNull == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->resultSet_->IsColumnNull(columnIndex, *isNull);
}

int RelationalCursor::Destroy(OH_Cursor *cursor)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    int errCode = self->resultSet_->Close();
    if (errCode != OHOS::NativeRdb::E_OK) {
        return errCode;
    }
    delete self;
    return errCode;
}

RelationalCursor::RelationalCursor(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet)
    : resultSet_(std::move(resultSet))
{
    id = RDB_CURSOR_CID;

    getColumnCount = GetColumnCount;
    getColumnType = GetColumnType;
    getColumnIndex = GetColumnIndex;
    getColumnName = GetColumnName;
    getRowCount = GetRowCount;
    goToNextRow = GoToNextRow;
    getSize = GetSize;
    getText = GetText;
    getInt64 = GetInt64;
    getReal = GetReal;
    getBlob = GetBlob;
    isNull = IsNull;
    destroy = Destroy;
}

RelationalCursor *RelationalCursor::GetSelf(OH_Cursor *cursor)
{
    if (cursor == nullptr || cursor->id != OHOS::RdbNdk::RDB_CURSOR_CID) {
        LOG_ERROR("cursor invalid. is null %{public}d", (cursor == nullptr));
        return nullptr;
    }
    return static_cast<OHOS::RdbNdk::RelationalCursor *>(cursor);
}
} // namespace RdbNdk
} // namespace OHOS