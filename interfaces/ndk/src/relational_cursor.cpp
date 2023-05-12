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

#include "relational_cursor.h"
#include "relational_cursor_impl.h"
#include "relational_error_code.h"
#include "rdb_errno.h"
#include "securec.h"

OHOS::NativeRdb::CursorImpl::CursorImpl(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet)
{
    id = RDB_CURSOR_CID;
    resultSet_ = resultSet;

    OH_Cursor_GetColumnCount = CURSOR_GetColumnCount;
    OH_Cursor_GetColumnType = CURSOR_GetColumnType;
    OH_Cursor_GetColumnIndex = CURSOR_GetColumnIndex;
    OH_Cursor_GetColumnName = CURSOR_GetColumnName;
    OH_Cursor_GetRowCount = CURSOR_GetRowCount;
    OH_Cursor_GoToNextRow = CURSOR_GoToNextRow;
    OH_Cursor_GetSize = CURSOR_GetSize;
    OH_Cursor_GetText = CURSOR_GetText;
    OH_Cursor_GetInt64 = CURSOR_GetInt64;
    OH_Cursor_GetReal = CURSOR_GetReal;
    OH_Cursor_GetBlob = CURSOR_GetBlob;
    OH_Cursor_IsNull = CURSOR_IsNull;
    OH_Cursor_Close = CURSOR_Close;
}

std::shared_ptr<OHOS::NativeRdb::ResultSet> OHOS::NativeRdb::CursorImpl::GetResultSet()
{
    return resultSet_;
}

int CURSOR_GetColumnCount(OH_Cursor *cursor, int *count)
{
    if (cursor == nullptr || count == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    return tempCursor->GetResultSet()->GetColumnCount(*count);
}

int CURSOR_GetColumnType(OH_Cursor *cursor, int32_t columnIndex, OH_Rdb_ColumnType *columnType)
{
    if (cursor == nullptr || columnType == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    OHOS::NativeRdb::ColumnType type;
    int error = tempCursor->GetResultSet()->GetColumnType(columnIndex, type);
    *columnType = static_cast<OH_Rdb_ColumnType>(static_cast<int>(type));
    return error;
}

int CURSOR_GetColumnIndex(OH_Cursor *cursor, const char *name, int *columnIndex)
{
    if (cursor == nullptr || name == nullptr || columnIndex == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    return tempCursor->GetResultSet()->GetColumnIndex(name, *columnIndex);
}

int CURSOR_GetColumnName(OH_Cursor *cursor, int32_t columnIndex, char *name, int length)
{
    if (cursor == nullptr || name == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    std::string str;
    int errCode = tempCursor->GetResultSet()->GetColumnName(columnIndex, str);
    if (errCode != OHOS::NativeRdb::E_OK) {
        return errCode;
    }
    errno_t result = memcpy_s(name, length, str.c_str(), str.length());
    if (result != EOK) {
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    return errCode;
}

int CURSOR_GetRowCount(OH_Cursor *cursor, int *count)
{
    if (cursor == nullptr || count == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    return tempCursor->GetResultSet()->GetRowCount(*count);
}

int CURSOR_GoToNextRow(OH_Cursor *cursor)
{
    if (cursor == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    return tempCursor->GetResultSet()->GoToNextRow();
}

int CURSOR_GetSize(OH_Cursor *cursor, int32_t columnIndex, size_t *size)
{
    if (cursor == nullptr || size == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    return tempCursor->GetResultSet()->GetSize(columnIndex, *size);
}

int CURSOR_GetText(OH_Cursor *cursor, int32_t columnIndex, char *value, int length)
{
    if (cursor == nullptr || value == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    std::string str;
    int errCode = tempCursor->GetResultSet()->GetString(columnIndex, str);
    if (errCode != OHOS::NativeRdb::E_OK) {
        return errCode;
    }
    errno_t result = memcpy_s(value, length, str.c_str(), str.length());
    if (result != EOK) {
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    return errCode;
}

int CURSOR_GetInt64(OH_Cursor *cursor, int32_t columnIndex, int64_t *value)
{
    if (cursor == nullptr || value == nullptr ||cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    return tempCursor->GetResultSet()->GetLong(columnIndex, *value);
}

int CURSOR_GetReal(OH_Cursor *cursor, int32_t columnIndex, double *value)
{
    if (cursor == nullptr || value == nullptr ||cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    return tempCursor->GetResultSet()->GetDouble(columnIndex, *value);
}

int CURSOR_GetBlob(OH_Cursor *cursor, int32_t columnIndex, unsigned char *value, int length)
{
    if (cursor == nullptr || value == nullptr ||cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    std::vector<uint8_t> vec;
    int errCode = tempCursor->GetResultSet()->GetBlob(columnIndex, vec);
    if (errCode != OHOS::NativeRdb::E_OK) {
        return errCode;
    }
    errno_t result = memcpy_s(value, length, vec.data(), vec.size());
    if (result != EOK) {
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    return errCode;
}

int CURSOR_IsNull(OH_Cursor *cursor, int32_t columnIndex, bool *isNull)
{
    if (cursor == nullptr || isNull == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    return tempCursor->GetResultSet()->IsColumnNull(columnIndex, *isNull);
}

int CURSOR_Close(OH_Cursor *cursor)
{
    if (cursor == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return OH_Rdb_ErrCode::RDB_ERR_INVALID_ARGS;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    int errCode = tempCursor->GetResultSet()->Close();
    if (errCode != OHOS::NativeRdb::E_OK) {
        return errCode;
    }
    delete tempCursor;
    return errCode;
}
