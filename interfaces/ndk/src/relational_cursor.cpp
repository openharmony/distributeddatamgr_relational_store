/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

    getColumnCount = CURSOR_GetColumnCount;
    getColumnType = CURSOR_GetColumnType;
    getColumnIndex = CURSOR_GetColumnIndex;
    getColumnName = CURSOR_GetColumnName;
    getRowCount = CURSOR_GetRowCount;
    goToNextRow = CURSOR_GoToNextRow;
    getSize = CURSOR_GetSize;
    getText = CURSOR_GetText;
    getInt64 = CURSOR_GetInt64;
    getReal = CURSOR_GetReal;
    getBlob = CURSOR_GetBlob;
    isNull = CURSOR_IsNull;
    close = CURSOR_Close;
}

std::shared_ptr<OHOS::NativeRdb::ResultSet> OHOS::NativeRdb::CursorImpl::GetResultSet()
{
    return resultSet_;
}

int CURSOR_GetColumnCount(OH_Cursor *cursor, int *count)
{
    if (cursor == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    return tempCursor->GetResultSet()->GetColumnCount(*count);
}

int CURSOR_GetColumnType(OH_Cursor *cursor, int32_t columnIndex, ColumnType *columnType)
{
    if (cursor == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    OHOS::NativeRdb::ColumnType type;
    int error = tempCursor->GetResultSet()->GetColumnType(columnIndex, type);
    *columnType = ColumnType((int)type);
    return error;
}

int CURSOR_GetColumnIndex(OH_Cursor *cursor, const char *names, int *columnIndex)
{
    if (cursor == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    return tempCursor->GetResultSet()->GetColumnIndex(names, *columnIndex);
}

int CURSOR_GetColumnName(OH_Cursor *cursor, int32_t columnIndex, char *name, int length)
{
    if (cursor == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    std::string str;
    int errCode = tempCursor->GetResultSet()->GetColumnName(columnIndex, str);
    if (errCode != OHOS::NativeRdb::E_OK) {
        return errCode;
    }
    if (str.length() > length) {
        return E_LENGTH_ERROR;
    }
    memcpy_s(name, length, str.c_str(), str.length());
    return errCode;
}

int CURSOR_GetRowCount(OH_Cursor *cursor, int *count)
{
    if (cursor == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    return tempCursor->GetResultSet()->GetRowCount(*count);
}

int CURSOR_GoToNextRow(OH_Cursor *cursor)
{
    if (cursor == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    return tempCursor->GetResultSet()->GoToNextRow();
}

int CURSOR_GetSize(OH_Cursor *cursor, int32_t columnIndex, size_t *size)
{
    if (cursor == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    return tempCursor->GetResultSet()->GetSize(columnIndex, *size);
}

int CURSOR_GetText(OH_Cursor *cursor, int32_t columnIndex, char *value, int length)
{
    if (cursor == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    std::string str;
    int errCode = tempCursor->GetResultSet()->GetString(columnIndex, str);
    if (errCode != OHOS::NativeRdb::E_OK) {
        return errCode;
    }
    if (str.size() > length) {
        return E_LENGTH_ERROR;
    }
    memcpy_s(value, length, str.c_str(), str.length());
    return errCode;
}

int CURSOR_GetInt64(OH_Cursor *cursor, int32_t columnIndex, int64_t *value)
{
    if (cursor == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    int errCode = tempCursor->GetResultSet()->GetLong(columnIndex, *value);
    return errCode;
}

int CURSOR_GetReal(OH_Cursor *cursor, int32_t columnIndex, double *value)
{
    if (cursor == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    return tempCursor->GetResultSet()->GetDouble(columnIndex, *value);
}

int CURSOR_GetBlob(OH_Cursor *cursor, int32_t columnIndex, unsigned char *value, int length)
{
    if (cursor == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    std::vector<uint8_t> vec;
    int errCode = tempCursor->GetResultSet()->GetBlob(columnIndex, vec);
    if (errCode != OHOS::NativeRdb::E_OK) {
        return errCode;
    }
    if (vec.size() > length) {
        return E_LENGTH_ERROR;
    }
    memcpy_s(value, length, vec.data(), vec.size());
    return errCode;
}

int CURSOR_IsNull(OH_Cursor *cursor, int32_t columnIndex, bool *isNull)
{
    if (cursor == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    return tempCursor->GetResultSet()->IsColumnNull(columnIndex, *isNull);
}

int CURSOR_Close(OH_Cursor *cursor)
{
    if (cursor == nullptr || cursor->id != OHOS::NativeRdb::RDB_CURSOR_CID) {
        return E_INVALID_ARG;
    }
    OHOS::NativeRdb::CursorImpl *tempCursor = static_cast<OHOS::NativeRdb::CursorImpl *>(cursor);
    int errCode = tempCursor->GetResultSet()->Close();
    if (errCode != OHOS::NativeRdb::E_OK) {
        return errCode;
    }
    delete tempCursor;
    return errCode;
}
