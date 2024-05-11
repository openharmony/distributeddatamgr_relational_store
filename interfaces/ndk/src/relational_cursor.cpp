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
#define LOG_TAG "RelationalCursor"
#include "relational_cursor.h"

#include <string>

#include "logger.h"
#include "oh_cursor.h"
#include "rdb_errno.h"
#include "relational_asset.h"
#include "relational_store_error_code.h"
#include "securec.h"
#include "convertor_error_code.h"

namespace OHOS {
namespace RdbNdk {
int RelationalCursor::GetColumnCount(OH_Cursor *cursor, int *count)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->GetColumnCount(count);
}

int RelationalCursor::GetColumnType(OH_Cursor *cursor, int32_t columnIndex, OH_ColumnType *columnType)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->GetColumnType(columnIndex, columnType);
}

int RelationalCursor::GetColumnIndex(OH_Cursor *cursor, const char *name, int *columnIndex)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->GetColumnIndex(name, columnIndex);
}

int RelationalCursor::GetColumnName(OH_Cursor *cursor, int32_t columnIndex, char *name, int length)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->GetColumnName(columnIndex, name, length);
}

int RelationalCursor::GetRowCount(OH_Cursor *cursor, int *count)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->GetRowCount(count);
}

int RelationalCursor::GoToNextRow(OH_Cursor *cursor)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->GoToNextRow();
}

int RelationalCursor::GetSize(OH_Cursor *cursor, int32_t columnIndex, size_t *size)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->GetSize(columnIndex, size);
}

int RelationalCursor::GetText(OH_Cursor *cursor, int32_t columnIndex, char *value, int length)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->GetText(columnIndex, value, length);
}

int RelationalCursor::GetInt64(OH_Cursor *cursor, int32_t columnIndex, int64_t *value)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->GetInt64(columnIndex, value);
}

int RelationalCursor::GetReal(OH_Cursor *cursor, int32_t columnIndex, double *value)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->GetReal(columnIndex, value);
}

int RelationalCursor::GetBlob(OH_Cursor *cursor, int32_t columnIndex, unsigned char *value, int length)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->GetBlob(columnIndex, value, length);
}

int RelationalCursor::GetAsset(OH_Cursor *cursor, int32_t columnIndex, Data_Asset *value)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->GetAsset(columnIndex, value);
}

int RelationalCursor::GetAssets(OH_Cursor *cursor, int32_t columnIndex, Data_Asset **value, uint32_t *length)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->GetAssets(columnIndex, value, length);
}

int RelationalCursor::IsNull(OH_Cursor *cursor, int32_t columnIndex, bool *isNull)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->IsNull(columnIndex, isNull);
}


int RelationalCursor::GetAssetsCount(OH_Cursor *cursor, int32_t columnIndex, uint32_t *count)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return self->GetAssetsCount(columnIndex, count);
}

int RelationalCursor::Destroy(OH_Cursor *cursor)
{
    auto self = GetSelf(cursor);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    int errCode = self->Destroy();
    if (errCode != NativeRdb::E_OK) {
        return errCode;
    }
    delete self;
    return errCode;
}

RelationalCursor::RelationalCursor(std::shared_ptr<NativeRdb::ResultSet> resultSet)
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
    getAsset = GetAsset;
    getAssets = GetAssets;
    getAssetsCount = GetAssetsCount;
}

RelationalCursor *RelationalCursor::GetSelf(OH_Cursor *cursor)
{
    if (cursor == nullptr || cursor->id != RdbNdk::RDB_CURSOR_CID) {
        LOG_ERROR("cursor invalid. is null %{public}d", (cursor == nullptr));
        return nullptr;
    }
    return static_cast<RdbNdk::RelationalCursor *>(cursor);
}

int RelationalCursor::GetColumnCount(int *count)
{
    if (count == nullptr || resultSet_ == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(resultSet_->GetColumnCount(*count));
}

int RelationalCursor::GetColumnType(int32_t columnIndex, OH_ColumnType *columnType)
{
    if (columnType == nullptr || columnIndex < 0 || resultSet_ == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    NativeRdb::ColumnType type;
    int result = resultSet_->GetColumnType(columnIndex, type);
    *columnType = static_cast<OH_ColumnType>(static_cast<int>(type));
    return ConvertorErrorCode::NativeToNdk(result);
}

int RelationalCursor::GetColumnIndex(const char *name, int *columnIndex)
{
    if (name == nullptr || columnIndex == nullptr || resultSet_ == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(resultSet_->GetColumnIndex(name, *columnIndex));
}

int RelationalCursor::GetColumnName(int32_t columnIndex, char *name, int length)
{
    if (name == nullptr || length <= 0 || resultSet_ == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    std::string str;
    int errCode = resultSet_->GetColumnName(columnIndex, str);
    if (errCode != NativeRdb::E_OK) {
        return ConvertorErrorCode::NativeToNdk(errCode);
    }
    errno_t result = strcpy_s(name, length, str.c_str());
    if (result != EOK) {
        LOG_ERROR("strcpy_s failed, result is %{public}d", result);
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int RelationalCursor::GetRowCount(int *count)
{
    if (count == nullptr || resultSet_ == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(resultSet_->GetRowCount(*count));
}

int RelationalCursor::GoToNextRow()
{
    if (resultSet_ == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(resultSet_->GoToNextRow());
}

int RelationalCursor::GetSize(int32_t columnIndex, size_t *size)
{
    if (size == nullptr || resultSet_ == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(resultSet_->GetSize(columnIndex, *size));
}

int RelationalCursor::GetText(int32_t columnIndex, char *value, int length)
{
    if (value == nullptr || length <= 0 || resultSet_ == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    std::string str;
    int errCode = resultSet_->GetString(columnIndex, str);
    if (errCode != NativeRdb::E_OK) {
        return ConvertorErrorCode::NativeToNdk(errCode);
    }
    errno_t result = strcpy_s(value, length, str.c_str());
    if (result != EOK) {
        LOG_ERROR("strcpy_s failed, result is %{public}d", result);
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int RelationalCursor::GetInt64(int32_t columnIndex, int64_t *value)
{
    if (value == nullptr || resultSet_ == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(resultSet_->GetLong(columnIndex, *value));
}

int RelationalCursor::GetReal(int32_t columnIndex, double *value)
{
    if (value == nullptr || resultSet_ == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(resultSet_->GetDouble(columnIndex, *value));
}

int RelationalCursor::GetBlob(int32_t columnIndex, unsigned char *value, int length)
{
    if (value == nullptr || length <= 0 || resultSet_ == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    std::vector<uint8_t> vec;
    int errCode = resultSet_->GetBlob(columnIndex, vec);
    if (errCode != NativeRdb::E_OK) {
        return ConvertorErrorCode::NativeToNdk(errCode);
    }
    errno_t result = memcpy_s(value, length, vec.data(), vec.size());
    if (result != EOK) {
        LOG_ERROR("memcpy_s failed, result is %{public}d", result);
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int RelationalCursor::GetAsset(int32_t columnIndex, Data_Asset *value)
{
    if (resultSet_ == nullptr || value == nullptr || columnIndex < 0 || value->cid != DATA_ASSET_V0) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    NativeRdb::AssetValue asset;
    auto errCode = resultSet_->GetAsset(columnIndex, asset);
    if (errCode != NativeRdb::E_OK) {
        return ConvertorErrorCode::NativeToNdk(errCode);
    }
    value->cid = DATA_ASSET_V0;
    value->asset_ = asset;
    return ConvertorErrorCode::NativeToNdk(errCode);
}

int RelationalCursor::GetAssets(int32_t columnIndex, Data_Asset **value, uint32_t *length)
{
    if (resultSet_ == nullptr || length == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    std::vector<NativeRdb::AssetValue> assets;
    auto errCode = resultSet_->GetAssets(columnIndex, assets);
    if (errCode != NativeRdb::E_OK) {
        return ConvertorErrorCode::NativeToNdk(errCode);
    }
    uint32_t inputLength = *length;
    *length = assets.size();
    if (value == nullptr) {
        return OH_Rdb_ErrCode::RDB_OK;
    }
    if (*length != inputLength) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    for (uint32_t i = 0; i < *length; ++i) {
        if (value[i] == nullptr || value[i]->cid != DATA_ASSET_V0) {
            return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
        }
        value[i]->cid = DATA_ASSET_V0;
        value[i]->asset_ = assets[i];
    }
    return ConvertorErrorCode::NativeToNdk(errCode);
}

int RelationalCursor::IsNull(int32_t columnIndex, bool *isNull)
{
    if (isNull == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(resultSet_->IsColumnNull(columnIndex, *isNull));
}

int RelationalCursor::Destroy()
{
    if (resultSet_ == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    return ConvertorErrorCode::NativeToNdk(resultSet_->Close());
}

int RelationalCursor::GetAssetsCount(int32_t columnIndex, uint32_t *count)
{
    if (count == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    std::vector<NativeRdb::AssetValue> assets;
    auto errCode = resultSet_->GetAssets(columnIndex, assets);
    if (errCode != NativeRdb::E_OK) {
        return ConvertorErrorCode::NativeToNdk(errCode);
    }
    *count = assets.size();
    return OH_Rdb_ErrCode::RDB_OK;
}

} // namespace RdbNdk
} // namespace OHOS
