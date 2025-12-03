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
#define LOG_TAG "SharedBlockSerializerInfo"
#include "shared_block_serializer_info.h"

#include "logger.h"
#include "sqlite_utils.h"
#include "string_utils.h"
#include "value_object.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

SharedBlockSerializerInfo::SharedBlockSerializerInfo(
    AppDataFwk::AbsSharedBlock *sharedBlock, sqlite3_stmt *stat, int numColumns, int startPos)
    : sharedBlock_(sharedBlock), statement_(stat), anumColumns(numColumns), atotalRows(0), astartPos(startPos),
      raddedRows(0)
{
}

SharedBlockSerializerInfo::~SharedBlockSerializerInfo() {}

int SharedBlockSerializerInfo::AddRow(int addedRows)
{
    // Allocate a new field directory for the row.
    int status = sharedBlock_->AllocRow();
    if (status == AppDataFwk::SharedBlock::SHARED_BLOCK_OK) {
        raddedRows = addedRows + 1;
        return SQLITE_OK;
    }
    if (status == AppDataFwk::SharedBlock::SHARED_BLOCK_NO_MEMORY) {
        isFull = true;
    }
    return SQLITE_FULL;
}

int SharedBlockSerializerInfo::Reset(int startPos)
{
    int status = sharedBlock_->Clear();
    if (status != AppDataFwk::SharedBlock::SHARED_BLOCK_OK) {
        LOG_ERROR("SharedBlockSerializerInfo::Reset() Failed in Clear(), error=%{public}d.", status);
        return SQLITE_ERROR;
    }
    status = sharedBlock_->SetColumnNum(anumColumns);
    if (status != AppDataFwk::SharedBlock::SHARED_BLOCK_OK) {
        LOG_ERROR("SharedBlockSerializerInfo::Reset() Failed in SetColumnNum(), error=%{public}d.", status);
        return SQLITE_ERROR;
    }
    astartPos = startPos;
    raddedRows = 0;
    isFull = false;
    return SQLITE_OK;
}

int SharedBlockSerializerInfo::Finish(int addedRows, int totalRows)
{
    raddedRows = addedRows;
    atotalRows = totalRows;
    return SQLITE_OK;
}

int SharedBlockSerializerInfo::PutLong(int row, int column, sqlite3_int64 value)
{
    int status = sharedBlock_->PutLong(row, column, value);
    if (status == AppDataFwk::SharedBlock::SHARED_BLOCK_OK) {
        return SQLITE_OK;
    }
    if (status == AppDataFwk::SharedBlock::SHARED_BLOCK_NO_MEMORY) {
        isFull = true;
    }
    sharedBlock_->FreeLastRow();
    return SQLITE_FULL;
}

int SharedBlockSerializerInfo::PutDouble(int row, int column, double value)
{
    int status = sharedBlock_->PutDouble(row, column, value);
    if (status == AppDataFwk::SharedBlock::SHARED_BLOCK_OK) {
        return SQLITE_OK;
    }
    if (status == AppDataFwk::SharedBlock::SHARED_BLOCK_NO_MEMORY) {
        isFull = true;
    }
    sharedBlock_->FreeLastRow();
    return SQLITE_FULL;
}

int SharedBlockSerializerInfo::PutBlob(int row, int column, const void *blob, int len)
{
    auto action = &AppDataFwk::AbsSharedBlock::PutBlob;
    auto *declType = sqlite3_column_decltype(statement_, column);
    if (declType != nullptr) {
        auto type = StringUtils::TruncateAfterFirstParen(SqliteUtils::StrToUpper(declType));
        action = (type == ValueObject::DeclType<ValueObject::Asset>())         ? &AppDataFwk::AbsSharedBlock::PutAsset
                 : (type == ValueObject::DeclType<ValueObject::Assets>())      ? &AppDataFwk::AbsSharedBlock::PutAssets
                 : (type == ValueObject::DeclType<ValueObject::FloatVector>()) ? &AppDataFwk::AbsSharedBlock::PutFloats
                 : (type == ValueObject::DeclType<ValueObject::BigInt>())      ? &AppDataFwk::AbsSharedBlock::PutBigInt
                                                                               : &AppDataFwk::AbsSharedBlock::PutBlob;
    }

    int status = (sharedBlock_->*action)(row, column, blob, len);
    if (status == AppDataFwk::SharedBlock::SHARED_BLOCK_OK) {
        return SQLITE_OK;
    }
    if (status == AppDataFwk::SharedBlock::SHARED_BLOCK_NO_MEMORY) {
        isFull = true;
    }
    sharedBlock_->FreeLastRow();
    return SQLITE_FULL;
}

int SharedBlockSerializerInfo::PutNull(int row, int column)
{
    int status = sharedBlock_->PutNull(row, column);
    if (status == AppDataFwk::SharedBlock::SHARED_BLOCK_OK) {
        return SQLITE_OK;
    }
    if (status == AppDataFwk::SharedBlock::SHARED_BLOCK_NO_MEMORY) {
        isFull = true;
    }
    sharedBlock_->FreeLastRow();
    LOG_ERROR("Failed allocating space for a null in column %{public}d, error=%{public}d", column, status);
    return SQLITE_FULL;
}

int SharedBlockSerializerInfo::PutOther(int row, int column)
{
    sharedBlock_->FreeLastRow();
    return SQLITE_ERROR;
}
} // namespace NativeRdb
} // namespace OHOS