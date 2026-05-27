/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <cstdlib>

#include "cj_lambda.h"
#include "napi_rdb_js_utils.h"
#include "rdb_errno.h"
#include "relational_store_impl_resultsetproxy.h"
#include "relational_store_utils.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Relational {
extern "C" {
FFI_EXPORT CArrStr FfiOHOSRelationalStoreGetAllColumnNames(int64_t id)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        return CArrStr{ nullptr, 0 };
    }
    return nativeResultSet->GetAllColumnNames();
}

FFI_EXPORT CArrStr FfiOHOSRelationalStoreResultSetGetColumnNames(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return CArrStr{ nullptr, 0 };
    }
    return nativeResultSet->GetWholeColumnNames(errCode);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreGetColumnCount(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeResultSet->GetColumnCount();
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreGetRowCount(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeResultSet->GetRowCount();
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreGetRowIndex(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeResultSet->GetRowIndex();
}

FFI_EXPORT bool FfiOHOSRelationalStoreIsAtFirstRow(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return false;
    }
    *errCode = 0;
    return nativeResultSet->IsAtFirstRow();
}

FFI_EXPORT bool FfiOHOSRelationalStoreIsAtLastRow(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return false;
    }
    *errCode = 0;
    return nativeResultSet->IsAtLastRow();
}

FFI_EXPORT bool FfiOHOSRelationalStoreIsEnded(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return false;
    }
    *errCode = 0;
    return nativeResultSet->IsEnded();
}

FFI_EXPORT bool FfiOHOSRelationalStoreIsStarted(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return false;
    }
    *errCode = 0;
    return nativeResultSet->IsStarted();
}

FFI_EXPORT bool FfiOHOSRelationalStoreIsClosed(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return false;
    }
    *errCode = 0;
    return nativeResultSet->IsClosed();
}

FFI_EXPORT double FfiOHOSRelationalStoreGetDouble(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return -1;
    }
    return nativeResultSet->GetDouble(columnIndex, rtnCode);
}

FFI_EXPORT bool FfiOHOSRelationalStoreGoToRow(int64_t id, int32_t position, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoToRow(position, rtnCode);
}

FFI_EXPORT bool FfiOHOSRelationalStoreGoToPreviousRow(int64_t id, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoToPreviousRow(rtnCode);
}

FFI_EXPORT bool FfiOHOSRelationalStoreGoToLastRow(int64_t id, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoToLastRow(rtnCode);
}

FFI_EXPORT char *FfiOHOSRelationalStoreGetColumnName(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return nullptr;
    }
    return nativeResultSet->GetColumnName(columnIndex, rtnCode);
}

FFI_EXPORT bool FfiOHOSRelationalStoreIsColumnNull(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->IsColumnNull(columnIndex, rtnCode);
}

FFI_EXPORT Asset FfiOHOSRelationalStoreGetAsset(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return Asset{ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, 0 };
    }
    return nativeResultSet->GetAsset(columnIndex, rtnCode);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreClose(int64_t id)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        return -1;
    }
    return nativeResultSet->Close();
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreGetColumnIndex(int64_t id, char *columnName, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr || columnName == nullptr) {
        *rtnCode = -1;
        return -1;
    }
    return nativeResultSet->GetColumnIndex(columnName, rtnCode);
}

FFI_EXPORT char *FfiOHOSRelationalStoreGetString(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return nullptr;
    }
    return nativeResultSet->GetString(columnIndex, rtnCode);
}

FFI_EXPORT bool FfiOHOSRelationalStoreGoToFirstRow(int64_t id, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoToFirstRow(rtnCode);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreGetLong(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return -1;
    }
    return nativeResultSet->GetLong(columnIndex, rtnCode);
}

FFI_EXPORT bool FfiOHOSRelationalStoreGoToNextRow(int64_t id, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoToNextRow(rtnCode);
}

FFI_EXPORT CArrUI8 FfiOHOSRelationalStoreGetBlob(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return CArrUI8{ nullptr, 0 };
    }
    return nativeResultSet->GetBlob(columnIndex, rtnCode);
}

FFI_EXPORT bool FfiOHOSRelationalStoreGoTo(int64_t id, int32_t offset, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoTo(offset, rtnCode);
}

FFI_EXPORT Assets FfiOHOSRelationalStoreGetAssets(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return Assets{ nullptr, 0 };
    }
    return nativeResultSet->GetAssets(columnIndex, rtnCode);
}

FFI_EXPORT ValuesBucket FfiOHOSRelationalStoreGetRow(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return ValuesBucket{ nullptr, nullptr, 0 };
    }
    return nativeResultSet->GetRow(errCode);
}

FFI_EXPORT ValuesBucketEx FfiOHOSRelationalStoreGetRowEx(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return ValuesBucketEx{ nullptr, nullptr, 0 };
    }
    return nativeResultSet->GetRowEx(errCode);
}

FFI_EXPORT ValueTypeEx FfiOHOSRelationalStoreResultSetGetValue(int64_t id, int32_t columnIndex, int32_t* errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return ValueTypeEx{ 0 };
    }
    return nativeResultSet->GetValue(columnIndex, errCode);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreResultSetGetColumnTypeByName(int64_t id, char *columnName, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr || nativeResultSet->resultSetValue == nullptr) {
        *rtnCode = NativeRdb::E_ALREADY_CLOSED;
        return static_cast<int32_t>(NativeRdb::ColumnType::TYPE_NULL);
    }
    int32_t columnIndex = 0;
    *rtnCode = nativeResultSet->resultSetValue->GetColumnIndex(columnName, columnIndex);
    if (*rtnCode != NativeRdb::E_OK) {
        if (*rtnCode == NativeRdb::E_INVALID_ARGS) {
            *rtnCode = RelationalStoreJsKit::E_PARAM_ERROR;
        }
        return static_cast<int32_t>(NativeRdb::ColumnType::TYPE_NULL);
    }
    NativeRdb::ColumnType columnType = NativeRdb::ColumnType::TYPE_NULL;
    *rtnCode = nativeResultSet->resultSetValue->GetColumnType(columnIndex, columnType);
    if (*rtnCode != NativeRdb::E_OK) {
        if (*rtnCode == NativeRdb::E_INVALID_ARGS) {
            *rtnCode = RelationalStoreJsKit::E_PARAM_ERROR;
        }
        return static_cast<int32_t>(NativeRdb::ColumnType::TYPE_NULL);
    }
    return static_cast<int32_t>(columnType);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreResultSetGetColumnTypeById(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = NativeRdb::E_ALREADY_CLOSED;
        return static_cast<int32_t>(NativeRdb::ColumnType::TYPE_NULL);
    }
    NativeRdb::ColumnType columnType = NativeRdb::ColumnType::TYPE_NULL;
    *rtnCode = nativeResultSet->resultSetValue->GetColumnType(columnIndex, columnType);
    if (*rtnCode != NativeRdb::E_OK) {
        if (*rtnCode == NativeRdb::E_INVALID_ARGS) {
            *rtnCode = RelationalStoreJsKit::E_PARAM_ERROR;
        }
        return static_cast<int32_t>(NativeRdb::ColumnType::TYPE_NULL);
    }
    return static_cast<int32_t>(columnType);
}
}
} // namespace Relational
} // namespace OHOS