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

#include "ffi_remote_data.h"
#include "relational_store_impl_resultsetproxy.h"
#include "relational_store_utils.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Relational {
extern "C" {
CArrStr FfiOHOSRelationalStoreGetAllColumnNames(int64_t id)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        return CArrStr{ nullptr, 0 };
    }
    return nativeResultSet->GetAllColumnNames();
}

int32_t FfiOHOSRelationalStoreGetColumnCount(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeResultSet->GetColumnCount();
}

int32_t FfiOHOSRelationalStoreGetRowCount(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeResultSet->GetRowCount();
}

int32_t FfiOHOSRelationalStoreGetRowIndex(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeResultSet->GetRowIndex();
}

bool FfiOHOSRelationalStoreIsAtFirstRow(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return false;
    }
    *errCode = 0;
    return nativeResultSet->IsAtFirstRow();
}

bool FfiOHOSRelationalStoreIsAtLastRow(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return false;
    }
    *errCode = 0;
    return nativeResultSet->IsAtLastRow();
}

bool FfiOHOSRelationalStoreIsEnded(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return false;
    }
    *errCode = 0;
    return nativeResultSet->IsEnded();
}

bool FfiOHOSRelationalStoreIsStarted(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return false;
    }
    *errCode = 0;
    return nativeResultSet->IsStarted();
}

bool FfiOHOSRelationalStoreIsClosed(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return false;
    }
    *errCode = 0;
    return nativeResultSet->IsClosed();
}

double FfiOHOSRelationalStoreGetDouble(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return -1;
    }
    return nativeResultSet->GetDouble(columnIndex, rtnCode);
}

bool FfiOHOSRelationalStoreGoToRow(int64_t id, int32_t position, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoToRow(position, rtnCode);
}

bool FfiOHOSRelationalStoreGoToPreviousRow(int64_t id, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoToPreviousRow(rtnCode);
}

bool FfiOHOSRelationalStoreGoToLastRow(int64_t id, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoToLastRow(rtnCode);
}

char *FfiOHOSRelationalStoreGetColumnName(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return nullptr;
    }
    return nativeResultSet->GetColumnName(columnIndex, rtnCode);
}

bool FfiOHOSRelationalStoreIsColumnNull(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->IsColumnNull(columnIndex, rtnCode);
}

Asset FfiOHOSRelationalStoreGetAsset(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return Asset{ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, 0 };
    }
    return nativeResultSet->GetAsset(columnIndex, rtnCode);
}

int32_t FfiOHOSRelationalStoreClose(int64_t id)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        return -1;
    }
    return nativeResultSet->Close();
}

int32_t FfiOHOSRelationalStoreGetColumnIndex(int64_t id, char *columnName, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr || columnName == nullptr) {
        *rtnCode = -1;
        return -1;
    }
    return nativeResultSet->GetColumnIndex(columnName, rtnCode);
}

char *FfiOHOSRelationalStoreGetString(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return nullptr;
    }
    return nativeResultSet->GetString(columnIndex, rtnCode);
}

bool FfiOHOSRelationalStoreGoToFirstRow(int64_t id, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoToFirstRow(rtnCode);
}

int64_t FfiOHOSRelationalStoreGetLong(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return -1;
    }
    return nativeResultSet->GetLong(columnIndex, rtnCode);
}

bool FfiOHOSRelationalStoreGoToNextRow(int64_t id, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoToNextRow(rtnCode);
}

CArrUI8 FfiOHOSRelationalStoreGetBlob(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return CArrUI8{ nullptr, 0 };
    }
    return nativeResultSet->GetBlob(columnIndex, rtnCode);
}

bool FfiOHOSRelationalStoreGoTo(int64_t id, int32_t offset, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoTo(offset, rtnCode);
}

Assets FfiOHOSRelationalStoreGetAssets(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return Assets{ nullptr, 0 };
    }
    return nativeResultSet->GetAssets(columnIndex, rtnCode);
}

ValuesBucket FfiOHOSRelationalStoreGetRow(int64_t id, int32_t *errCode)
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
}
}
}