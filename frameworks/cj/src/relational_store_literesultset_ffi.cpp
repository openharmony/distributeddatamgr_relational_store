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
#include "relational_store_impl_literesultset.h"
#include "relational_store_utils.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Relational {
extern "C" {

FFI_EXPORT int32_t FfiOHOSRelationalStoreLiteResultSetGetColumnIndex(int64_t id, char *columnName, int32_t *rtnCode)
{
    auto liteResultSet = FFIData::GetData<LiteResultSetImpl>(id);
    if (liteResultSet == nullptr || columnName == nullptr) {
        *rtnCode = -1;
        return -1;
    }
    return liteResultSet->GetColumnIndex(columnName, rtnCode);
}

FFI_EXPORT char *FfiOHOSRelationalStoreLiteResultSetGetColumnName(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto liteResultSet = FFIData::GetData<LiteResultSetImpl>(id);
    if (liteResultSet == nullptr) {
        *rtnCode = -1;
        return nullptr;
    }
    return liteResultSet->GetColumnName(columnIndex, rtnCode);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreLiteResultSetGetColumnTypeByName(int64_t id,
    char *columnName, int32_t *rtnCode)
{
    auto liteResultSet = FFIData::GetData<LiteResultSetImpl>(id);
    if (liteResultSet == nullptr || columnName == nullptr) {
        *rtnCode = -1;
        return -1;
    }
    return liteResultSet->GetColumnTypeByName(columnName, rtnCode);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreLiteResultSetGetColumnTypeById(int64_t id,
    int32_t columnIndex, int32_t *rtnCode)
{
    auto liteResultSet = FFIData::GetData<LiteResultSetImpl>(id);
    if (liteResultSet == nullptr) {
        *rtnCode = -1;
        return -1;
    }
    return liteResultSet->GetColumnTypeById(columnIndex, rtnCode);
}

FFI_EXPORT bool FfiOHOSRelationalStoreLiteResultSetGoToNextRow(int64_t id, int32_t *rtnCode)
{
    auto liteResultSet = FFIData::GetData<LiteResultSetImpl>(id);
    if (liteResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return liteResultSet->GoToNextRow(rtnCode);
}

FFI_EXPORT CArrUI8 FfiOHOSRelationalStoreLiteResultSetGetBlob(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto liteResultSet = FFIData::GetData<LiteResultSetImpl>(id);
    if (liteResultSet == nullptr) {
        *rtnCode = -1;
        return CArrUI8{ nullptr, 0 };
    }
    return liteResultSet->GetBlob(columnIndex, rtnCode);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreLiteResultSetGetLong(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto liteResultSet = FFIData::GetData<LiteResultSetImpl>(id);
    if (liteResultSet == nullptr) {
        *rtnCode = -1;
        return -1;
    }
    return liteResultSet->GetLong(columnIndex, rtnCode);
}

FFI_EXPORT Asset FfiOHOSRelationalStoreLiteResultSetGetAsset(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto liteResultSet = FFIData::GetData<LiteResultSetImpl>(id);
    if (liteResultSet == nullptr) {
        *rtnCode = -1;
        return Asset{ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, 0 };
    }
    return liteResultSet->GetAsset(columnIndex, rtnCode);
}

FFI_EXPORT Assets FfiOHOSRelationalStoreLiteResultSetGetAssets(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto liteResultSet = FFIData::GetData<LiteResultSetImpl>(id);
    if (liteResultSet == nullptr) {
        *rtnCode = -1;
        return Assets{ nullptr, 0 };
    }
    return liteResultSet->GetAssets(columnIndex, rtnCode);
}

FFI_EXPORT ValueTypeEx FfiOHOSRelationalStoreLiteResultSetGetValue(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto liteResultSet = FFIData::GetData<LiteResultSetImpl>(id);
    if (liteResultSet == nullptr) {
        *rtnCode = -1;
        return ValueTypeEx{};
    }
    return liteResultSet->GetValue(columnIndex, rtnCode);
}

FFI_EXPORT ValuesBucketEx FfiOHOSRelationalStoreLiteResultSetGetRow(int64_t id, int32_t *rtnCode)
{
    auto liteResultSet = FFIData::GetData<LiteResultSetImpl>(id);
    if (liteResultSet == nullptr) {
        *rtnCode = -1;
        return ValuesBucketEx{ nullptr, nullptr, 0 };
    }
    return liteResultSet->GetRow(rtnCode);
}

FFI_EXPORT bool FfiOHOSRelationalStoreLiteResultSetIsColumnNull(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto liteResultSet = FFIData::GetData<LiteResultSetImpl>(id);
    if (liteResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return liteResultSet->IsColumnNull(columnIndex, rtnCode);
}

FFI_EXPORT CArrValuesBucket FfiOHOSRelationalStoreLiteResultSetGetRows(int64_t id,
    int32_t maxCount, int32_t position, int32_t *rtnCode)
{
    auto liteResultSet = FFIData::GetData<LiteResultSetImpl>(id);
    if (liteResultSet == nullptr) {
        *rtnCode = -1;
        return CArrValuesBucket{ nullptr, 0 };
    }
    return liteResultSet->GetRows(maxCount, position, rtnCode);
}

FFI_EXPORT RowDataEx FfiOHOSRelationalStoreLiteResultSetGetCurrentRowData(int64_t id, int32_t *rtnCode)
{
    auto liteResultSet = FFIData::GetData<LiteResultSetImpl>(id);
    if (liteResultSet == nullptr) {
        *rtnCode = -1;
        return RowDataEx{ nullptr, 0 };
    }
    return liteResultSet->GetCurrentRowData(rtnCode);
}

FFI_EXPORT RowsDataEx FfiOHOSRelationalStoreLiteResultSetGetRowsData(int64_t id,
    int32_t maxCount, int32_t position, int32_t *rtnCode)
{
    auto liteResultSet = FFIData::GetData<LiteResultSetImpl>(id);
    if (liteResultSet == nullptr) {
        *rtnCode = -1;
        return RowsDataEx{ nullptr, 0 };
    }
    return liteResultSet->GetRowsData(maxCount, position, rtnCode);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreLiteResultSetClose(int64_t id)
{
    auto liteResultSet = FFIData::GetData<LiteResultSetImpl>(id);
    if (liteResultSet == nullptr) {
        return -1;
    }
    return liteResultSet->Close();
}
}
} // namespace Relational
} // namespace OHOS