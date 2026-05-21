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

#include "native_log.h"
#include "napi_rdb_error.h"
#include "rdb_errno.h"
#include "relational_store_impl_resultsetproxy.h"
#include "relational_store_utils.h"
#include "value_object.h"

namespace OHOS {
namespace Relational {
static const int E_OK = 0;
static constexpr size_t MAX_COLUMNS = 2000;
static constexpr int32_t MAX_ROWS_COUNT = 32766;

ValuesBucket ResultSetImpl::GetRow(int32_t* rtnCode)
{
    NativeRdb::RowEntity rowEntity;
    *rtnCode = resultSetValue->GetRow(rowEntity);
    if (*rtnCode != E_OK) {
        return ValuesBucket{nullptr, nullptr, 0};
    }
    const std::map<std::string, NativeRdb::ValueObject> map = rowEntity.Get();
    size_t size = map.size();
    if (size == 0) {
        return ValuesBucket{nullptr, nullptr, 0};
    }
    if (size > MAX_COLUMNS) {
        LOGE("GetRow size %{public}zu exceeds limit %{public}zu", size, MAX_COLUMNS);
        return ValuesBucket{nullptr, nullptr, -1};
    }
    ValuesBucket result = ValuesBucket {
        .key = static_cast<char**>(malloc(sizeof(char*) * size)),
        .value = static_cast<ValueType*>(malloc(sizeof(ValueType) * size)),
        .size = size
    };
    if (result.key == nullptr || result.value == nullptr) {
        free(result.key);
        free(result.value);
        return ValuesBucket{nullptr, nullptr, -1};
    }
    int64_t i = 0;
    for (auto &t : map) {
        result.key[i] = MallocCString(t.first);
        result.value[i] = ValueObjectToValueType(t.second);
        i++;
    }
    return result;
}

ValuesBucketEx ResultSetImpl::GetRowEx(int32_t* rtnCode)
{
    NativeRdb::RowEntity rowEntity;
    *rtnCode = resultSetValue->GetRow(rowEntity);
    if (*rtnCode != E_OK) {
        return ValuesBucketEx{nullptr, nullptr, 0};
    }
    const std::map<std::string, NativeRdb::ValueObject> map = rowEntity.Get();
    size_t size = map.size();
    if (size == 0) {
        return ValuesBucketEx{nullptr, nullptr, 0};
    }
    if (size > MAX_COLUMNS) {
        LOGE("GetRowEx size %{public}zu exceeds limit %{public}zu", size, MAX_COLUMNS);
        return ValuesBucketEx{nullptr, nullptr, ERROR_VALUE};
    }
    ValuesBucketEx result = ValuesBucketEx {
        .key = static_cast<char**>(malloc(sizeof(char*) * size)),
        .value = static_cast<ValueTypeEx*>(malloc(sizeof(ValueTypeEx) * size)),
        .size = size
    };
    if (result.key == nullptr || result.value == nullptr) {
        free(result.key);
        free(result.value);
        return ValuesBucketEx{nullptr, nullptr, ERROR_VALUE};
    }
    int64_t i = 0;
    for (auto &t : map) {
        result.key[i] = MallocCString(t.first);
        result.value[i] = ValueObjectToValueTypeEx(t.second);
        i++;
    }
    return result;
}

ValueTypeEx ResultSetImpl::GetValue(int32_t columnIndex, int32_t* rtnCode)
{
    NativeRdb::ValueObject object;
    *rtnCode = NativeRdb::E_ALREADY_CLOSED;
    if (resultSetValue != nullptr) {
        *rtnCode = resultSetValue->Get(columnIndex, object);
    }
    if (*rtnCode != E_OK) {
        return ValueTypeEx{ 0 };
    }
    return ValueObjectToValueTypeEx(object);
}

int32_t ResultSetImpl::GetColumnType(int32_t columnIndex, int32_t *rtnCode)
{
    NativeRdb::ColumnType columnType = NativeRdb::ColumnType::TYPE_NULL;
    *rtnCode = NativeRdb::E_ALREADY_CLOSED;
    if (resultSetValue != nullptr) {
        *rtnCode = resultSetValue->GetColumnType(columnIndex, columnType);
    }
    if (*rtnCode != NativeRdb::E_OK) {
        return -1;
    }
    return static_cast<int32_t>(columnType);
}

RowDataEx ResultSetImpl::GetCurrentRowData(int32_t *rtnCode)
{
    *rtnCode = NativeRdb::E_ALREADY_CLOSED;
    if (resultSetValue == nullptr) {
        return RowDataEx{ nullptr, 0 };
    }

    auto [errCode, rowData] = resultSetValue->GetRowData();
    *rtnCode = errCode;
    if (errCode != NativeRdb::E_OK) {
        return RowDataEx{ nullptr, 0 };
    }

    return ValueObjectVectorToRowDataEx(rowData);
}

RowsDataEx ResultSetImpl::GetRowsData(int32_t maxCount, int32_t position, int32_t *rtnCode)
{
    *rtnCode = NativeRdb::E_ALREADY_CLOSED;
    if (resultSetValue == nullptr) {
        return RowsDataEx{ nullptr, 0 };
    }

    auto [errCode, rowsData] = resultSetValue->GetRowsData(maxCount, position);
    *rtnCode = errCode;
    if (errCode != NativeRdb::E_OK) {
        return RowsDataEx{ nullptr, 0 };
    }
    if (rowsData.size() > MAX_ROWS_COUNT) {
        LOGE("GetRowsData size %{public}zu exceeds limit %{public}d", rowsData.size(), MAX_ROWS_COUNT);
        *rtnCode = ERROR_VALUE;
        return RowsDataEx{ nullptr, 0 };
    }

    return RowDataExVectorToRowsDataEx(rowsData);
}

} // namespace Relational
} // namespace OHOS