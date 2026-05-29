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

#include "relational_store_impl_literesultset.h"

#include "native_log.h"
#include "rdb_errno.h"
#include "relational_store_utils.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Relational {

OHOS::FFI::RuntimeType *LiteResultSetImpl::GetClassType()
{
    static OHOS::FFI::RuntimeType runtimeType = OHOS::FFI::RuntimeType::Create<OHOS::FFI::FFIData>("LiteResultSetImpl");
    return &runtimeType;
}

LiteResultSetImpl::LiteResultSetImpl(std::shared_ptr<NativeRdb::ResultSet> resultSet)
    : resultSet_(resultSet)
{
}

int32_t LiteResultSetImpl::GetColumnIndex(char *columnName, int32_t *rtnCode)
{
    if (resultSet_ == nullptr) {
        *rtnCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }
    int32_t result = -1;
    int errCode = resultSet_->GetColumnIndex(columnName, result);
    *rtnCode = errCode;
    return result;
}

char *LiteResultSetImpl::GetColumnName(int32_t columnIndex, int32_t *rtnCode)
{
    if (resultSet_ == nullptr) {
        *rtnCode = NativeRdb::E_ALREADY_CLOSED;
        return nullptr;
    }
    std::string result;
    int errCode = resultSet_->GetColumnName(columnIndex, result);
    *rtnCode = errCode;
    if (errCode != NativeRdb::E_OK) {
        return nullptr;
    }
    return MallocCString(result);
}

int32_t LiteResultSetImpl::GetColumnTypeByName(char *columnName, int32_t *rtnCode)
{
    if (resultSet_ == nullptr) {
        *rtnCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }
    int errCode = NativeRdb::E_OK;
    int32_t columnIndex = 0;
    if (columnName != nullptr && strlen(columnName) > 0) {
        errCode = resultSet_->GetColumnIndex(columnName, columnIndex);
    }
    if (errCode != NativeRdb::E_OK) {
        *rtnCode = errCode;
        return -1;
    }
    NativeRdb::ColumnType columnType = NativeRdb::ColumnType::TYPE_NULL;
    errCode = resultSet_->GetColumnType(columnIndex, columnType);
    *rtnCode = errCode;
    if (errCode != NativeRdb::E_OK) {
        return -1;
    }
    return static_cast<int32_t>(columnType);
}

int32_t LiteResultSetImpl::GetColumnTypeById(int32_t columnIndex, int32_t *rtnCode)
{
    if (resultSet_ == nullptr) {
        *rtnCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }
    NativeRdb::ColumnType type = NativeRdb::ColumnType::TYPE_NULL;
    int errCode = resultSet_->GetColumnType(columnIndex, type);
    *rtnCode = errCode;
    if (errCode != NativeRdb::E_OK) {
        return -1;
    }
    return static_cast<int32_t>(type);
}

bool LiteResultSetImpl::GoToNextRow(int32_t *rtnCode)
{
    int errCode = NativeRdb::E_ALREADY_CLOSED;
    if (resultSet_ != nullptr) {
        errCode = resultSet_->GoToNextRow();
    }
    *rtnCode = errCode;
    if (errCode == NativeRdb::E_ROW_OUT_RANGE) {
        *rtnCode = 0;
        return false;
    }
    return errCode == NativeRdb::E_OK;
}

CArrUI8 LiteResultSetImpl::GetBlob(int32_t columnIndex, int32_t *rtnCode)
{
    if (resultSet_ == nullptr) {
        *rtnCode = NativeRdb::E_ALREADY_CLOSED;
        return CArrUI8{ nullptr, 0 };
    }
    std::vector<uint8_t> result;
    int errCode = resultSet_->GetBlob(columnIndex, result);
    *rtnCode = errCode;
    if (errCode != NativeRdb::E_OK || result.size() == 0) {
        return CArrUI8{ nullptr, 0 };
    }
    uint8_t *arr = static_cast<uint8_t *>(malloc(result.size() * sizeof(uint8_t)));
    if (arr == nullptr) {
        *rtnCode = ERROR_VALUE;
        return CArrUI8{ nullptr, ERROR_VALUE };
    }
    for (size_t i = 0; i < result.size(); i++) {
        arr[i] = result[i];
    }
    return CArrUI8{ arr, static_cast<int64_t>(result.size()) };
}

int64_t LiteResultSetImpl::GetLong(int32_t columnIndex, int32_t *rtnCode)
{
    if (resultSet_ == nullptr) {
        *rtnCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }
    int64_t result = 0;
    int errCode = resultSet_->GetLong(columnIndex, result);
    *rtnCode = errCode;
    return result;
}

Asset LiteResultSetImpl::GetAsset(int32_t columnIndex, int32_t *rtnCode)
{
    if (resultSet_ == nullptr) {
        *rtnCode = NativeRdb::E_ALREADY_CLOSED;
        return Asset{ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, 0 };
    }
    NativeRdb::ValueObject::Asset result;
    int errCode = resultSet_->GetAsset(columnIndex, result);
    *rtnCode = errCode;
    if (errCode == NativeRdb::E_NULL_OBJECT) {
        LOGI("GetAsset col %{public}d is null.", columnIndex);
        return Asset{ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, 0 };
    }
    if (errCode != NativeRdb::E_OK) {
        return Asset{ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, 0 };
    }
    return Asset{
        .name = MallocCString(result.name),
        .uri = MallocCString(result.uri),
        .path = MallocCString(result.path),
        .createTime = MallocCString(result.createTime),
        .modifyTime = MallocCString(result.modifyTime),
        .size = MallocCString(result.size),
        .status = static_cast<int32_t>(result.status)
    };
}

Assets LiteResultSetImpl::GetAssets(int32_t columnIndex, int32_t *rtnCode)
{
    if (resultSet_ == nullptr) {
        *rtnCode = NativeRdb::E_ALREADY_CLOSED;
        return Assets{ nullptr, 0 };
    }
    std::vector<NativeRdb::ValueObject::Asset> result;
    int errCode = resultSet_->GetAssets(columnIndex, result);
    *rtnCode = errCode;
    if (errCode == NativeRdb::E_NULL_OBJECT) {
        LOGI("GetAssets col %{public}d is null.", columnIndex);
        return Assets{ nullptr, 0 };
    }
    if (errCode != NativeRdb::E_OK || result.size() == 0) {
        return Assets{ nullptr, 0 };
    }
    Asset *arr = static_cast<Asset *>(malloc(result.size() * sizeof(Asset)));
    if (arr == nullptr) {
        *rtnCode = ERROR_VALUE;
        return Assets{ nullptr, ERROR_VALUE };
    }
    for (size_t i = 0; i < result.size(); i++) {
        arr[i] = Asset{
            .name = MallocCString(result[i].name),
            .uri = MallocCString(result[i].uri),
            .path = MallocCString(result[i].path),
            .createTime = MallocCString(result[i].createTime),
            .modifyTime = MallocCString(result[i].modifyTime),
            .size = MallocCString(result[i].size),
            .status = static_cast<int32_t>(result[i].status)
        };
    }
    return Assets{ .head = arr, .size = static_cast<int64_t>(result.size()) };
}

ValueTypeEx LiteResultSetImpl::GetValue(int32_t columnIndex, int32_t *rtnCode)
{
    if (resultSet_ == nullptr) {
        *rtnCode = NativeRdb::E_ALREADY_CLOSED;
        return ValueTypeEx{};
    }
    NativeRdb::ValueObject object;
    int errCode = resultSet_->Get(columnIndex, object);
    *rtnCode = errCode;
    if (errCode != NativeRdb::E_OK) {
        return ValueTypeEx{};
    }
    return ValueObjectToValueTypeEx(object);
}

ValuesBucketEx LiteResultSetImpl::GetRow(int32_t *rtnCode)
{
    if (resultSet_ == nullptr) {
        *rtnCode = NativeRdb::E_ALREADY_CLOSED;
        return ValuesBucketEx{ nullptr, nullptr, 0 };
    }
    NativeRdb::RowEntity rowEntity;
    int errCode = resultSet_->GetRow(rowEntity);
    *rtnCode = errCode;
    if (errCode != NativeRdb::E_OK) {
        return ValuesBucketEx{ nullptr, nullptr, 0 };
    }
    return RowEntityToValuesBucketEx(rowEntity);
}

bool LiteResultSetImpl::IsColumnNull(int32_t columnIndex, int32_t *rtnCode)
{
    if (resultSet_ == nullptr) {
        *rtnCode = NativeRdb::E_ALREADY_CLOSED;
        return false;
    }
    bool result = false;
    int errCode = resultSet_->IsColumnNull(columnIndex, result);
    *rtnCode = errCode;
    return result;
}

} // namespace Relational
} // namespace OHOS