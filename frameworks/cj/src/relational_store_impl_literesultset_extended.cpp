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
#include "rdb_errno.h"
#include "relational_store_impl_literesultset.h"
#include "relational_store_utils.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Relational {

static constexpr int32_t INIT_POSITION = -1;
static constexpr int32_t MAX_ROWS_COUNT = 32766;

int32_t LiteResultSetImpl::PreparePosition(int32_t position)
{
    int rowPos = 0;
    resultSet_->GetRowIndex(rowPos);
    int errCode = NativeRdb::E_OK;
    if (position != INIT_POSITION && position != rowPos) {
        errCode = resultSet_->GoToRow(position);
    } else if (rowPos == INIT_POSITION) {
        errCode = resultSet_->GoToFirstRow();
        if (errCode == NativeRdb::E_ROW_OUT_RANGE) {
            return NativeRdb::E_OK;
        }
    }
    return errCode;
}

int32_t LiteResultSetImpl::FetchRowEntities(int32_t maxCount, std::vector<NativeRdb::RowEntity> &rowEntities)
{
    for (int32_t i = 0; i < maxCount; ++i) {
        NativeRdb::RowEntity rowEntity;
        int code = resultSet_->GetRow(rowEntity);
        if (code == NativeRdb::E_ROW_OUT_RANGE) {
            break;
        }
        if (code != NativeRdb::E_OK) {
            return code;
        }
        rowEntities.push_back(std::move(rowEntity));
        code = resultSet_->GoToNextRow();
        if (code == NativeRdb::E_ROW_OUT_RANGE) {
            break;
        }
        if (code != NativeRdb::E_OK) {
            return code;
        }
    }
    return NativeRdb::E_OK;
}

CArrValuesBucket LiteResultSetImpl::ConvertToCArrValuesBucket(
    std::vector<NativeRdb::RowEntity> &rowEntities, int32_t *rtnCode)
{
    if (rowEntities.empty()) {
        return CArrValuesBucket{ nullptr, 0 };
    }
    size_t size = rowEntities.size();
    if (size > MAX_ROWS_COUNT) {
        LOGE("ConvertToCArrValuesBucket size %{public}zu exceeds limit", size);
        *rtnCode = NativeRdb::E_INVALID_ARGS_NEW;
        return CArrValuesBucket{ nullptr, 0 };
    }
    CArrValuesBucket result = CArrValuesBucket{
        .head = static_cast<ValuesBucketEx *>(malloc(sizeof(ValuesBucketEx) * size)),
        .size = static_cast<int64_t>(size)
    };
    if (result.head == nullptr) {
        return CArrValuesBucket{ nullptr, ERROR_VALUE };
    }
    int64_t idx = 0;
    for (auto &entity : rowEntities) {
        result.head[idx] = RowEntityToValuesBucketEx(entity);
        if (result.head[idx].size == ERROR_VALUE) {
            for (int64_t j = 0; j < idx; j++) {
                free(result.head[j].key);
                free(result.head[j].value);
            }
            free(result.head);
            *rtnCode = NativeRdb::E_ERROR;
            return CArrValuesBucket{ nullptr, 0 };
        }
        idx++;
    }
    return result;
}

CArrValuesBucket LiteResultSetImpl::GetRows(int32_t maxCount, int32_t position, int32_t *rtnCode)
{
    if (resultSet_ == nullptr) {
        *rtnCode = NativeRdb::E_ALREADY_CLOSED;
        return CArrValuesBucket{ nullptr, 0 };
    }
    int errCode = PreparePosition(position);
    if (errCode != NativeRdb::E_OK) {
        LOGE("Failed code:%{public}d. [%{public}d, %{public}d]", errCode, maxCount, position);
        *rtnCode = errCode;
        return CArrValuesBucket{ nullptr, 0 };
    }
    std::vector<NativeRdb::RowEntity> rowEntities;
    errCode = FetchRowEntities(maxCount, rowEntities);
    if (errCode != NativeRdb::E_OK) {
        *rtnCode = errCode;
        return CArrValuesBucket{ nullptr, 0 };
    }
    *rtnCode = NativeRdb::E_OK;
    return ConvertToCArrValuesBucket(rowEntities, rtnCode);
}

RowDataEx LiteResultSetImpl::GetCurrentRowData(int32_t *rtnCode)
{
    if (resultSet_ == nullptr) {
        *rtnCode = NativeRdb::E_ALREADY_CLOSED;
        return RowDataEx{ nullptr, 0 };
    }
    int errCode = NativeRdb::E_OK;
    std::vector<NativeRdb::ValueObject> rowData;
    std::tie(errCode, rowData) = resultSet_->GetRowData();
    *rtnCode = errCode;
    if (errCode != NativeRdb::E_OK) {
        return RowDataEx{ nullptr, 0 };
    }
    return ValueObjectVectorToRowDataEx(rowData);
}

RowsDataEx LiteResultSetImpl::GetRowsData(int32_t maxCount, int32_t position, int32_t *rtnCode)
{
    if (resultSet_ == nullptr) {
        *rtnCode = NativeRdb::E_ALREADY_CLOSED;
        return RowsDataEx{ nullptr, 0 };
    }
    int errCode = NativeRdb::E_OK;
    std::vector<std::vector<NativeRdb::ValueObject>> rowsData;
    std::tie(errCode, rowsData) = resultSet_->GetRowsData(maxCount, position);
    *rtnCode = errCode;
    if (errCode != NativeRdb::E_OK) {
        return RowsDataEx{ nullptr, 0 };
    }
    return RowDataExVectorToRowsDataEx(rowsData);
}

int32_t LiteResultSetImpl::Close()
{
    if (resultSet_ != nullptr) {
        std::shared_ptr<NativeRdb::ResultSet> res = resultSet_;
        resultSet_ = nullptr;
        if (res.use_count() != 1) {
            LOGI("use_count = %{public}ld", res.use_count());
        }
    }
    return NativeRdb::E_OK;
}

} // namespace Relational
} // namespace OHOS