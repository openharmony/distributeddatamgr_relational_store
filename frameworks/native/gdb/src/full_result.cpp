/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define LOG_TAG "GdbDataSet"
#include "full_result.h"

#include "aip_errors.h"
#include "statement.h"
#include "logger.h"

namespace OHOS::DistributedDataAip {
int32_t FullResult::InitData(std::shared_ptr<Statement> stmt)
{
    if (stmt == nullptr) {
        return E_STATEMENT_EMPTY;
    }
    data_ = std::vector<std::unordered_map<std::string, GraphValue>>();
    int32_t errCode = stmt->Step();
    while (errCode == E_OK) {
        auto [ret, oneResult] = GetRow(stmt);
        if (ret != E_OK) {
            return ret;
        }
        data_.emplace_back(oneResult);
        errCode = stmt->Step();
    }
    return (errCode == E_GRD_NO_DATA) ? E_OK : errCode;
}

std::vector<std::unordered_map<std::string, GraphValue>> FullResult::GetAllData() const
{
    return data_;
}
std::pair<int32_t, std::unordered_map<std::string, GraphValue>> FullResult::GetRow(std::shared_ptr<Statement> stmt)
{
    std::unordered_map<std::string, GraphValue> res;
    if (stmt == nullptr) {
        return { E_STATEMENT_EMPTY, res };
    }
    auto columnCount = stmt->GetColumnCount();
    if (columnCount == 0) {
        LOG_ERROR("GetKeys failed ret=%{public}d.", E_NO_DATA);
        return { E_NO_DATA, res };
    }

    for (uint32_t i = 0; i < columnCount; i++) {
        auto [ret, key] = stmt->GetColumnName(i);
        if (ret != E_OK) {
            LOG_ERROR("GetKeys failed ret=%{public}d.", ret);
            return { ret, res };
        }
        auto [err, value] = stmt->GetColumnValue(i);
        if (err != E_OK) {
            LOG_ERROR("GetValue failed, key=%{public}s, ret=%{public}d.", key.c_str(), err);
            return { err, res };
        }
        res.emplace(key, value);
    }
    return { E_OK, res };
}

} // namespace OHOS::DistributedDataAip