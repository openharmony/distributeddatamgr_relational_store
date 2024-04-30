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

#ifndef OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_INCLUDE_STATEMENT_H
#define OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_INCLUDE_STATEMENT_H
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "value_object.h"
namespace OHOS::NativeRdb {
struct SharedBlockInfo;
class Statement {
public:
    static constexpr int32_t COLUMN_TYPE_ASSET = 1000;
    static constexpr int32_t COLUMN_TYPE_ASSETS = 1001;
    static constexpr int32_t COLUMN_TYPE_FLOATS = 1002;
    static constexpr int32_t COLUMN_TYPE_BIGINT = 1003;

    virtual ~Statement() = default;
    virtual int32_t Prepare(const std::string &sql) = 0;
    virtual int32_t Bind(const std::vector<ValueObject> &args = {}) = 0;
    virtual int32_t Step() = 0;
    virtual int32_t Reset() = 0;
    virtual int32_t Finalize() = 0;

    virtual int32_t Execute(const std::vector<ValueObject> &args = {}) = 0;
    virtual std::pair<int, ValueObject> ExecuteForValue(const std::vector<ValueObject> &args = {}) = 0;
    virtual int32_t Changes() const = 0;
    virtual int64_t LastInsertRowId() const = 0;

    virtual int32_t GetColumnCount() const = 0;
    virtual std::pair<int32_t, std::string> GetColumnName(int32_t index) const = 0;
    virtual std::pair<int32_t, int32_t> GetColumnType(int32_t index) const = 0;
    virtual std::pair<int32_t, size_t> GetSize(int32_t index) const = 0;
    virtual std::pair<int32_t, ValueObject> GetColumn(int32_t index) const = 0;
    virtual bool ReadOnly() const = 0;
    virtual bool SupportBlockInfo() const = 0;
    virtual int32_t FillBlockInfo(SharedBlockInfo *info) const = 0;
    virtual int ModifyLockStatus(const std::string &table, const std::vector<std::vector<uint8_t>> &hashKeys,
        bool isLock)
    {
        return 0;
    }
};
} // namespace OHOS::NativeRdb
#endif // OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_INCLUDE_STATEMENT_H
