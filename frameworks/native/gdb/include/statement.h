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

#ifndef NATIVE_GDB_STATEMENT_H
#define NATIVE_GDB_STATEMENT_H
#include <functional>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "full_result.h"

namespace OHOS::DistributedDataAip {
/**
 * @brief Indicates the column type.
 *
 * Value returned by getColumnType(int)
 */
enum class ColumnType : int {
    TYPE_INTEGER = 0,
    TYPE_FLOAT,
    TYPE_TEXT,
    TYPE_BLOB,
    TYPE_FLOATVECTOR,
    TYPE_JSONSTR,
    TYPE_NULL,
};
class Statement {
public:
    virtual int32_t Prepare() = 0;
    virtual int32_t Step() = 0;
    virtual int32_t Finalize() = 0;

    virtual uint32_t GetColumnCount() const = 0;
    virtual std::pair<int32_t, std::string> GetColumnName(int32_t index) const = 0;
    virtual std::pair<int32_t, ColumnType> GetColumnType(int32_t index) const = 0;
    virtual std::pair<int32_t, GraphValue> GetColumnValue(int32_t index) const = 0;

    virtual bool IsReady() const = 0;
};
} // namespace OHOS::DistributedDataAip
#endif //ARKDATA_INTELLIGENCE_PLATFORM_STATEMENT_H