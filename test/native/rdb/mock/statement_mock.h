/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_STATEMENT_MOCK_H
#define OHOS_STATEMENT_MOCK_H

#include <gmock/gmock.h>

#include "statement.h"

namespace OHOS::NativeRdb {
struct SharedBlockInfo;
class MockStatement : public Statement {
public:
    MOCK_METHOD(int32_t, Prepare, (const std::string &sql), (override));
    MOCK_METHOD(int32_t, Bind, (const std::vector<ValueObject> &args), (override));
    MOCK_METHOD((std::pair<int32_t, int32_t>), Count, (), (override));
    MOCK_METHOD(int32_t, Step, (), (override));
    MOCK_METHOD(int32_t, Reset, (), (override));
    MOCK_METHOD(int32_t, Finalize, (), (override));
    MOCK_METHOD(int32_t, Execute, (const std::vector<ValueObject> &args), (override));
    MOCK_METHOD(
        int32_t, Execute, (const std::vector<std::reference_wrapper<ValueObject>> &args), (override));
    MOCK_METHOD((std::pair<int, ValueObject>), ExecuteForValue, (const std::vector<ValueObject> &args), (override));
    MOCK_METHOD((std::pair<int, std::vector<ValuesBucket>>), ExecuteForRows, (const std::vector<ValueObject> &args,
        int32_t maxCount), (override));
    MOCK_METHOD((std::pair<int, std::vector<ValuesBucket>>), ExecuteForRows,
        (const std::vector<std::reference_wrapper<ValueObject>> &args, int32_t maxCount), (override));
    MOCK_METHOD(int32_t, Changes, (), (const, override));
    MOCK_METHOD(int64_t, LastInsertRowId, (), (const, override));
    MOCK_METHOD(int32_t, GetColumnCount, (), (const, override));
    MOCK_METHOD((std::pair<int32_t, std::string>), GetColumnName, (int32_t index), (const, override));
    MOCK_METHOD((std::pair<int32_t, int32_t>), GetColumnType, (int32_t index), (const, override));
    MOCK_METHOD((std::pair<int32_t, size_t>), GetSize, (int32_t index), (const, override));
    MOCK_METHOD((std::pair<int32_t, ValueObject>), GetColumn, (int32_t index), (const, override));
    MOCK_METHOD((std::pair<int32_t, std::vector<ValuesBucket>>), GetRows, (int32_t maxCount), (override));
    MOCK_METHOD(bool, ReadOnly, (), (const, override));
    MOCK_METHOD(bool, SupportBlockInfo, (), (const, override));
    MOCK_METHOD(int32_t, FillBlockInfo, (SharedBlockInfo * info, int retiyTime), (const, override));
    MOCK_METHOD(int, ModifyLockStatus,
        (const std::string &table, const std::vector<std::vector<uint8_t>> &hashKeys, bool isLock), (override));
};
} // namespace OHOS::NativeRdb
#endif // OHOS_STATEMENT_MOCK_H
