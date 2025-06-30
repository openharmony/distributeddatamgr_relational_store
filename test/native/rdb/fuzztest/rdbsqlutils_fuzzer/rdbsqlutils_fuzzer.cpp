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
#include "rdbsqlutils_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <rdb_sql_utils.h>
#include <rdb_store_config.h>
#include <shared_block.h>

#include <memory>
#include <string>
#include <vector>

using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

ConflictResolution GetConflictResolution(FuzzedDataProvider &provider)
{
    int min = static_cast<int>(ConflictResolution::ON_CONFLICT_NONE);
    int max = static_cast<int>(ConflictResolution::ON_CONFLICT_REPLACE);
    int enumInt = provider.ConsumeIntegralInRange<int>(min, max);
    ConflictResolution resolution = static_cast<ConflictResolution>(enumInt);
    return resolution;
}

std::vector<ValueObject> ConsumeRandomLengthValueObjectVector(FuzzedDataProvider &provider)
{
    const int loopsMin = 0;
    const int loopsMax = 100;
    size_t loops = provider.ConsumeIntegralInRange<size_t>(loopsMin, loopsMax);
    std::vector<ValueObject> columns;
    for (size_t i = 0; i < loops; ++i) {
        int32_t value = provider.ConsumeIntegral<int32_t>();
        ValueObject obj(value);
        columns.emplace_back(obj);
    }
    return columns;
}

std::vector<std::string> ConsumeRandomLengthStringVector(FuzzedDataProvider &provider)
{
    const int loopsMin = 0;
    const int loopsMax = 100;
    size_t loops = provider.ConsumeIntegralInRange<size_t>(loopsMin, loopsMax);
    std::vector<std::string> columns;
    for (size_t i = 0; i < loops; ++i) {
        int32_t length = provider.ConsumeIntegral<int32_t>();
        auto bytes = provider.ConsumeBytes<char>(length);
        columns.emplace_back(bytes.begin(), bytes.end());
    }
    return columns;
}

// Fuzz CreateDirectory
void FuzzCreateDirectory(FuzzedDataProvider &provider)
{
    std::string databaseDir = provider.ConsumeRandomLengthString();
    RdbSqlUtils::CreateDirectory(databaseDir);
}

// Fuzz GetDefaultDatabasePath
void FuzzGetDefaultDatabasePath(FuzzedDataProvider &provider)
{
    std::string baseDir = provider.ConsumeRandomLengthString();
    std::string name = provider.ConsumeRandomLengthString();
    std::string customDir = provider.ConsumeRandomLengthString();
    RdbSqlUtils::GetDefaultDatabasePath(baseDir, name, customDir);
}

// Fuzz GetCustomDatabasePath
void FuzzGetCustomDatabasePath(FuzzedDataProvider &provider)
{
    std::string rootDir = provider.ConsumeRandomLengthString();
    std::string name = provider.ConsumeRandomLengthString();
    std::string customDir = provider.ConsumeRandomLengthString();
    RdbSqlUtils::GetCustomDatabasePath(rootDir, name, customDir);
}

// Fuzz GetDefaultDatabasePath with errorCode
void FuzzGetDefaultDatabasePathWithErrorCode(FuzzedDataProvider &provider)
{
    std::string baseDir = provider.ConsumeRandomLengthString();
    std::string name = provider.ConsumeRandomLengthString();
    int errorCode = 0;
    RdbSqlUtils::GetDefaultDatabasePath(baseDir, name, errorCode);
}

// Fuzz BuildQueryString
void FuzzBuildQueryString(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString();
    AbsRdbPredicates predicates(table);
    std::vector<std::string> columns = ConsumeRandomLengthStringVector(provider);
    RdbSqlUtils::BuildQueryString(predicates, columns);
}

// Fuzz GetInsertSqlInfo
void FuzzGetInsertSqlInfo(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString();
    Row row;
    ConflictResolution resolution = GetConflictResolution(provider);
    RdbSqlUtils::GetInsertSqlInfo(table, row, resolution);
}

// Fuzz GetUpdateSqlInfo
void FuzzGetUpdateSqlInfo(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString();
    AbsRdbPredicates predicates(table);
    Row row;
    ConflictResolution resolution = GetConflictResolution(provider);
    std::vector<std::string> returningFields;
    RdbSqlUtils::GetUpdateSqlInfo(predicates, row, resolution, returningFields);
}

// Fuzz GetDeleteSqlInfo
void FuzzGetDeleteSqlInfo(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString();
    AbsRdbPredicates predicates(table);
    std::vector<std::string> returningFields;
    RdbSqlUtils::GetDeleteSqlInfo(predicates, returningFields);
}

// Fuzz GetQuerySqlInfo
void FuzzGetQuerySqlInfo(FuzzedDataProvider &provider)
{
    std::string table = provider.ConsumeRandomLengthString();
    AbsRdbPredicates predicates(table);
    Fields columns = ConsumeRandomLengthStringVector(provider);
    RdbSqlUtils::GetQuerySqlInfo(predicates, columns);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::FuzzCreateDirectory(provider);
    OHOS::FuzzGetDefaultDatabasePath(provider);
    OHOS::FuzzGetCustomDatabasePath(provider);
    OHOS::FuzzGetDefaultDatabasePathWithErrorCode(provider);
    OHOS::FuzzBuildQueryString(provider);
    OHOS::FuzzGetInsertSqlInfo(provider);
    OHOS::FuzzGetUpdateSqlInfo(provider);
    OHOS::FuzzGetDeleteSqlInfo(provider);
    OHOS::FuzzGetQuerySqlInfo(provider);
    return 0;
}
