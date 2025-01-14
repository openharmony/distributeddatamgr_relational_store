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

#ifndef SQLITE_FUNCTION_REGISTRY_H
#define SQLITE_FUNCTION_REGISTRY_H

#include <sqlite3.h>

#include <map>

#include "value_object.h"

namespace OHOS {
namespace NativeRdb {
struct SqliteFunction {
    const char *name;
    int numArgs;
    void (*function)(sqlite3_context *, int, sqlite3_value **);
};

class SqliteFunctionRegistry {
private:
    static void MergeAssets(sqlite3_context *ctx, int argc, sqlite3_value **argv);
    static void MergeAsset(sqlite3_context *ctx, int argc, sqlite3_value **argv);
    static void CompAssets(
        std::map<std::string, ValueObject::Asset> &oldAssets, std::map<std::string, ValueObject::Asset> &newAssets);
    static void MergeAsset(ValueObject::Asset &oldAsset, ValueObject::Asset &newAsset);
    static void ImportDB(sqlite3_context *ctx, int argc, sqlite3_value **argv);
    static void SqliteResultError(sqlite3_context *ctx, const int &errCode, const std::string &msg);
    static int32_t IntegrityCheck(sqlite3 *dbHandle);
    static int32_t BackUpDB(sqlite3 *source, sqlite3 *dest);
    static constexpr SqliteFunction FUNCTIONS[] = {
        { "merge_assets", 2, &SqliteFunctionRegistry::MergeAssets },
        { "merge_asset", 2, &SqliteFunctionRegistry::MergeAsset },
        { "import_db_from_path", 1, &SqliteFunctionRegistry::ImportDB },
    };

public:
    static constexpr std::pair<const SqliteFunction*, size_t> GetFunctions()
    {
        return { FUNCTIONS, sizeof(FUNCTIONS) / sizeof(FUNCTIONS[0]) };
    };
};

} // namespace NativeRdb
} // namespace OHOS
#endif
