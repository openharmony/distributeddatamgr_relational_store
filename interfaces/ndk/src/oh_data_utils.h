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
#ifndef OH_DATA_UTILS_H
#define OH_DATA_UTILS_H

#include <mutex>
#include <optional>
#include "oh_rdb_types.h"
#include "rdb_common.h"
#include "serializable.h"
#include "oh_data_define.h"
#include "relational_values_bucket.h"
namespace OHOS::RdbNdk {
class Utils {
public:
    static NativeRdb::ConflictResolution ConvertConflictResolution(Rdb_ConflictResolution resolution);
    static bool IsContainTerminator();
    static bool IsValidContext(const OH_RDB_ReturningContext *context);
    static bool IsValidRows(const OH_Data_VBuckets *rows);
    static bool IsValidResolution(Rdb_ConflictResolution resolution);
    static bool IsValidTableName(const char *table);
    static bool IsValidRdbValuesBucket(OHOS::RdbNdk::RelationalValuesBucket *rdbValuesBucket);
private:
    struct TrustsProxy final : public Serializable {
        std::string bundleName;
        bool Marshal(json &node) const override;
        bool Unmarshal(const json &node) override;
    };
    static bool isInited_;
    static bool flag_;
    static std::mutex mutex_;
};
} // namespace OHOS::RdbNdk
#endif // OH_DATA_UTILS_H