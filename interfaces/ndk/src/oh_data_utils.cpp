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

#include "oh_data_utils.h"

namespace OHOS::RdbNdk {
NativeRdb::ConflictResolution Utils::ConvertConflictResolution(Rdb_ConflictResolution resolution)
{
    switch (resolution) {
        case RDB_CONFLICT_NONE:
            return NativeRdb::ConflictResolution::ON_CONFLICT_NONE;
        case RDB_CONFLICT_ROLLBACK:
            return NativeRdb::ConflictResolution::ON_CONFLICT_ROLLBACK;
        case RDB_CONFLICT_ABORT:
            return NativeRdb::ConflictResolution::ON_CONFLICT_ABORT;
        case RDB_CONFLICT_FAIL:
            return NativeRdb::ConflictResolution::ON_CONFLICT_FAIL;
        case RDB_CONFLICT_IGNORE:
            return NativeRdb::ConflictResolution::ON_CONFLICT_IGNORE;
        case RDB_CONFLICT_REPLACE:
            return NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE;
        default:
            return NativeRdb::ConflictResolution::ON_CONFLICT_NONE;
    }
}
} // namespace OHOS::RdbNdk