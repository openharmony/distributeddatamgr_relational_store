/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef NATIVE_RDB_RDB_COMMON_H
#define NATIVE_RDB_RDB_COMMON_H

#include <cstdint>
namespace OHOS {
namespace NativeRdb {
enum class ConflictResolution {
    /** Implements no action when conflict occurs.*/
    ON_CONFLICT_NONE = 0,
    /** Implements rollback operation when conflict occurs.*/
    ON_CONFLICT_ROLLBACK,
    /** Implements abort operation when conflict occurs.*/
    ON_CONFLICT_ABORT,
    /** Implements fail operation when conflict occurs.*/
    ON_CONFLICT_FAIL,
    /** Implements ignore operation when conflict occurs.*/
    ON_CONFLICT_IGNORE,
    /** Implements replace operation operator when conflict occurs.*/
    ON_CONFLICT_REPLACE,
};

enum RebuiltType : uint32_t {
    NONE,
    REBUILT,
};
} // namespace NativeRdb
} // namespace OHOS

#endif // NATIVE_RDB_RDB_COMMON_H
