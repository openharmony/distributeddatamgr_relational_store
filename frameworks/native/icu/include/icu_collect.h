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

#ifndef OHOS_NATIVE_RDB_ICU_COLLECT_H
#define OHOS_NATIVE_RDB_ICU_COLLECT_H
#include <string>

#include "sqlite3sym.h"

namespace OHOS::NativeRdb {

class ICUCollect {
public:
    static int32_t Local(sqlite3 *dbHandle, const std::string &str);

private:
    static int Collate8Compare(void *p, int n1, const void *v1, int n2, const void *v2);
    static void LocalizedCollatorDestroy(void *collator);
};

} // namespace OHOS::NativeRdb

#endif // OHOS_NATIVE_RDB_ICU_COLLECT_H