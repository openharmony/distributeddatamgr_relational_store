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
#ifndef ANI_RDB_STORE_H
#define ANI_RDB_STORE_H

#include <ani.h>
#include "rdb_store.h"

namespace OHOS {
namespace RelationalStoreAniKit {

using namespace OHOS::NativeRdb;

class RdbStoreProxy {
    public:
        std::shared_ptr<RdbStore> nativeRdb;
};
ani_status RdbStoreInit(ani_env *env);

} // namespace RelationalStoreAniKit
} // namespace OHOS
#endif // ANI_RDB_STORE_H

