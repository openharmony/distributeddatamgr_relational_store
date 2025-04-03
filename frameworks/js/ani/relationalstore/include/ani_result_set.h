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

#ifndef RESULT_SET_ANI_H
#define RESULT_SET_ANI_H

#include "rdb_helper.h"

namespace OHOS {
namespace RelationalStoreAniKit {

class ResultSetProxy {
    public:
        std::shared_ptr<OHOS::NativeRdb::AbsSharedResultSet> resultset;
};

ani_status ResultSetInit(ani_env *env);

} // namespace RelationalStoreAniKit
} // namespace OHOS

#endif //RESULT_SET_ANI_H