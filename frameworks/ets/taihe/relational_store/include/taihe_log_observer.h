/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_RELATION_STORE_TAIHE_LOG_OBSERVER_H
#define OHOS_RELATION_STORE_TAIHE_LOG_OBSERVER_H

#include "ani_rdb_utils.h"

namespace ani_rdbutils {
using namespace taihe;

class TaiheLogObserver : public OHOS::DistributedRdb::SqlErrorObserver,
    public std::enable_shared_from_this<TaiheLogObserver> {
public:
    explicit TaiheLogObserver(
        ani_env *env,
        ani_object callbackObj,
        std::shared_ptr<JsExceptionMessageCallbackType> callbackPtr
    );
    ~TaiheLogObserver();
    bool IsEquals(ani_object callbackObj);
    void OnErrorLog(const ExceptionMessage &message) override;

private:
    ani_ref callbackRef_;
    std::shared_ptr<JsExceptionMessageCallbackType> callbackPtr_;
};
}

#endif // OHOS_RELATION_STORE_TAIHE_LOG_OBSERVER_H