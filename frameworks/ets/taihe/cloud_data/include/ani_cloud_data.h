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
#ifndef OHOS_RELATION_STORE_ANI_CLOUD_DATA_H_
#define OHOS_RELATION_STORE_ANI_CLOUD_DATA_H_
#include <functional>
#include "ohos.data.cloudData.proj.hpp"
#include "ohos.data.cloudData.impl.hpp"
#include "ohos.data.cloudData.sharing.proj.hpp"
#include "ohos.data.cloudData.sharing.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"
#include "cloud_service.h"
#include "cloud_manager.h"

namespace AniCloudData {
using namespace OHOS::CloudData;
using namespace ::taihe;
using namespace ::ohos::data::cloudData;
class ConfigImpl {
public:
    static void ChangeAppCloudSwitchImpl(string_view accountId, string_view bundleName, bool status);
    static void ClearImpl(string_view accountId, map_view<string, ClearAction> appActions);
};
} // namespace AniCloudData
#endif