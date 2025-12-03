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
#ifndef OHOS_RELATION_STORE_ANI_CLOUD_DATA_UTILS_H
#define OHOS_RELATION_STORE_ANI_CLOUD_DATA_UTILS_H
#include "ani_cloud_data.h"
#include "cloud_types.h"

namespace AniCloudData {
void RequestIPC(std::function<void(std::shared_ptr<CloudService>)> work);
OHOS::CloudData::DBSwitchInfo ConvertTaiheDbSwitchInfo(::ohos::data::cloudData::DBSwitchInfo dbSwitchInfo);
OHOS::CloudData::ClearConfig ConvertTaiheClearConfig(::ohos::data::cloudData::ClearConfig clearConfig);
OHOS::CloudData::DBActionInfo ConvertTaiheDbActionInfo(::ohos::data::cloudData::DBActionInfo actionInfo);
} // namespace AniCloudData
#endif