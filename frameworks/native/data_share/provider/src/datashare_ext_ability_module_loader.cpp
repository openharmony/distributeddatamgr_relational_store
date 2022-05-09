/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "datashare_ext_ability_module_loader.h"
#include "datashare_ext_ability.h"

namespace OHOS::DataShare {
using namespace AbilityRuntime;
DataShareExtAbilityModuleLoader::DataShareExtAbilityModuleLoader() = default;
DataShareExtAbilityModuleLoader::~DataShareExtAbilityModuleLoader() = default;

Extension *DataShareExtAbilityModuleLoader::Create(const std::unique_ptr<Runtime>& runtime) const
{
    return DataShareExtAbility::Create(runtime);
}

extern "C" __attribute__((visibility("default"))) void* OHOS_EXTENSION_GetExtensionModule()
{
    return &DataShareExtAbilityModuleLoader::GetInstance();
}

extern "C" __attribute__((visibility("default"))) void* SetCreator(const CreatorFunc& creator)
{
    return DataShareExtAbility::SetCreator(creator);
}
} // namespace OHOS::DataShare