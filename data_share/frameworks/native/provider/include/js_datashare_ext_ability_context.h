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

#ifndef JS_DATASHARE_EXT_ABILITY_CONTEXT_H
#define JS_DATASHARE_EXT_ABILITY_CONTEXT_H

#include <memory>

#include "ability_connect_callback.h"
#include "datashare_ext_ability_context.h"
#include "native_engine/native_engine.h"
#include "native_engine/native_value.h"

namespace OHOS {
namespace DataShare {
using namespace AbilityRuntime;
NativeValue* CreateJsDataShareExtAbilityContext(NativeEngine& engine,
    std::shared_ptr<DataShareExtAbilityContext> context);
} // namespace DataShare
} // namespace OHOS
#endif // JS_DATASHARE_EXT_ABILITY_CONTEXT_H
