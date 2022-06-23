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

#ifndef DATASHARE_EXT_ABILITY_CONTEXT_H
#define DATASHARE_EXT_ABILITY_CONTEXT_H

#include "extension_context.h"

namespace OHOS {
namespace DataShare {
using namespace AbilityRuntime;
/**
 * @brief context supply for datashare
 *
 */
class DataShareExtAbilityContext : public ExtensionContext {
public:
    DataShareExtAbilityContext();
    virtual ~DataShareExtAbilityContext() = default;

    using SelfType = DataShareExtAbilityContext;
    static const size_t CONTEXT_TYPE_ID;

protected:
    bool IsContext(size_t contextTypeId) override
    {
        return contextTypeId == CONTEXT_TYPE_ID || ExtensionContext::IsContext(contextTypeId);
    }
};
}  // namespace DataShare
}  // namespace OHOS
#endif  // DATASHARE_EXT_ABILITY_CONTEXT_H