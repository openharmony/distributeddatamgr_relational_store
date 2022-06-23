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

#include "js_datashare_ext_ability_context.h"

#include <cstdint>

#include "datashare_log.h"
#include "js_extension_context.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi_common_want.h"
#include "napi_remote_object.h"
#include "napi_common_start_options.h"
#include "start_options.h"

namespace OHOS {
namespace DataShare {
using namespace AbilityRuntime;
namespace {
class JsDataShareExtAbilityContext final {
public:
    explicit JsDataShareExtAbilityContext(const std::shared_ptr<DataShareExtAbilityContext>& context)
        : context_(context) {}
    ~JsDataShareExtAbilityContext() = default;

    static void Finalizer(NativeEngine* engine, void* data, void* hint)
    {
        LOG_INFO("JsAbilityContext::Finalizer is called");
        std::unique_ptr<JsDataShareExtAbilityContext>(static_cast<JsDataShareExtAbilityContext*>(data));
    }
private:
    std::weak_ptr<DataShareExtAbilityContext> context_;
};
} // namespace

NativeValue* CreateJsDataShareExtAbilityContext(NativeEngine& engine,
    std::shared_ptr<DataShareExtAbilityContext> context)
{
    LOG_INFO("CreateJsDataShareExtAbilityContext begin");
    NativeValue* objValue = CreateJsExtensionContext(engine, context);
    NativeObject* object = ConvertNativeValueTo<NativeObject>(objValue);

    std::unique_ptr<JsDataShareExtAbilityContext> jsContext = std::make_unique<JsDataShareExtAbilityContext>(context);
    object->SetNativePointer(jsContext.release(), JsDataShareExtAbilityContext::Finalizer, nullptr);
    return objValue;
}
}  // namespace DataShare
}  // namespace OHOS
