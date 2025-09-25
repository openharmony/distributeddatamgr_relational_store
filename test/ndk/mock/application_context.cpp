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
#include "application_context.h"

namespace OHOS {
namespace AbilityRuntime {

std::shared_ptr<ApplicationContext> Context::applicationContext_ = nullptr;
std::shared_ptr<ApplicationInfo> ApplicationContext::applicationInfo_ = nullptr;

std::shared_ptr<ApplicationContext> Context::GetApplicationContext()
{
    return applicationContext_;
}

void Context::SetApplicationContext()
{
    applicationContext_ = std::make_shared<ApplicationContext>();
}

std::shared_ptr<ApplicationInfo> ApplicationContext::GetApplicationInfo()
{
    return applicationInfo_;
}

void ApplicationContext::SetApplicationInfo()
{
    applicationInfo_ = std::make_shared<ApplicationInfo>();
}
}  // namespace AbilityRuntime
}  // namespace OHOS