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
#ifndef APPLICATION_CONTEXT_MOCK_H
#define APPLICATION_CONTEXT_MOCK_H

#include <memory>

namespace OHOS {
namespace AbilityRuntime {
class ApplicationContext;
struct ApplicationInfo;

// mock Context from ablity
class Context : public std::enable_shared_from_this<Context> {
public:
    Context() = default;
    virtual ~Context() = default;
    static std::shared_ptr<ApplicationContext> GetApplicationContext();
    static void SetApplicationContext();

    static std::shared_ptr<ApplicationContext> applicationContext_;
};

class ApplicationContext : public Context {
public:
    ApplicationContext() = default;
    ~ApplicationContext() override = default;

    static std::shared_ptr<ApplicationInfo> GetApplicationInfo();
    static void SetApplicationInfo();

    static std::shared_ptr<ApplicationInfo> applicationInfo_;
};

struct ApplicationInfo {
    int32_t apiTargetVersion = 19;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // APPLICATION_CONTEXT_MOCK_H
