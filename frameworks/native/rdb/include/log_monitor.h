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

#ifndef LOG_MONITOR_H
#define LOG_MONITOR_H
#include <string>
#include <mutex>
#include <map>

namespace OHOS::NativeRdb {
class LogMonitor {
public:
    static LogMonitor &GetInstance();
    bool IsPrintLog(std::string);
private:
    static constexpr uint32_t PRINT_CNT = 50;
    static constexpr uint32_t MAX_SIZE = 10000;
    std::mutex mutex_;
    std::map<std::string, uint32_t> logRecord_;
};
} // namespace OHOS::NativeRdb
#endif
