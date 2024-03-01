/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
#include <sys/syscall.h>
#include <unistd.h>
#endif
#include "log_monitor.h"

namespace OHOS::NativeRdb {
LogMonitor &LogMonitor::GetInstance()
{
    static LogMonitor instance;
    return instance;
}

bool LogMonitor::IsPrintLog(std::string logMsg)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    bool isPrint = false;
    std::lock_guard<std::mutex> lock(mutex_);
    if (logRecord_.size() > MAX_SIZE) {
        std::map<std::string, uint32_t>().swap(logRecord_);
    }
    std::string msgTemp = std::to_string(getpid()) + "_" + std::to_string(syscall(SYS_gettid))
        + "_" + logMsg;
    if (logRecord_.count(msgTemp) != 0) {
        if ((++logRecord_[msgTemp] % PRINT_CNT) == 0) {
            logRecord_[msgTemp] = 0;
            isPrint = true;
        }
    } else {
        logRecord_[msgTemp] = 0;
        isPrint = true;
    }
    return isPrint;
#endif
    return true;
}
} // namespace OHOS::NativeRdb