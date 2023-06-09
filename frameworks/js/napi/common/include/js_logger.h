/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef RDB_JSKIT_LOGGER_H
#define RDB_JSKIT_LOGGER_H

#include <string>
#include <vector>

#include "hilog/log.h"

namespace OHOS {
namespace AppDataMgrJsKit {
static inline OHOS::HiviewDFX::HiLogLabel LogLabel()
{
    return { LOG_CORE, 0xD001650, "AppDataMgrJsKit" };
}
#define LOG_DEBUG(fmt, ...)                                                                                  \
    do {                                                                                                     \
        using HiLog = OHOS::HiviewDFX::HiLog;                                                                \
        auto lable = LogLabel();                                                                             \
        if (!HiLogIsLoggable(lable.domain, lable.tag, LOG_DEBUG)) {                                          \
            break;                                                                                           \
        }                                                                                                    \
        HiLog::Debug(lable, "::%{public}s: %{public}d " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#define LOG_INFO(fmt, ...)                                                                                  \
    do {                                                                                                    \
        using HiLog = OHOS::HiviewDFX::HiLog;                                                               \
        auto lable = LogLabel();                                                                            \
        if (!HiLogIsLoggable(lable.domain, lable.tag, LOG_INFO)) {                                          \
            break;                                                                                          \
        }                                                                                                   \
        HiLog::Info(lable, "::%{public}s: %{public}d " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#define LOG_WARN(fmt, ...)                                                                                  \
    do {                                                                                                    \
        using HiLog = OHOS::HiviewDFX::HiLog;                                                               \
        auto lable = LogLabel();                                                                            \
        if (!HiLogIsLoggable(lable.domain, lable.tag, LOG_WARN)) {                                          \
            break;                                                                                          \
        }                                                                                                   \
        HiLog::Warn(lable, "::%{public}s: %{public}d " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#define LOG_ERROR(fmt, ...)                                                                                  \
    do {                                                                                                     \
        using HiLog = OHOS::HiviewDFX::HiLog;                                                                \
        auto lable = LogLabel();                                                                             \
        if (!HiLogIsLoggable(lable.domain, lable.tag, LOG_ERROR)) {                                          \
            break;                                                                                           \
        }                                                                                                    \
        HiLog::Error(lable, "::%{public}s: %{public}d " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#define LOG_FATAL(fmt, ...)                                                                                  \
    do {                                                                                                     \
        using HiLog = OHOS::HiviewDFX::HiLog;                                                                \
        auto lable = LogLabel();                                                                             \
        if (!HiLogIsLoggable(lable.domain, lable.tag, LOG_ERROR)) {                                          \
            break;                                                                                           \
        }                                                                                                    \
        HiLog::Fatal(lable, "::%{public}s: %{public}d " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } while (0)
} // namespace AppDataMgrJsKit
} // namespace OHOS

#endif
