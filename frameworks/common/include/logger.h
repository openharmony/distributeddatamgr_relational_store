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

#ifndef RDB_LOGGER_H
#define RDB_LOGGER_H

#include "hilog/log.h"

namespace OHOS {
static inline OHOS::HiviewDFX::HiLogLabel LogLabel()
{
    return { LOG_CORE, 0xD001650, "Rdb" };
}

namespace RdbNdk {
static inline OHOS::HiviewDFX::HiLogLabel LogLabel()
{
    return { LOG_CORE, 0xD001656, "RdbNdk" };
}
} // namespace RdbNdk
} // namespace OHOS

#define FILENAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#define LOG_DEBUG(fmt, ...)                                                               \
    do {                                                                                  \
        using HiLog = OHOS::HiviewDFX::HiLog;                                             \
        auto lable = LogLabel();                                                          \
        if (!HiLogIsLoggable(lable.domain, lable.tag, LogLevel::LOG_DEBUG)) {             \
            break;                                                                        \
        }                                                                                 \
        HiLog::Debug(lable, LOG_TAG "::[%{public}s()-%{public}s:%{public}d]: " fmt, __FUNCTION__, FILENAME, __LINE__, \
            ##__VA_ARGS__); \
    } while (0)

#define LOG_INFO(fmt, ...)                                                               \
    do {                                                                                 \
        using HiLog = OHOS::HiviewDFX::HiLog;                                            \
        auto lable = LogLabel();                                                         \
        if (!HiLogIsLoggable(lable.domain, lable.tag, LogLevel::LOG_INFO)) {       \
            break;                                                                       \
        }                                                                                \
        HiLog::Info(lable, LOG_TAG "::[%{public}s()-%{public}s:%{public}d]: " fmt, __FUNCTION__, FILENAME, __LINE__, \
            ##__VA_ARGS__); \
    } while (0)

#define LOG_WARN(fmt, ...)                                                               \
    do {                                                                                 \
        using HiLog = OHOS::HiviewDFX::HiLog;                                            \
        auto lable = LogLabel();                                                         \
        if (!HiLogIsLoggable(lable.domain, lable.tag, LogLevel::LOG_WARN)) {             \
            break;                                                                       \
        }                                                                                \
        HiLog::Warn(lable, LOG_TAG "::[%{public}s()-%{public}s:%{public}d]: " fmt, __FUNCTION__, FILENAME, __LINE__, \
            ##__VA_ARGS__); \
    } while (0)

#define LOG_ERROR(fmt, ...)                                                               \
    do {                                                                                  \
        using HiLog = OHOS::HiviewDFX::HiLog;                                             \
        auto lable = LogLabel();                                                          \
        if (!HiLogIsLoggable(lable.domain, lable.tag, LogLevel::LOG_ERROR)) {             \
            break;                                                                        \
        }                                                                                 \
        HiLog::Error(lable, LOG_TAG "::[%{public}s()-%{public}s:%{public}d]: " fmt, __FUNCTION__, FILENAME, __LINE__, \
            ##__VA_ARGS__); \
    } while (0)

#define LOG_FATAL(fmt, ...)                                                               \
    do {                                                                                  \
        using HiLog = OHOS::HiviewDFX::HiLog;                                             \
        auto lable = LogLabel();                                                          \
        if (!HiLogIsLoggable(lable.domain, lable.tag, LogLevel::LOG_FATAL)) {             \
            break;                                                                        \
        }                                                                                 \
        HiLog::Fatal(lable, LOG_TAG "::[%{public}s()-%{public}s:%{public}d]: " fmt, __FUNCTION__, FILENAME, __LINE__, \
            ##__VA_ARGS__); \
    } while (0)

#endif // RDB_LOGGER_H
