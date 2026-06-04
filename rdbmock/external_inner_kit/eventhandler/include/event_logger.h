/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef BASE_EVENTHANDLER_INTERFACES_INNER_API_EVENT_LOGGER_H
#define BASE_EVENTHANDLER_INTERFACES_INNER_API_EVENT_LOGGER_H

#include <cinttypes>
#include <functional>
#include <future>
#include <string>
#include <sstream>

#include "hilog/log.h"

namespace OHOS {
namespace AppExecFwk {
inline constexpr uint32_t EH_LOG_DOMAIN = 0xD001201;
#define EH_LOG_LIMIT_INTERVALS 10000 //ms
} // namespace AppExecFwk
} // namespace OHOS

#ifndef EH_FUNC_FMT
#define EH_FUNC_FMT "in %{public}s:%{public}d, "
#endif

#ifndef EH_FUNC_INFO
#define EH_FUNC_INFO __FUNCTION__, __LINE__
#endif

#ifndef EH_FILE_NAME
#define EH_FILE_NAME   (strrchr((__FILE__), '/') ? strrchr((__FILE__), '/') + 1 : (__FILE__))
#endif

#ifndef EH_LINE_INFO
#define EH_LINE_INFO   EH_FILE_NAME, __LINE__
#endif

#define DEFINE_EH_HILOG_LABEL(name) \
    static const constexpr char* EH_LOG_LABEL = (name)

#define HILOGD(fmt, ...) do { \
    if (HiLogIsLoggable(OHOS::AppExecFwk::EH_LOG_DOMAIN, EH_LOG_LABEL, LOG_DEBUG)) { \
        ((void)HILOG_IMPL(LOG_CORE, LOG_DEBUG, EH_LOG_DOMAIN, EH_LOG_LABEL, fmt, ##__VA_ARGS__)); \
    } \
} while (0)

#define HILOGI(fmt, ...) do { \
    ((void)HILOG_IMPL(LOG_CORE, LOG_INFO, EH_LOG_DOMAIN, EH_LOG_LABEL, fmt, ##__VA_ARGS__)); \
} while (0)

#define HILOGW(fmt, ...) do { \
    ((void)HILOG_IMPL(LOG_CORE, LOG_WARN, EH_LOG_DOMAIN, EH_LOG_LABEL, fmt, ##__VA_ARGS__)); \
} while (0)

#define HILOGE(fmt, ...) do { \
    ((void)HILOG_IMPL(LOG_CORE, LOG_ERROR, EH_LOG_DOMAIN, EH_LOG_LABEL, fmt, ##__VA_ARGS__)); \
} while (0)

#define HILOGF(fmt, ...) do { \
    ((void)HILOG_IMPL(LOG_CORE, LOG_FATAL, EH_LOG_DOMAIN, EH_LOG_LABEL, fmt, ##__VA_ARGS__)); \
} while (0)

#define EH_PRINT_LIMIT(type, level, intervals, canPrint)                               \
do {                                                                                    \
    static auto last = std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds>();   \
    static uint32_t supressed = 0;                                                      \
    auto now = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now()); \
    auto duration = now - last;                                                         \
    if (duration.count() >= (intervals)) {                                              \
        last = now;                                                                     \
        supressed = 0;                                                                  \
        (canPrint) = true;                                                              \
    } else {                                                                            \
        supressed++;                                                                    \
        (canPrint) = false;                                                             \
    }                                                                                   \
} while (0)

#define EH_LOGF_LIMIT(fmt, ...)                                        \
do {                                                                    \
    bool can = true;                                                    \
    EH_PRINT_LIMIT(LOG_CORE, LOG_FATAL, EH_LOG_LIMIT_INTERVALS, can); \
    if (can) {                                                          \
        HILOGF(fmt, ##__VA_ARGS__);                                   \
    }                                                                   \
} while (0)

#define EH_LOGE_LIMIT(fmt, ...)                                        \
do {                                                                    \
    bool can = true;                                                    \
    EH_PRINT_LIMIT(LOG_CORE, LOG_ERROR, EH_LOG_LIMIT_INTERVALS, can); \
    if (can) {                                                          \
        HILOGE(fmt, ##__VA_ARGS__);                                   \
    }                                                                   \
} while (0)

#define EH_LOGW_LIMIT(fmt, ...)                                        \
do {                                                                    \
    bool can = true;                                                    \
    EH_PRINT_LIMIT(LOG_CORE, LOG_WARN, EH_LOG_LIMIT_INTERVALS, can);  \
    if (can) {                                                          \
        HILOGW(fmt, ##__VA_ARGS__);                                   \
    }                                                                   \
} while (0)

#define EH_LOGI_LIMIT(fmt, ...)                                        \
do {                                                                    \
    bool can = true;                                                    \
    EH_PRINT_LIMIT(LOG_CORE, LOG_INFO, EH_LOG_LIMIT_INTERVALS, can);  \
    if (can) {                                                          \
        HILOGI(fmt, ##__VA_ARGS__);                                   \
    }                                                                   \
} while (0)

#define EH_LOGD_LIMIT(fmt, ...)                                        \
do {                                                                    \
    bool can = true;                                                    \
    EH_PRINT_LIMIT(LOG_CORE, LOG_DEBUG, EH_LOG_LIMIT_INTERVALS, can); \
    if (can) {                                                          \
        HILOGD(fmt, ##__VA_ARGS__);                                   \
    }                                                                   \
} while (0)

#endif // BASE_EVENTHANDLER_INTERFACES_INNER_API_EVENT_LOGGER_H
