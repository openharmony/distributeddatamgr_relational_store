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

#ifndef DATA_SHARE_ADAPTER_LOGGER_H
#define DATA_SHARE_ADAPTER_LOGGER_H

#include "hilog/log.h"

namespace OHOS {
namespace RdbDataShareAdapter {
static const OHOS::HiviewDFX::HiLogLabel DATA_SHARE_ADAPTER_LABEL = { LOG_CORE, 0xD001650,
    "DATA_SHARE_ADAPTER" };

#define LOG_DEBUG(...) ((void)OHOS::HiviewDFX::HiLog::Debug(DATA_SHARE_ADAPTER_LABEL, __VA_ARGS__))
#define LOG_INFO(...) ((void)OHOS::HiviewDFX::HiLog::Info(DATA_SHARE_ADAPTER_LABEL, __VA_ARGS__))
#define LOG_WARN(...) ((void)OHOS::HiviewDFX::HiLog::Warn(DATA_SHARE_ADAPTER_LABEL, __VA_ARGS__))
#define LOG_ERROR(...) ((void)OHOS::HiviewDFX::HiLog::Error(DATA_SHARE_ADAPTER_LABEL, __VA_ARGS__))
#define LOG_FATAL(...) ((void)OHOS::HiviewDFX::HiLog::Fatal(DATA_SHARE_ADAPTER_LABEL, __VA_ARGS__))
} // namespace RdbDataShareAdapter
} // namespace OHOS

#endif // DATA_SHARE_ADAPTER_LOGGER_H