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

#ifndef HISTOGRAM_PLUGIN_MACROS_H
#define HISTOGRAM_PLUGIN_MACROS_H

#define HISTOGRAM_BOOLEAN(name, sample)
#define HISTOGRAM_ENUMERATION(name, sample, boundary)
#define HISTOGRAM_CUSTOM_COUNTS(name, sample, min, max, bucket_count)
#define HISTOGRAM_TIMES(name, sample)
#define HISTOGRAM_PERCENTAGE(name, sample)

#endif // HISTOGRAM_PLUGIN_MACROS_H
