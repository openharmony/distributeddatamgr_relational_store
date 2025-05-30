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

#define LOG_TAG "Suspender"
#include "suspender.h"
#include "rdb_sql_log.h"
#include "rdb_perfStat.h"

namespace OHOS::NativeRdb {
Suspender::Suspender(Flag flag) : flag_(flag)
{
    if ((flag_ & SQL_STATISTIC) != 0) {
        DistributedRdb::PerfStat::Pause();
    }
    if ((flag_ & SQL_LOG) != 0) {
        SqlLog::Pause();
    }
}
Suspender::~Suspender()
{
    if ((flag_ & SQL_STATISTIC) != 0) {
        DistributedRdb::PerfStat::Resume();
    }
    if ((flag_ & SQL_LOG) != 0) {
        SqlLog::Resume();
    }
}
} // namespace OHOS::NativeRdb