/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "timer.h"

namespace OHOS {
namespace Utils {

Timer::Timer(const std::string& name, int timeoutMs)
{
}

uint32_t Timer::Setup()
{
    return TIMER_ERR_OK;
}

void Timer::Shutdown(bool useJoin)
{
}

uint32_t Timer::Register(const TimerCallback& callback, uint32_t interval /* ms */, bool once)
{
    return 0;
}

void Timer::Unregister(uint32_t timerId)
{
    return 0;
}

void Timer::MainLoop()
{
}

uint32_t Timer::DoRegister(const TimerListCallback& callback, uint32_t interval, bool once, int &timerFd)
{
    return TIMER_ERR_OK;
}

void Timer::DoUnregister(uint32_t interval)
{
}

void Timer::OnTimer(int timerFd)
{
}

void Timer::DoTimerListCallback(const TimerListCallback& callback, int timerFd)
{
}

/* valid range: [1, UINT32_MAX], but not TIMER_ERR_DEAL_FAILED */
uint32_t Timer::GetValidId(uint32_t timerId) const
{
    return 0;
}

int Timer::GetTimerFd(uint32_t interval /* ms */)
{
    return 0;
}

void Timer::EraseUnusedTimerId(uint32_t interval, const std::vector<uint32_t>& unusedIds)
{
}

} // namespace Utils
} // namespace OHOS
