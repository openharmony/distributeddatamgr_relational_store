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
#include "event_handler.h"

namespace OHOS {
namespace AppExecFwk {

InnerEvent::Pointer InnerEvent::Get(uint32_t innerEventId, int64_t param, const Caller &caller)
{
    return InnerEvent::Pointer(nullptr, nullptr);
}

InnerEvent::Pointer InnerEvent::Get(const EventId &innerEventId, int64_t param, const Caller &caller)
{
    return InnerEvent::Pointer(nullptr, nullptr);
}

InnerEvent::Pointer InnerEvent::Get(const Callback &callback, const std::string &name, const Caller &caller)
{
    return InnerEvent::Pointer(nullptr, nullptr);
}

InnerEvent::Pointer InnerEvent::Get()
{
    return InnerEvent::Pointer(nullptr, nullptr);
}

EventHandler::EventHandler(const std::shared_ptr<EventRunner> &runner)
    : eventRunner_(runner)
{
}

EventHandler::~EventHandler()
{
}

std::shared_ptr<EventHandler> EventHandler::Current()
{
    return std::shared_ptr<EventHandler>();
}

bool EventHandler::SendEvent(InnerEvent::Pointer &event, int64_t delayTime, Priority priority)
{
    return false;
}

bool EventHandler::SendTimingEvent(InnerEvent::Pointer &event, int64_t taskTime, Priority priority)
{
    return false;
}

void EventHandler::ProcessEvent(const InnerEvent::Pointer &event)
{
}

EventRunner::EventRunner(bool deposit, Mode runningMode)
    : queue_(std::shared_ptr<EventQueue>())
{
}

EventRunner::~EventRunner()
{
}

}  // namespace AppExecFwk
}  // namespace OHOS