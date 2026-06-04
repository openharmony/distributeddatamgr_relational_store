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

#ifndef BASE_EVENTHANDLER_INTERFACES_INNER_API_EVENT_HANDLER_H
#define BASE_EVENTHANDLER_INTERFACES_INNER_API_EVENT_HANDLER_H

#include "event_runner.h"
#include "dumper.h"
#include "inner_event.h"

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#if defined(__GNUC__) && __GNUC__ >= 4
    #define EVENTHANDLER_HIDDEN __attribute__((visibility("hidden")))
#else
    #define EVENTHANDLER_HIDDEN
#endif

namespace OHOS {
namespace AppExecFwk {
enum class EventType {
    SYNC_EVENT = 0,
    DELAY_EVENT = 1,
    TIMING_EVENT = 2,
};

template<typename T>
class ThreadLocalData;

struct TaskOptions {
    std::string dfxName_;
    int64_t delayTime_;
    EventQueue::Priority priority_;
    uintptr_t taskId_;
    TaskOptions(std::string dfxName, int64_t delayTime, EventQueue::Priority priority, uintptr_t taskId)
        : dfxName_(dfxName), delayTime_(delayTime), priority_(priority), taskId_(taskId) {}
};

struct PendingTaskInfo {
    int32_t MaxPendingTime = 0;
    int32_t taskCount = 0;
};
class EventHandler : public std::enable_shared_from_this<EventHandler> {
public:
    using CallbackTimeout = std::function<void()>;
    using Callback = InnerEvent::Callback;
    using Priority = EventQueue::Priority;

    /**
     * Constructor, set 'EventRunner' automatically.
     *
     * @param runner The 'EventRunner'.
     */
    explicit EventHandler(const std::shared_ptr<EventRunner> &runner = nullptr);
    virtual ~EventHandler();
    DISALLOW_COPY_AND_MOVE(EventHandler);

    /**
     * Get event handler that running on current thread.
     *
     * @return Returns shared pointer of the current 'EventHandler'.
     */
    static std::shared_ptr<EventHandler> Current();

    /**
     * Send an event.
     *
     * @param event Event which should be handled.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param priority Priority of the event queue for this event.
     * @return Returns true if event has been sent successfully. If returns false, event should be released manually.
     */
    bool SendEvent(InnerEvent::Pointer &event, int64_t delayTime = 0, Priority priority = Priority::LOW);

    /**
     * Send an event.
     *
     * @param event Event which should be handled.
     * @param taskTime Process the event at taskTime.
     * @param priority Priority of the event queue for this event.
     * @return Returns true if event has been sent successfully. If returns false, event should be released manually.
     */
    bool SendTimingEvent(InnerEvent::Pointer &event, int64_t taskTime, Priority priority = Priority::LOW);

    /**
     * Send an event.
     *
     * @param event Event which should be handled.
     * @param priority Priority of the event queue for this event.
     * @return Returns true if event has been sent successfully. If returns false, event should be released manually.
     */
    inline bool SendEvent(InnerEvent::Pointer &event, Priority priority)
    {
        return SendEvent(event, 0, priority);
    }

    /**
     * Send an event.
     *
     * @param event Event which should be handled.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param priority Priority of the event queue for this event.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendEvent(InnerEvent::Pointer &&event, int64_t delayTime = 0, Priority priority = Priority::LOW)
    {
        return SendEvent(event, delayTime, priority);
    }

    /**
     * Send an event.
     *
     * @param innerEventId The id of the event.
     * @param param Basic parameter of the event, default is 0.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendEvent(uint32_t innerEventId, int64_t param, int64_t delayTime, const Caller &caller = {})
    {
        return SendEvent(InnerEvent::Get(innerEventId, param, caller), delayTime);
    }

    /**
     * Send an event.
     *
     * @param innerEventId The id of the event.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param priority Priority of the event queue for this event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendEvent(uint32_t innerEventId, int64_t delayTime = 0,
                          Priority priority = Priority::LOW, const Caller &caller = {})
    {
        return SendEvent(InnerEvent::Get(innerEventId, 0, caller), delayTime, priority);
    }

    /**
     * Send an event.
     *
     * @param innerEventId The id of the event.
     * @param priority Priority of the event queue for this event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendEvent(uint32_t innerEventId, Priority priority, const Caller &caller = {})
    {
        return SendEvent(InnerEvent::Get(innerEventId, 0, caller), 0, priority);
    }

    /**
     * Send an event.
     *
     * @param innerEventId The id of the event.
     * @param object Shared pointer of object.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T>
    inline bool SendEvent(uint32_t innerEventId, const std::shared_ptr<T> &object,
                          int64_t delayTime = 0, const Caller &caller = {})
    {
        return SendEvent(InnerEvent::Get(innerEventId, object, 0, caller), delayTime);
    }

    /**
     * Send an event.
     *
     * @param innerEventId The id of the event.
     * @param object Weak pointer of object.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T>
    inline bool SendEvent(uint32_t innerEventId, const std::weak_ptr<T> &object,
                          int64_t delayTime = 0, const Caller &caller = {})
    {
        return SendEvent(InnerEvent::Get(innerEventId, object, 0, caller), delayTime);
    }

    /**
     * Send an event.
     *
     * @param innerEventId The id of the event.
     * @param object Unique pointer of object.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T, typename D>
    inline bool SendEvent(uint32_t innerEventId, std::unique_ptr<T, D> &object,
                          int64_t delayTime = 0, const Caller &caller = {})
    {
        return SendEvent(InnerEvent::Get(innerEventId, object, 0, caller), delayTime);
    }

    /**
     * Send an event.
     *
     * @param innerEventId The id of the event.
     * @param object Unique pointer of object.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T, typename D>
    inline bool SendEvent(uint32_t innerEventId, std::unique_ptr<T, D> &&object,
                          int64_t delayTime = 0, const Caller &caller = {})
    {
        return SendEvent(InnerEvent::Get(innerEventId, object, 0, caller), delayTime);
    }

    /**
     * Send an immediate event.
     *
     * @param event Event which should be handled.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendImmediateEvent(InnerEvent::Pointer &event)
    {
        return SendEvent(event, 0, Priority::IMMEDIATE);
    }

    /**
     * Send an immediate event.
     *
     * @param event Event which should be handled.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendImmediateEvent(InnerEvent::Pointer &&event)
    {
        return SendImmediateEvent(event);
    }

    /**
     * Send an immediate event.
     *
     * @param innerEventId The id of the event.
     * @param param Basic parameter of the event, default is 0.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendImmediateEvent(uint32_t innerEventId, int64_t param = 0, const Caller &caller = {})
    {
        return SendImmediateEvent(InnerEvent::Get(innerEventId, param, caller));
    }

    /**
     * Send an immediate event.
     *
     * @param innerEventId The id of the event.
     * @param object Shared pointer of object.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T>
    inline bool SendImmediateEvent(uint32_t innerEventId, const std::shared_ptr<T> &object,
                                   const Caller &caller = {})
    {
        return SendImmediateEvent(InnerEvent::Get(innerEventId, object, 0, caller));
    }

    /**
     * Send an immediate event.
     *
     * @param innerEventId The id of the event.
     * @param object Weak pointer of object.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T>
    inline bool SendImmediateEvent(uint32_t innerEventId, const std::weak_ptr<T> &object,
                                   const Caller &caller = {})
    {
        return SendImmediateEvent(InnerEvent::Get(innerEventId, object, 0, caller));
    }

    /**
     * Send an immediate event.
     *
     * @param innerEventId The id of the event.
     * @param object Unique pointer of object.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T, typename D>
    inline bool SendImmediateEvent(uint32_t innerEventId, std::unique_ptr<T, D> &object,
                                   const Caller &caller = {})
    {
        return SendImmediateEvent(InnerEvent::Get(innerEventId, object, 0, caller));
    }

    /**
     * Send an immediate event.
     *
     * @param innerEventId The id of the event.
     * @param object Unique pointer of object.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T, typename D>
    inline bool SendImmediateEvent(uint32_t innerEventId, std::unique_ptr<T, D> &&object,
                                   const Caller &caller = {})
    {
        return SendImmediateEvent(InnerEvent::Get(innerEventId, object, 0, caller));
    }

    /**
     * Send an high priority event.
     *
     * @param event Event which should be handled.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendHighPriorityEvent(InnerEvent::Pointer &event, int64_t delayTime = 0)
    {
        return SendEvent(event, delayTime, Priority::HIGH);
    }

    /**
     * Send an high priority event.
     *
     * @param event Event which should be handled.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendHighPriorityEvent(InnerEvent::Pointer &&event, int64_t delayTime = 0)
    {
        return SendHighPriorityEvent(event, delayTime);
    }

    /**
     * Send an high priority event.
     *
     * @param innerEventId The id of the event.
     * @param param Basic parameter of the event, default is 0.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendHighPriorityEvent(uint32_t innerEventId, int64_t param = 0,
                                      int64_t delayTime = 0, const Caller &caller = {})
    {
        return SendHighPriorityEvent(InnerEvent::Get(innerEventId, param, caller), delayTime);
    }

    /**
     * Send an high priority event.
     *
     * @param innerEventId The id of the event.
     * @param object Shared pointer of object.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T>
    inline bool SendHighPriorityEvent(uint32_t innerEventId, const std::shared_ptr<T> &object,
                                      int64_t delayTime = 0, const Caller &caller = {})
    {
        return SendHighPriorityEvent(InnerEvent::Get(innerEventId, object, 0, caller), delayTime);
    }

    /**
     * Send an high priority event.
     *
     * @param innerEventId The id of the event.
     * @param object Weak pointer of object.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T>
    inline bool SendHighPriorityEvent(uint32_t innerEventId, const std::weak_ptr<T> &object,
                                      int64_t delayTime = 0, const Caller &caller = {})
    {
        return SendHighPriorityEvent(InnerEvent::Get(innerEventId, object, 0, caller), delayTime);
    }

    /**
     * Send an high priority event.
     *
     * @param innerEventId The id of the event.
     * @param object Unique pointer of object.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T, typename D>
    inline bool SendHighPriorityEvent(uint32_t innerEventId, std::unique_ptr<T, D> &object,
                                      int64_t delayTime = 0, const Caller &caller = {})
    {
        return SendHighPriorityEvent(InnerEvent::Get(innerEventId, object, 0, caller), delayTime);
    }

    /**
     * Send an high priority event.
     *
     * @param innerEventId The id of the event.
     * @param object Unique pointer of object.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T, typename D>
    inline bool SendHighPriorityEvent(uint32_t innerEventId, std::unique_ptr<T, D> &&object,
                                      int64_t delayTime = 0, const Caller &caller = {})
    {
        return SendHighPriorityEvent(InnerEvent::Get(innerEventId, object, 0, caller), delayTime);
    }

    /**
     * Post a task.
     *
     * @param callback Task callback.
     * @param name Name of the task.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param priority Priority of the event queue for this event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if task has been sent successfully.
     */
    inline bool PostTask(const Callback &callback, const std::string &name = std::string(),
                         int64_t delayTime = 0, Priority priority = Priority::LOW, const Caller &caller = {})
    {
        return SendEvent(InnerEvent::Get(callback, name, caller), delayTime, priority);
    }

    /**
     * Post a task at front of queue.
     *
     * @param callback Task callback.
     * @param name Name of the task.
     * @param priority Priority of the event queue for this event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @param option VsyncBarrierOption of the event, default is no barrier.
     * @return Returns true if task has been sent successfully.
     */
    bool PostTaskAtFront(const Callback &callback, const std::string &name = std::string(),
                         Priority priority = Priority::LOW, const Caller &caller = {},
                         VsyncBarrierOption option = VsyncBarrierOption::NO_BARRIER);

    /**
     * Post a task at tail of queue.
     *
     * @param callback Task callback.
     * @param name Name of the task.
     * @param priority Priority of the event queue for this event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @param option VsyncBarrierOption of the event, default is no barrier.
     * @return Returns true if task has been sent successfully.
     */
    bool PostTaskAtTail(const Callback &callback, const std::string &name = std::string(),
                        Priority priority = Priority::LOW, const Caller &caller = {},
                        VsyncBarrierOption option = VsyncBarrierOption::NO_BARRIER);

    /**
     * Set delivery time out callback.
     *
     * @param callback Delivery Time out callback.
     */
    void SetDeliveryTimeoutCallback(const Callback &callback)
    {
        deliveryTimeoutCallback_ = callback;
    }

    /**
     * Set distribute time out callback.
     *
     * @param callback Distribute Time out callback.
     */
    void SetDistributeTimeoutCallback(const Callback &callback)
    {
        distributeTimeoutCallback_ = callback;
    }

    /**
     * Post a task.
     *
     * @param callback Task callback.
     * @param priority Priority of the event queue for this event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if task has been sent successfully.
     */
    inline bool PostTask(const Callback &callback, Priority priority, const Caller &caller = {})
    {
        return PostTask(callback, std::string(), 0, priority, caller);
    }

    /**
     * Post a task.
     *
     * @param callback Task callback.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param priority Priority of the event queue for this event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if task has been sent successfully.
     */
    inline bool PostTask(const Callback &callback, int64_t delayTime, Priority priority = Priority::LOW,
                         const Caller &caller = {})
    {
        return PostTask(callback, std::string(), delayTime, priority, caller);
    }

    /**
     * Post an immediate task.
     *
     * @param callback Task callback.
     * @param name Remove events by name of the task.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if task has been sent successfully.
     */
    inline bool PostImmediateTask(const Callback &callback, const std::string &name = std::string(),
                                  const Caller &caller = {})
    {
        return SendEvent(InnerEvent::Get(callback, name, caller), 0, Priority::IMMEDIATE);
    }

    /**
     * Post a high priority task.
     *
     * @param callback Task callback.
     * @param name Name of the task.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if task has been sent successfully.
     */
    inline bool PostHighPriorityTask(const Callback &callback, const std::string &name = std::string(),
                                     int64_t delayTime = 0, const Caller &caller = {})
    {
        return PostTask(callback, name, delayTime, Priority::HIGH, caller);
    }

    /**
     * Post a high priority task.
     *
     * @param callback Task callback.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if task has been sent successfully.
     */
    inline bool PostHighPriorityTask(const Callback &callback, int64_t delayTime, const Caller &caller = {})
    {
        return PostHighPriorityTask(callback, std::string(), delayTime, caller);
    }

    /**
     * Post a idle task.
     *
     * @param callback task callback.
     * @param name Name of the task.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if task has been sent successfully.
     */
    inline bool PostIdleTask(const Callback &callback, const std::string &name = std::string(),
                             int64_t delayTime = 0, const Caller &caller = {})
    {
        return PostTask(callback, name, delayTime, Priority::IDLE, caller);
    }

    /**
     * Post a idle task.
     *
     * @param callback Task callback.
     * @param delayTime Process the event after 'delayTime' milliseconds.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if task has been sent successfully.
     */
    inline bool PostIdleTask(const Callback &callback, int64_t delayTime, const Caller &caller = {})
    {
        return PostIdleTask(callback, std::string(), delayTime, caller);
    }

    /**
     * Send an event, and wait until this event has been handled.
     *
     * @param event Event which should be handled.
     * @param priority Priority of the event queue for this event, IDLE is not permitted for sync event.
     * @return Returns true if event has been sent successfully. If returns false, event should be released manually.
     */
    bool SendSyncEvent(InnerEvent::Pointer &event, Priority priority = Priority::LOW);

    /**
     * Send an event.
     *
     * @param event Event which should be handled.
     * @param priority Priority of the event queue for this event.
     * @param priority Priority of the event queue for this event, IDLE is not permitted for sync event.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendSyncEvent(InnerEvent::Pointer &&event, Priority priority = Priority::LOW)
    {
        return SendSyncEvent(event, priority);
    }

    /**
     * Send an event, and wait until this event has been handled.
     *
     * @param innerEventId The id of the event.
     * @param param Basic parameter of the event, default is 0.
     * @param priority Priority of the event queue for this event, IDLE is not permitted for sync event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendSyncEvent(uint32_t innerEventId, int64_t param = 0,
                              Priority priority = Priority::LOW, const Caller &caller = {})
    {
        return SendSyncEvent(InnerEvent::Get(innerEventId, param, caller), priority);
    }

    /**
     * Send an event, and wait until this event has been handled.
     *
     * @param innerEventId The id of the event.
     * @param priority Priority of the event queue for this event, IDLE is not permitted for sync event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendSyncEvent(uint32_t innerEventId, Priority priority, const Caller &caller = {})
    {
        return SendSyncEvent(InnerEvent::Get(innerEventId, 0, caller), priority);
    }

    /**
     * Send an event, and wait until this event has been handled.
     *
     * @param innerEventId The id of the event.
     * @param object Shared pointer of object.
     * @param priority Priority of the event queue for this event, IDLE is not permitted for sync event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T>
    inline bool SendSyncEvent(uint32_t innerEventId, const std::shared_ptr<T> &object,
                              Priority priority = Priority::LOW, const Caller &caller = {})
    {
        return SendSyncEvent(InnerEvent::Get(innerEventId, object, 0, caller), priority);
    }

    /**
     * Send an event, and wait until this event has been handled.
     *
     * @param innerEventId The id of the event.
     * @param object Weak pointer of object.
     * @param priority Priority of the event queue for this event, IDLE is not permitted for sync event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T>
    inline bool SendSyncEvent(uint32_t innerEventId, const std::weak_ptr<T> &object,
                              Priority priority = Priority::LOW, const Caller &caller = {})
    {
        return SendSyncEvent(InnerEvent::Get(innerEventId, object, 0, caller), priority);
    }

    /**
     * Send an event, and wait until this event has been handled.
     *
     * @param innerEventId The id of the event.
     * @param object Unique pointer of object.
     * @param priority Priority of the event queue for this event, IDLE is not permitted for sync event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T, typename D>
    inline bool SendSyncEvent(uint32_t innerEventId, std::unique_ptr<T, D> &object,
                              Priority priority = Priority::LOW, const Caller &caller = {})
    {
        return SendSyncEvent(InnerEvent::Get(innerEventId, object, 0, caller), priority);
    }

    /**
     * Send an event, and wait until this event has been handled.
     *
     * @param innerEventId The id of the event.
     * @param object Unique pointer of object.
     * @param priority Priority of the event queue for this event, IDLE is not permitted for sync event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T, typename D>
    inline bool SendSyncEvent(uint32_t innerEventId, std::unique_ptr<T, D> &&object,
                              Priority priority = Priority::LOW, const Caller &caller = {})
    {
        return SendSyncEvent(InnerEvent::Get(innerEventId, object, 0, caller), priority);
    }

    /**
     * Post a task, and wait until this task has been handled.
     *
     * @param callback Task callback.
     * @param name Name of the task.
     * @param priority Priority of the event queue for this event, IDLE is not permitted for sync event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if task has been sent successfully.
     */
    inline bool PostSyncTask(const Callback &callback, const std::string &name,
                             Priority priority = Priority::LOW, const Caller &caller = {})
    {
        return SendSyncEvent(InnerEvent::Get(callback, name, caller), priority);
    }

    /**
     * Post a task, and wait until this task has been handled.
     *
     * @param callback Task callback.
     * @param priority Priority of the event queue for this event, IDLE is not permitted for sync event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if task has been sent successfully.
     */
    inline bool PostSyncTask(const Callback &callback, Priority priority = Priority::LOW,
                             const Caller &caller = {})
    {
        return PostSyncTask(callback, std::string(), priority, caller);
    }

    /**
     * Send a timing event.
     *
     * @param event Event which should be handled.
     * @param taskTime Process the event at taskTime.
     * @param priority Priority of the event queue for this event.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendTimingEvent(InnerEvent::Pointer &&event, int64_t taskTime, Priority priority)
    {
        return SendTimingEvent(event, taskTime, priority);
    }

    /**
     * Send a timing event.
     *
     * @param event Event which should be handled.
     * @param taskTime Process the event at taskTime.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendTimingEvent(InnerEvent::Pointer &&event, int64_t taskTime)
    {
        return SendTimingEvent(event, taskTime, Priority::LOW);
    }

    /**
     * Send a timing event.
     *
     * @param innerEventId The id of the event.
     * @param taskTime Process the event at taskTime.
     * @param param Basic parameter of the event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendTimingEvent(uint32_t innerEventId, int64_t taskTime, int64_t param,
                                const Caller &caller = {})
    {
        return SendTimingEvent(InnerEvent::Get(innerEventId, param, caller), taskTime);
    }

    /**
     * Send a timing event.
     *
     * @param innerEventId The id of the event.
     * @param taskTime Process the event at taskTime.
     * @param priority Priority of the event queue for this event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendTimingEvent(uint32_t innerEventId, int64_t taskTime, Priority priority,
                                const Caller &caller = {})
    {
        return SendTimingEvent(InnerEvent::Get(innerEventId, 0, caller), taskTime, priority);
    }

    /**
     * Send a timing event.
     *
     * @param innerEventId The id of the event.
     * @param taskTime Process the event at taskTime.
     * @param priority Priority of the event queue for this event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    inline bool SendTimingEvent(uint32_t innerEventId, int64_t taskTime, const Caller &caller = {})
    {
        return SendTimingEvent(InnerEvent::Get(innerEventId, 0, caller), taskTime, Priority::LOW);
    }

    /**
     * Send a timing event.
     *
     * @param innerEventId The id of the event.
     * @param object Shared pointer of object.
     * @param taskTime Process the event at taskTime.
     * @param priority Priority of the event queue for this event
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T>
    inline bool SendTimingEvent(uint32_t innerEventId, const std::shared_ptr<T> &object, int64_t taskTime,
                                Priority priority = Priority::LOW, const Caller &caller = {})
    {
        return SendTimingEvent(InnerEvent::Get(innerEventId, object, 0, caller), taskTime, priority);
    }

    /**
     * Send a timing event.
     *
     * @param innerEventId The id of the event.
     * @param object Weak pointer of object.
     * @param taskTime Process the event at taskTime.
     * @param priority Priority of the event queue for this event
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T>
    inline bool SendTimingEvent(uint32_t innerEventId, const std::weak_ptr<T> &object, int64_t taskTime,
                                Priority priority = Priority::LOW, const Caller &caller = {})
    {
        return SendTimingEvent(InnerEvent::Get(innerEventId, object, 0, caller), taskTime, priority);
    }

    /**
     * Send a timing event.
     *
     * @param innerEventId The id of the event.
     * @param object Unique pointer of object.
     * @param taskTime Process the event at taskTime.
     * @param priority Priority of the event queue for this event
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T, typename D>
    inline bool SendTimingEvent(uint32_t innerEventId, std::unique_ptr<T, D> &object, int64_t taskTime,
                                Priority priority = Priority::LOW, const Caller &caller = {})
    {
        return SendTimingEvent(InnerEvent::Get(innerEventId, object, 0, caller), taskTime, priority);
    }

    /**
     * Send a timing event.
     *
     * @param innerEventId The id of the event.
     * @param object Unique pointer of object.
     * @param taskTime Process the event at taskTime.
     * @param priority Priority of the event queue for this event
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if event has been sent successfully.
     */
    template<typename T, typename D>
    inline bool SendTimingEvent(uint32_t innerEventId, std::unique_ptr<T, D> &&object, int64_t taskTime,
                                Priority priority = Priority::LOW, const Caller &caller = {})
    {
        return SendTimingEvent(InnerEvent::Get(innerEventId, object, 0, caller), taskTime, priority);
    }

    /**
     * Post a timing task.
     *
     * @param callback Task callback.
     * @param taskTime Process the event at taskTime.
     * @param name Name of the task.
     * @param priority Priority of the event queue for this event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if task has been sent successfully.
     */
    inline bool PostTimingTask(const Callback &callback, int64_t taskTime, const std::string &name = std::string(),
                               Priority priority = Priority::LOW, const Caller &caller = {})
    {
        return SendTimingEvent(InnerEvent::Get(callback, name, caller), taskTime, priority);
    }

    /**
     * Post a timing task.
     *
     * @param callback Task callback.
     * @param taskTime Process the event at taskTime.
     * @param priority Priority of the event queue for this event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns true if task has been sent successfully.
     */
    inline bool PostTimingTask(const Callback &callback, int64_t taskTime, Priority priority = Priority::LOW,
                               const Caller &caller = {})
    {
        return PostTimingTask(callback, taskTime, std::string(), priority, caller);
    }

    /**
     * Remove all sent events.
     */
    void RemoveAllEvents();

    /**
     * Remove sent events.
     *
     * @param innerEventId The id of the event.
     */
    void RemoveEvent(uint32_t innerEventId);

    /**
     * Remove sent events.
     *
     * @param innerEventId The id of the event.
     * @param param Basic parameter of the event.
     */
    void RemoveEvent(uint32_t innerEventId, int64_t param);

    /**
     * Remove a task.
     *
     * @param name Name of the task.
     */
    void RemoveTask(const std::string &name);

    /**
     * Remove a task.
     *
     * @param name Name of the task.
     */
    int RemoveTaskWithRet(const std::string &name);

    /**
     * Add file descriptor listener for a file descriptor.
     *
     * @param fileDescriptor File descriptor.
     * @param events Events from file descriptor, such as input, output, error
     * @param listener Listener callback.
     * @return Return 'ERR_OK' on success.
     */
    ErrCode AddFileDescriptorListener(int32_t fileDescriptor, uint32_t events,
        const std::shared_ptr<FileDescriptorListener> &listener, const std::string &taskName);

    /**
     * Add file descriptor listener for a file descriptor.
     *
     * @param fileDescriptor File descriptor.
     * @param events Events from file descriptor, such as input, output, error
     * @param listener Listener callback.
     * @param priority Priority of the for file descriptor.
     * @return Return 'ERR_OK' on success.
     */
    ErrCode AddFileDescriptorListener(int32_t fileDescriptor, uint32_t events,
        const std::shared_ptr<FileDescriptorListener> &listener, const std::string &taskName,
        EventQueue::Priority priority);

    /**
     * Remove all file descriptor listeners.
     */
    void RemoveAllFileDescriptorListeners();

    /**
     * Remove file descriptor listener for a file descriptor.
     *
     * @param fileDescriptor File descriptor.
     */
    void RemoveFileDescriptorListener(int32_t fileDescriptor);

    /**
     * Set the 'EventRunner' to the 'EventHandler'.
     *
     * @param runner The 'EventRunner'.
     */
    void SetEventRunner(const std::shared_ptr<EventRunner> &runner);

    /**
     * Get the 'EventRunner' of the 'EventHandler'.
     *
     * @return Return the 'EventRunner'.
     */
    inline const std::shared_ptr<EventRunner> &GetEventRunner() const
    {
        return eventRunner_;
    }

    /**
     * Distribute time out handler.
     *
     * @param beginTime Dotting before distribution.
     */
    void DistributeTimeoutHandler(const InnerEvent::TimePoint& beginTime);

    /**
     * Distribute the event.
     *
     * @param event The event should be distributed.
     */
    void DistributeEvent(const InnerEvent::Pointer &event);

    /**
     * Distribute time out action.
     *
     * @param event The event should be distribute.
     * @param nowStart Dotting before distribution.
     */
    void DistributeTimeAction(const InnerEvent::Pointer &event, InnerEvent::TimePoint nowStart);

    /**
     * Delivery time out action.
     *
     * @param event The event should be distribute.
     * @param nowStart Dotting before distribution.
     */
    void DeliveryTimeAction(const InnerEvent::Pointer &event, InnerEvent::TimePoint nowStart);

    /**
     * Check whether there are events which priority higher than current event. Currently ONLY applicable to
     * the main thread, otherwise it will result in problematic returns.
     * It will return false if the eventQueue is not in barrier mode.
     *
     * @param priority Current priority.
     * @param onlyCheckVsync Only check Vsync.
     * @return Return true if there are higher priority events, otherwise return false.
     */
    bool HasPendingHigherEvent(int32_t priority = -1, bool onlyCheckVsync = true);

    /**
     * Print out the internal information about an object in the specified format,
     * helping you diagnose internal errors of the object.
     *
     * @param dumpr The Dumper object you have implemented to process the output internal information.
     */
    void Dump(Dumper &dumper);

    /**
     * Check whether an event with the given ID can be found among the events that have been sent but not processed.
     *
     * @param innerEventId The id of the event.
     */
    bool HasInnerEvent(uint32_t innerEventId);

    /**
     * Check whether an event carrying the given param can be found among the events that have been sent but not
     * processed.
     *
     * @param param Basic parameter of the event.
     */
    bool HasInnerEvent(int64_t param);

    /**
     * Check whether an event carrying the given param can be found among the events that have been sent but not
     * processed.
     *
     * @param event InnerEvent whose name is to be obtained.
     * @return Returns the task name if the given event contains a specific task; returns the event ID otherwise.
     */
    std::string GetEventName(const InnerEvent::Pointer &event);

    /**
     * Check whether there are events which priority higher than basePrio in subevent queue.
     *
     * @param basePrio base priority
     * @return Return true if there are higher priority events, ohtherwise return false.
    */
    bool HasPreferEvent(int basePrio);

    /**
     * Checks whether the current event handler is idle
     * @return Returns true if current event handler is idle otherwise return false.
     */
    bool IsIdle();

    /**
     * @param enableEventLog dump event log handle time.
     */
    void EnableEventLog(bool enableEventLog = false);

    /**
     * Get handler id, only for inner use
     */
    inline std::string GetHandlerId()
    {
        return handlerId_;
    }

    /**
     * Get pending task info
     */
    PendingTaskInfo QueryPendingTaskInfo(int32_t fileDescriptor);

    /**
     * queue_cancel_and_wait
     */
    void TaskCancelAndWait();

    /**
     * Set priority of event at current.
     *
     * @param priority Priority of event at current.
     */
    void SetCurrentEventPriority(int32_t priority = -1);

    /**
     * Get priority of event at current.
     *
     * @return Return priority of event at current.
     */
    const int32_t &GetCurrentEventPriority();

    /**
     * Set the first force enable time for AppVsync.
     * @enable Enable or not
     * @timeout The timeout duration in nanoseconds
     */
    static inline void SetVsyncFirstForceEnableTime(bool enable, uint64_t timeout)
    {
        auto runner = EventRunner::GetMainEventRunner();
        if (runner) {
            auto queue = runner->GetEventQueue();
            if (queue) {
                queue->SetVsyncFirstForceEnableTime(enable, timeout);
            }
        }
    }

    /**
     * Set the lazy mode for AppVsync.
     * @isLazy Lazy or not
     */
    static inline void SetVsyncLazyMode(bool isLazy)
    {
        auto runner = EventRunner::GetMainEventRunner();
        if (runner) {
            auto queue = runner->GetEventQueue();
            if (queue) {
                queue->SetVsyncLazyMode(isLazy);
            }
        }
    }

    /**
     * Set the policy of AppVsync.
     * @policy corresponding to VsyncPolicy enum
     */
    static inline void SetVsyncPolicy(uint32_t policy)
    {
        if (policy > static_cast<uint32_t>(VsyncPolicy::VSYNC_FIRST_WITHOUT_DEFAULT_BARRIER)) {
            return;
        }
        auto runner = EventRunner::GetMainEventRunner();
        if (runner) {
            auto queue = runner->GetEventQueue();
            if (queue) {
                queue->SetVsyncPolicy(static_cast<VsyncPolicy>(policy));
            }
        }
    }

    /**
     * Notification of request next vsync.
     *
     * @param lastFrameTime is the received time of the last frame.
     * @param period is vsync period, the unit is nanoseconds.
     */
    inline void RequestVsyncNotification(int64_t lastFrameTime, int64_t period)
    {
        auto queue = eventRunner_->GetEventQueue();
        if (queue) {
            queue->UpdateVsyncCheckTime(lastFrameTime, period);
        }
    }

protected:
    /**
     * Process the event. Developers should override this method.
     *
     * @param event The event should be processed.
     */
    virtual void ProcessEvent(const InnerEvent::Pointer &event);

private:
    /**
     * Create a task.
     *
     * @param callback Task callback.
     * @param name Name of the task.
     * @param priority Priority of the event queue for this event.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns a innerEvent pointer if task has been created successfully.
     */
    InnerEvent::Pointer CreateTask(const Callback &callback, const std::string &name,
        Priority priority, const Caller &caller);
    
    std::string handlerId_;
    bool enableEventLog_ {false};
    std::shared_ptr<EventRunner> eventRunner_;
    CallbackTimeout deliveryTimeoutCallback_;
    CallbackTimeout distributeTimeoutCallback_;
    EVENTHANDLER_HIDDEN static thread_local std::weak_ptr<EventHandler> currentEventHandler;
    EVENTHANDLER_HIDDEN static thread_local int32_t currentEventPriority;
};
}  // namespace AppExecFwk
namespace EventHandling = AppExecFwk;
}  // namespace OHOS

#endif  // #ifndef BASE_EVENTHANDLER_INTERFACES_INNER_API_EVENT_HANDLER_H
