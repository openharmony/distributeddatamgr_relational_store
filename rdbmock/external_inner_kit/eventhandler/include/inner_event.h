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

#ifndef BASE_EVENTHANDLER_INTERFACES_INNER_API_INNER_EVENT_H
#define BASE_EVENTHANDLER_INTERFACES_INNER_API_INNER_EVENT_H

#include <cstdint>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <typeinfo>
#include <variant>

#include "nocopyable.h"

namespace OHOS {
namespace HiviewDFX {
class HiTraceId;
}

namespace AppExecFwk {
constexpr static uint32_t TYPE_U32_INDEX = 0u;
using HiTraceId = OHOS::HiviewDFX::HiTraceId;

class EventHandler;

const std::string LINE_SEPARATOR = "\n";

struct Caller {
    std::string file_ {""};
    int         line_ {0};
    std::string func_ {""};
    std::string dfxName_ {""};
#if __has_builtin(__builtin_FILE)
    Caller(std::string file = __builtin_FILE(), int line = __builtin_LINE(),
           std::string func = __builtin_FUNCTION())
        : file_(file), line_(line), func_(func) {}
#else
    Caller() {}
#endif
    std::string ToString() const
    {
        if (file_.empty()) {
            return std::string("[ ]");
        }
        size_t split = file_.find_last_of("/\\");
        if (split == std::string::npos) {
            split = 0;
        }
        std::string caller("[" + file_.substr(split + 1) + "(" + func_ + ":" + std::to_string(line_) +
            dfxName_ + ")]");
        return caller;
    }

    void ClearCaller()
    {
        file_ = "";
        func_ = "";
        line_ = 0;
    }
};

class InnerEvent final {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = std::chrono::time_point<Clock>;
    using Callback = std::function<void()>;
    using Pointer = std::unique_ptr<InnerEvent, void (*)(InnerEvent *)>;
    using EventId = std::variant<uint32_t, std::string>;
    class Waiter {
    public:
        Waiter() = default;
        virtual ~Waiter() = default;
        DISALLOW_COPY_AND_MOVE(Waiter);

        virtual void Wait() = 0;
        virtual void Notify() = 0;
    };

    DISALLOW_COPY_AND_MOVE(InnerEvent);

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param param Basic parameter of the event, default is 0.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    static Pointer Get(uint32_t innerEventId, int64_t param = 0, const Caller &caller = {});

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param param Basic parameter of the event, default is 0.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    static Pointer Get(const EventId &innerEventId, int64_t param = 0, const Caller &caller = {});

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param object Shared pointer of the object.
     * @param param Basic parameter of the event, default is 0.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    template<typename T>
    static inline Pointer Get(uint32_t innerEventId, const std::shared_ptr<T> &object,
                              int64_t param = 0, const Caller &caller = {})
    {
        auto event = Get(innerEventId, param, caller);
        event->SaveSharedPtr(object);
        return event;
    }

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param object Shared pointer of the object.
     * @param param Basic parameter of the event, default is 0.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    template<typename T>
    static inline Pointer Get(const EventId &innerEventId, const std::shared_ptr<T> &object,
                              int64_t param = 0, const Caller &caller = {})
    {
        auto event = Get(innerEventId, param, caller);
        event->SaveSharedPtr(object);
        return event;
    }

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param object Weak pointer of the object.
     * @param param Basic parameter of the event, default is 0.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    template<typename T>
    static inline Pointer Get(uint32_t innerEventId, const std::weak_ptr<T> &object,
                              int64_t param = 0, const Caller &caller = {})
    {
        auto event = Get(innerEventId, param, caller);
        event->SaveSharedPtr(object);
        return event;
    }

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param object Weak pointer of the object.
     * @param param Basic parameter of the event, default is 0.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    template<typename T>
    static inline Pointer Get(const EventId &innerEventId, const std::weak_ptr<T> &object,
                              int64_t param = 0, const Caller &caller = {})
    {
        auto event = Get(innerEventId, param, caller);
        event->SaveSharedPtr(object);
        return event;
    }

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param object Unique pointer of the object.
     * @param param Basic parameter of the event, default is 0.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    template<typename T, typename D>
    static inline Pointer Get(uint32_t innerEventId, std::unique_ptr<T, D> &&object,
                              int64_t param = 0, const Caller &caller = {})
    {
        auto event = Get(innerEventId, param, caller);
        event->SaveUniquePtr(object);
        return event;
    }

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param object Unique pointer of the object.
     * @param param Basic parameter of the event, default is 0.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    template<typename T, typename D>
    static inline Pointer Get(const EventId &innerEventId, std::unique_ptr<T, D> &&object,
                              int64_t param = 0, const Caller &caller = {})
    {
        auto event = Get(innerEventId, param, caller);
        event->SaveUniquePtr(object);
        return event;
    }

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param object Unique pointer of the object.
     * @param param Basic parameter of the event, default is 0.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    template<typename T, typename D>
    static inline Pointer Get(uint32_t innerEventId, std::unique_ptr<T, D> &object,
                              int64_t param = 0, const Caller &caller = {})
    {
        auto event = Get(innerEventId, param, caller);
        event->SaveUniquePtr(object);
        return event;
    }

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param object Unique pointer of the object.
     * @param param Basic parameter of the event, default is 0.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    template<typename T, typename D>
    static inline Pointer Get(const EventId &innerEventId, std::unique_ptr<T, D> &object,
                              int64_t param = 0, const Caller &caller = {})
    {
        auto event = Get(innerEventId, param, caller);
        event->SaveUniquePtr(object);
        return event;
    }

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param param Basic parameter of the event.
     * @param object Shared pointer of the object.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    template<typename T>
    static inline Pointer Get(uint32_t innerEventId, int64_t param, const std::shared_ptr<T> &object,
                              const Caller &caller = {})
    {
        auto event = Get(innerEventId, param, caller);
        event->SaveSharedPtr(object);
        return event;
    }

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param param Basic parameter of the event.
     * @param object Shared pointer of the object.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    template<typename T>
    static inline Pointer Get(const EventId &innerEventId, int64_t param, const std::shared_ptr<T> &object,
                              const Caller &caller = {})
    {
        auto event = Get(innerEventId, param, caller);
        event->SaveSharedPtr(object);
        return event;
    }

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param param Basic parameter of the event.
     * @param object Weak pointer of the object.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    template<typename T>
    static inline Pointer Get(uint32_t innerEventId, int64_t param, const std::weak_ptr<T> &object,
                              const Caller &caller = {})
    {
        auto event = Get(innerEventId, param, caller);
        event->SaveSharedPtr(object);
        return event;
    }

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param param Basic parameter of the event.
     * @param object Weak pointer of the object.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    template<typename T>
    static inline Pointer Get(const EventId &innerEventId, int64_t param, const std::weak_ptr<T> &object,
                              const Caller &caller = {})
    {
        auto event = Get(innerEventId, param, caller);
        event->SaveSharedPtr(object);
        return event;
    }

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param param Basic parameter of the event.
     * @param object Unique pointer of the object.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    template<typename T, typename D>
    static inline Pointer Get(uint32_t innerEventId, int64_t param, std::unique_ptr<T, D> &&object,
                              const Caller &caller = {})
    {
        auto event = Get(innerEventId, param, caller);
        event->SaveUniquePtr(object);
        return event;
    }

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param param Basic parameter of the event.
     * @param object Unique pointer of the object.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    template<typename T, typename D>
    static inline Pointer Get(const EventId &innerEventId, int64_t param, std::unique_ptr<T, D> &&object,
                              const Caller &caller = {})
    {
        auto event = Get(innerEventId, param, caller);
        event->SaveUniquePtr(object);
        return event;
    }

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param param Basic parameter of the event.
     * @param object Unique pointer of the object.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    template<typename T, typename D>
    static inline Pointer Get(uint32_t innerEventId, int64_t param, std::unique_ptr<T, D> &object,
                              const Caller &caller = {})
    {
        auto event = Get(innerEventId, param, caller);
        event->SaveUniquePtr(object);
        return event;
    }

    /**
     * Get InnerEvent instance from pool.
     *
     * @param innerEventId The id of the event.
     * @param param Basic parameter of the event.
     * @param object Unique pointer of the object.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance.
     */
    template<typename T, typename D>
    static inline Pointer Get(const EventId &innerEventId, int64_t param, std::unique_ptr<T, D> &object,
                              const Caller &caller = {})
    {
        auto event = Get(innerEventId, param, caller);
        event->SaveUniquePtr(object);
        return event;
    }

    /**
     * Get InnerEvent instance from pool.
     *
     * @param callback Callback for task.
     * @param name Name of task.
     * @param caller Caller info of the event, default is caller's file, func and line.
     * @return Returns the pointer of InnerEvent instance, if callback is invalid, returns nullptr object.
     */
    static Pointer Get(const Callback &callback, const std::string &name = std::string(),
                       const Caller &caller = {});

    /**
     * Get InnerEvent instance from pool.
     *
     * @return Returns the pointer of InnerEvent instance
     */
    static Pointer Get();

    /**
     * Get owner of the event.
     *
     * @return Returns owner of the event after it has been sent.
     */
    inline std::shared_ptr<EventHandler> GetOwner() const
    {
        return owner_.lock();
    }

    /**
     * Get weak owner of the event.
     *
     * @return Returns owner of the event after it has been sent.
     */
    inline std::weak_ptr<EventHandler> GetWeakOwner() const
    {
        return owner_;
    }

    /**
     * Set owner of the event.
     *
     * @param owner Owner for the event.
     */
    inline void SetOwner(const std::shared_ptr<EventHandler> &owner)
    {
        owner_ = owner;
    }

    /**
     * Get handle time of the event.
     *
     * @return Returns handle time of the event after it has been sent.
     */
    inline const TimePoint &GetHandleTime() const
    {
        return handleTime_;
    }

    /**
     * Set handle time of the event.
     *
     * @param handleTime Handle time of the event.
     */
    inline void SetHandleTime(const TimePoint &handleTime)
    {
        handleTime_ = handleTime;
    }

    /**
     * Get send time of the event.
     *
     * @return Returns send time of the event after it has been sent.
     */
    inline const TimePoint &GetSendTime() const
    {
        return sendTime_;
    }

    /**
     * Set send time of the event.
     *
     * @param sendTime Send time of the event.
     */
    inline void SetSendTime(const TimePoint &sendTime)
    {
        sendTime_ = sendTime;
    }

    /**
     * Set send kernel thread id of the event.
     *
     * @param senderKernelThreadId Send kernel thread id of the event
     */
    inline void SetSenderKernelThreadId(uint64_t senderKernelThreadId)
    {
        senderKernelThreadId_ = senderKernelThreadId;
    }

    /**
     * Get the kernel thread id of the event.
     *
     * @return Returns kernel thread id of the event after it has been sent.
     */
    inline uint64_t GetSenderKernelThreadId()
    {
        return senderKernelThreadId_;
    }

    /**
     * Get id of the event.
     * Make sure {@link #hasTask} returns false.
     *
     * @return Returns id of the event after it has been sent.
     */
    inline uint32_t GetInnerEventId() const
    {
        if (innerEventId_.index() != TYPE_U32_INDEX) {
            return 0u;
        }
        return std::get<uint32_t>(innerEventId_);
    }

    /**
     * Get id of the event.
     * Make sure {@link #hasTask} returns false.
     *
     * @return Returns id of the event after it has been sent.
     */
    inline EventId GetInnerEventIdEx() const
    {
        return innerEventId_;
    }

    /**
     * Get basic param of the event.
     * Make sure {@link #hasTask} returns false.
     *
     * @return Returns basic param of the event after it has been sent.
     */
    inline int64_t GetParam() const
    {
        return param_;
    }

    /**
     * Get saved object.
     *
     * @return Returns shared pointer of saved object.
     */
    template<typename T>
    std::shared_ptr<T> GetSharedObject() const
    {
        const std::shared_ptr<T> &sharedObject = *reinterpret_cast<const std::shared_ptr<T> *>(smartPtr_);
        if (CalculateSmartPtrTypeId(sharedObject) == smartPtrTypeId_) {
            return sharedObject;
        }

        const std::weak_ptr<T> &weakObject = *reinterpret_cast<const std::weak_ptr<T> *>(smartPtr_);
        if (CalculateSmartPtrTypeId(weakObject) == smartPtrTypeId_) {
            return weakObject.lock();
        }

        WarnSmartPtrCastMismatch();
        return nullptr;
    }

    /**
     * Get saved object.
     *
     * @return Returns unique pointer of saved object.
     */
    template<typename T>
    std::unique_ptr<T> GetUniqueObject() const
    {
        std::unique_ptr<T> &object = *reinterpret_cast<std::unique_ptr<T> *>(smartPtr_);
        if (CalculateSmartPtrTypeId(object) == smartPtrTypeId_) {
            return std::move(object);
        }

        WarnSmartPtrCastMismatch();
        return nullptr;
    }

    /**
     * Get saved object.
     *
     * @return Returns unique pointer of saved object.
     */
    template<typename T, typename D>
    std::unique_ptr<T, D> GetUniqueObject() const
    {
        std::unique_ptr<T, D> &object = *reinterpret_cast<std::unique_ptr<T, D> *>(smartPtr_);
        if (CalculateSmartPtrTypeId(object) == smartPtrTypeId_) {
            return std::move(object);
        }

        WarnSmartPtrCastMismatch();
        return std::unique_ptr<T, D>(nullptr, nullptr);
    }

    /**
     * Get task name.
     * Make sure {@link #hasTask} returns true.
     *
     * @return Returns the task name.
     */
    inline const std::string &GetTaskName() const
    {
        return taskName_;
    }

    /**
     * Get task callback.
     * Make sure {@link #hasTask} returns true.
     *
     * @return Returns the callback of the task.
     */
    inline const Callback &GetTaskCallback() const
    {
        return taskCallback_;
    }

    /**
     * Get task caller info.
     *
     * @return Returns the caller info of the task.
     */
    inline Caller &GetCaller()
    {
        return caller_;
    }

    /**
     * Obtains the Runnable task that will be executed when this InnerEvent is handled.
     *
     * @return Returns the callback of the task.
     */
    inline const Callback &GetTask() const
    {
        return GetTaskCallback();
    }

    /**
     * Check whether it takes a task callback in event.
     *
     * @return Returns true if it takes a task callback.
     */
    inline bool HasTask() const
    {
        return static_cast<bool>(taskCallback_);
    }

    /**
     * Convert TimePoint to human readable string.
     *
     * @param time object represent time
     */
    static std::string DumpTimeToString(const TimePoint &time);

    /**
     * Convert std::chrono::system_clock::time_point to human readable string.
     *
     * @param time object represent time
     */
    static std::string DumpTimeToString(const std::chrono::system_clock::time_point &time);

    /**
     * Prints out the internal information about an object in the specified format,
     * helping you diagnose internal errors of the object.
     *
     * @param return The content of the event.
     */
    std::string Dump();

    /**
     * Prints out the internal information about an object in the specified format,
     * helping you diagnose internal errors of the object.
     *
     * @param return The content of the event for trace.
     */
    std::string TraceInfo();

    /**
     * Release stack id.
     */
    void ReleaseStackId();

    /**
     * Set uniqueId in event.
     */
    void SetEventUniqueId();

    /**
     * Get uniqueId for event.
     *
     * @return Returns uniqueId for event.
     */
    inline std::string GetEventUniqueId()
    {
        return eventId;
    }

    /**
     * Get event priority.
     *
     * @return Returns uniqueId for event.
     */
    inline int32_t GetEventPriority()
    {
        return priority;
    }

    /**
     * Set event priority.
     */
    inline void SetEventPriority(int32_t prio)
    {
        priority = prio;
    }

    /**
     * Set ownerId.
     */
    inline void SetOwnerId(std::string ownerId)
    {
        ownerId_ = ownerId;
    }

    /**
     * Get ownerId.
     */
    inline std::string GetOwnerId()
    {
        return ownerId_;
    }

    /**
     * Set delayTime.
     */
    inline void SetDelayTime(int64_t delayTime)
    {
        delayTime_ = delayTime;
    }

    /**
     * Get delayTime.
     */
    inline int64_t GetDelayTime()
    {
        return delayTime_;
    }

    /**
     * Mark the event is a vsync.
     */
    inline void MarkVsyncTask()
    {
        isVsync_ = true;
    }

    /**
     * Check the event is or not a vsync.
     */
    inline bool IsVsyncTask()
    {
        return isVsync_;
    }

    /**
     * Mark the event can be handled in the barrier mode.
     */
    inline void MarkBarrierTask()
    {
        isBarrier_ = true;
    }

    /**
     * Check the event can be handled in the barrier mode.
     */
    inline bool IsBarrierTask()
    {
        return isBarrier_;
    }

    /**
     * Mark the event sent by enhanced api.
     */
    inline void SetIsEnhanced(const bool isEnhanced)
    {
        isEnhanced_ = isEnhanced;
    }

    /**
     * Check the event whether sent by enhanced api.
     */
    inline bool IsEnhanced()
    {
        return isEnhanced_;
    }

    inline void SetEmitterId(uint32_t emitterId)
    {
        emitterId_ = emitterId;
    }

    inline uint32_t GetEmitterId()
    {
        return emitterId_;
    }

    inline void SetStackId(uint64_t stackId)
    {
        ReleaseStackId();
        stackId_ = stackId;
    }

    inline uint64_t GetStackId()
    {
        return stackId_;
    }
private:
    using SmartPtrDestructor = void (*)(void *);

    InnerEvent() = default;
    ~InnerEvent() = default;

    void ClearEvent();

    static void WarnSmartPtrCastMismatch();

    template<typename T>
    static void ReleaseSmartPtr(void *smartPtr)
    {
        if (smartPtr != nullptr) {
            delete reinterpret_cast<T *>(smartPtr);
        }
    }

    template<typename T>
    inline void SaveSharedPtr(const T &object)
    {
        smartPtrDtor_ = ReleaseSmartPtr<T>;
        smartPtrTypeId_ = CalculateSmartPtrTypeId(object);
        smartPtr_ = new (std::nothrow) T(object);
        if (smartPtr_ == nullptr) {
            return;
        }
    }

    template<typename T>
    inline void SaveUniquePtr(T &object)
    {
        smartPtrDtor_ = ReleaseSmartPtr<T>;
        smartPtrTypeId_ = CalculateSmartPtrTypeId(object);
        smartPtr_ = new (std::nothrow) T(std::move(object));
        if (smartPtr_ == nullptr) {
            return;
        }
    }

    /**
     * if event has trace id ,return trace id, else create span id,
     * store it in event and return.
     *
     * @return return hiTrace Id.
     */
    const std::shared_ptr<HiTraceId> GetOrCreateTraceId();

    /**
     * return trace id.
     *
     * @return return hiTrace Id.
     */
    const std::shared_ptr<HiTraceId> GetTraceId();

    /*
     * Calculate the type id for different smart pointers.
     */
#ifdef __GXX_RTTI
    // If RTTI(Run-Time Type Info) is enabled, use hash code of type info.
    template<typename T>
    static inline size_t CalculateSmartPtrTypeId(const T &)
    {
        return typeid(T).hash_code();
    }
#else   // #ifdef __GXX_RTTI
    // Otherwise, generate type id using smart pointer type and the size of the elements they contain.
    static const size_t SHARED_PTR_TYPE = 0x10000000;
    static const size_t WEAK_PTR_TYPE = 0x20000000;
    static const size_t UNIQUE_PTR_TYPE = 0x30000000;
    static const size_t UNIQUE_PTR_ARRAY_TYPE = 0x40000000;

    template<typename T>
    static inline size_t CalculateSmartPtrTypeId(const std::shared_ptr<T> &)
    {
        return (sizeof(T) | SHARED_PTR_TYPE);
    }

    template<typename T>
    static inline size_t CalculateSmartPtrTypeId(const std::weak_ptr<T> &)
    {
        return (sizeof(T) | WEAK_PTR_TYPE);
    }

    template<typename T, typename D>
    static inline size_t CalculateSmartPtrTypeId(const std::unique_ptr<T, D> &)
    {
        return (sizeof(T) | (sizeof(D) - 1) | UNIQUE_PTR_TYPE);
    }

    template<typename T, typename D>
    static inline size_t CalculateSmartPtrTypeId(const std::unique_ptr<T[], D> &)
    {
        return (sizeof(T) | (sizeof(D) - 1) | UNIQUE_PTR_ARRAY_TYPE);
    }
#endif  // #ifdef __GXX_RTTI

    // Used by event handler to create waiter.
    const std::shared_ptr<Waiter> &CreateWaiter();

    // Used by event handler to tell whether event has waiter.
    bool HasWaiter() const;

    // Let event pool to create instance of events.
    friend class InnerEventPool;
    // Let event handler to access private interface.
    friend class EventHandler;

    std::weak_ptr<EventHandler> owner_;
    TimePoint handleTime_;
    TimePoint sendTime_;
    uint64_t senderKernelThreadId_{0};

    // Event id of the event, if it is not a task object
    EventId innerEventId_ = 0u;

    // Simple parameter for the event.
    int64_t param_{0};

    // Using to save smart pointer
    size_t smartPtrTypeId_{0};
    void *smartPtr_{nullptr};
    SmartPtrDestructor smartPtrDtor_{nullptr};

    // Task callback and its name.
    Callback taskCallback_;
    std::string taskName_;

    // Task event caller info
    Caller caller_;

    // Used for synchronized event.
    std::shared_ptr<Waiter> waiter_;

    // use to store hitrace Id
    std::shared_ptr<HiTraceId> hiTraceId_;

    // use to store event unique Id
    std::string eventId;

    uint32_t emitterId_ = 0;

    int32_t priority = -1;

    bool isVsync_ = false;

    bool isBarrier_ = false;

    std::string ownerId_;

    int64_t delayTime_ = 0;

    bool isEnhanced_ = false;

    uint64_t stackId_ = 0;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // #ifndef BASE_EVENTHANDLER_INTERFACES_INNER_API_INNER_EVENT_H
