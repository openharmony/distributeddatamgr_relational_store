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

#ifndef BASE_EVENTHANDLER_INTERFACES_INNER_API_EVENT_RUNNER_H
#define BASE_EVENTHANDLER_INTERFACES_INNER_API_EVENT_RUNNER_H

#include <atomic>

#include "event_queue.h"
#include "dumper.h"
#include "event_inner_logger.h"
#include "inner_event.h"
#include "local_handle_adapter.h"

namespace OHOS {
namespace AppExecFwk {
class EventInnerRunner;

// Running mode of eventrunner
enum class Mode: uint32_t {
    DEFAULT = 0,  // Default polling mode
    NO_WAIT,      // One poll mode
};

enum class ThreadMode: uint32_t {
    NEW_THREAD = 0,    // for new thread mode, event handler create thread
    FFRT,           // for new thread mode, use ffrt
};

class EventRunner final {
public:
    EventRunner() = delete;
    ~EventRunner();
    DISALLOW_COPY_AND_MOVE(EventRunner);

    using DistributeBeginTime = std::function<InnerEvent::TimePoint(const std::string&)>;
    using DistributeEndTime = std::function<void(const std::string&, const InnerEvent::TimePoint&)>;
    using CallbackTime = std::function<void(int64_t)>;
    static DistributeBeginTime distributeBegin_;
    static DistributeEndTime distributeEnd_;
    static CallbackTime distributeCallback_;

    /**
     * Create new 'EventRunner'.
     *
     * @deprecated This function is deprecated, use 'Create(const std::string &threadName, ThreadMode threadMode)'.
     * @param inNewThread True if create new thread to start the 'EventRunner' automatically.
     * @param mode default The EventRunner's running mode.
     * @return Returns shared pointer of the new 'EventRunner'.
     */
    static std::shared_ptr<EventRunner> Create(bool inNewThread = true, Mode mode = Mode::DEFAULT,
        EventLockType lockType = EventLockType::STANDARD);

    /**
     * Create new 'EventRunner'.
     *
     * @param inNewThread True if create new thread to start the 'EventRunner' automatically.
     * @param threadMode thread mode, use ffrt or new thread, for inNewThread = true.
     * @return Returns shared pointer of the new 'EventRunner'.
     */
    static std::shared_ptr<EventRunner> Create(bool inNewThread, ThreadMode threadMode,
 	    EventLockType lockType = EventLockType::STANDARD);

    /**
     * Create new 'EventRunner' and start to run in a new thread.
     *
     * @deprecated This function is deprecated, use 'Create(const std::string &threadName, ThreadMode threadMode)'.
     * @param threadName Thread name of the new created thread.
     * @param mode default The EventRunner's running mode.
     * @return Returns shared pointer of the new 'EventRunner'.
     */
    static std::shared_ptr<EventRunner> Create(const std::string &threadName, Mode mode = Mode::DEFAULT,
        EventLockType lockType = EventLockType::STANDARD)
    {
        return Create(threadName, mode, ThreadMode::NEW_THREAD, lockType);
    }

    /**
     * Create new 'EventRunner' and start to run in a new thread.
     *
     * @param threadName Thread name of the new created thread.
     * @param threadMode thread mode, use ffrt or new thread.
     * @return Returns shared pointer of the new 'EventRunner'.
     */
    static std::shared_ptr<EventRunner> Create(const std::string &threadName, ThreadMode threadMode,
 	    EventLockType lockType = EventLockType::STANDARD)
    {
        return Create(threadName, Mode::DEFAULT, threadMode, lockType);
    }

    /**
     * Create new 'EventRunner' and start to run in a new thread.
     * Eliminate ambiguity, while calling like 'EventRunner::Create("threadName")'.
     *
     * @deprecated This function is deprecated, use 'Create(const char *threadName, ThreadMode threadMode)'.
     * @param threadName Thread name of the new created thread.
     * @param mode default The EventRunner's running mode.
     * @return Returns shared pointer of the new 'EventRunner'.
     */
    static inline std::shared_ptr<EventRunner> Create(const char *threadName, Mode mode = Mode::DEFAULT,
 	    EventLockType lockType = EventLockType::STANDARD)
    {
        return Create((threadName != nullptr) ? std::string(threadName) : std::string(), mode,
            ThreadMode::NEW_THREAD, lockType);
    }

    /**
     * Create new 'EventRunner' and start to run in a new thread.
     * Eliminate ambiguity, while calling like 'EventRunner::Create("threadName")'.
     *
     * @param threadName Thread name of the new created thread.
     * @param threadMode thread mode, use ffrt or new thread.
     * @return Returns shared pointer of the new 'EventRunner'.
     */
    static inline std::shared_ptr<EventRunner> Create(const char *threadName, ThreadMode threadMode,
 	    EventLockType lockType = EventLockType::STANDARD)
    {
        return Create((threadName != nullptr) ? std::string(threadName) : std::string(),
            Mode::DEFAULT, threadMode, lockType);
    }

    /**
     * Create new 'EventRunner' for nowait mode.
     *
     * @param threadName Thread name of the new created thread.
     * @return Returns shared pointer of the new 'EventRunner'.
     */
    static std::shared_ptr<EventRunner> CreateNoWait(const std::string &threadName)
    {
        return Create(threadName, Mode::NO_WAIT, ThreadMode::NEW_THREAD, EventLockType::STANDARD);
    }

    /**
     * Get event runner on current thread.
     *
     * @return Returns shared pointer of the current 'EventRunner'.
     */
    static std::shared_ptr<EventRunner> Current();

    /**
     * Start to run the 'EventRunner'. Only used for the 'EventRunner' which is not running in new thread.
     * Only running on single thread.
     *
     * @return Returns 'ERR_OK' on success.
     */
    ErrCode Run();

    /**
     * Stop to run the 'EventRunner'. Only used for the 'EventRunner' which is not running in new thread.
     * It is a good practice to call {@link #Stop} on the same thread that called {@link #Run}.
     *
     * @return Returns 'ERR_OK' on success.
     */
    ErrCode Stop();

    /**
     * Get thread name
     *
     * @return Returns thread name.
     */
    std::string GetRunnerThreadName() const;

    /**
     * Get event queue from event runner.
     * This method only called by 'EventHandler'.
     *
     * @return Returns event queue.
     */
    inline const std::shared_ptr<EventQueue> &GetEventQueue() const
    {
        return queue_;
    }

    /**
     * Obtain the event queue of the EventRunner associated with the current thread.
     *
     * @return Return current event queue.
     */
    static std::shared_ptr<EventQueue> GetCurrentEventQueue();

    /**
     * Print out the internal information about an object in the specified format,
     * helping you diagnose internal errors of the object.
     *
     * @param dumpr The Dumper object you have implemented to process the output internal information.
     */
    void Dump(Dumper &dumper);

    /**
     * Print out the internal information about an object in the specified format,
     * helping you diagnose internal errors of the object.
     *
     * @param runnerInfo runner Info.
     */
    void DumpRunnerInfo(std::string& runnerInfo);

    /**
     * Set the Logger object for logging messages that are processed by this event runner.
     *
     * @param logger The Logger object you have implemented for logging messages.
     */
    void SetLogger(const std::shared_ptr<Logger> &logger);

    /**
     * Obtain the ID of the worker thread associated with this EventRunner.
     *
     * @return thread id.
     */
    uint64_t GetThreadId();

    /**
     * Obtain the kernel thread ID of the worker thread associated with this EventRunner.
     *
     * @return kernel thread id.
     */
    uint64_t GetKernelThreadId();

    /**
     * Check whether the current thread is the worker thread of this EventRunner.
     *
     * @return Returns true if the current thread is the worker thread of this EventRunner; returns false otherwise.
     */
    bool IsCurrentRunnerThread();

    /**
     * Set the distribution standard expiration time.
     *
     * @param deliveryTimeout the distribution standard expiration time.
     */
    void SetDeliveryTimeout(int64_t deliveryTimeout)
    {
        deliveryTimeout_ = deliveryTimeout;
    }

    /**
     * Get the distribution standard expiration time.
     *
     * @return the distribution standard expiration time.
     */
    int64_t GetDeliveryTimeout() const
    {
        return deliveryTimeout_;
    }

    /**
     * Set the execution standard timeout period.
     *
     * @param distributeTimeout the distribution standard expiration time.
     */
    void SetDistributeTimeout(int64_t distributeTimeout)
    {
        distributeTimeout_ = distributeTimeout;
    }

    /**
     * Get the execution standard timeout period.
     *
     * @return the distribution standard expiration time.
     */
    int64_t GetDistributeTimeout() const
    {
        return distributeTimeout_;
    }

    /**
     * Set the main thread timeout period.
     *
     * @param distributeTimeout the distribution standard expiration time.
     */
    void SetTimeout(int64_t distributeTimeout)
    {
        timeout_ = distributeTimeout;
    }

    /**
     * Set distribute time out callback.
     *
     * @param callback Distribute Time out callback.
     */
    void SetTimeoutCallback(CallbackTime callback)
    {
        distributeCallback_ = callback;
    }

    /**
     * Get the execution standard timeout period.
     *
     * @return the distribution standard expiration time.
     */
    int64_t GetTimeout() const
    {
        return timeout_;
    }

    /**
     * set eventRunner env param
     *
     * @param env current env
     */
    inline void EventSetEnvToHandler(void* env)
    {
        env_ = env;
    }

    /**
     * Get current env.
     *
     * @return current env.
     */
    inline void* GetHandleEnv()
    {
        return env_;
    }

    /**
     * set EventOpenLocalHandleFunc and EventCloseLocalHandleFunc
     *
     * @param openFunc eventOpenLocalHandleFunc
     * @param closeFunc eventCloseLocalHandleFunc
     */
    inline void RegisterLocalHandleCallback(EventOpenLocalHandleFunc openFunc, EventCloseLocalHandleFunc closeFunc)
    {
        LocalHandleAdapter::GetInstance().SetLocalHandleFunc(openFunc, closeFunc);
    }

    /**
     * execute current openLocalHandleFunc
     *
     * @param localHandle localHandle
     */
    inline void EventOpenLocalHandle(void** localHandle)
    {
        auto openFunc = LocalHandleAdapter::GetInstance().openLocalHandleFunc;
        if (env_ != nullptr && openFunc != nullptr) {
            openFunc(env_, localHandle);
        }
    }

    /**
     * execute current closeLocalHandleFunc
     *
     * @param localHandle localHandle
     */
    inline void EventCloseLocalHandle(void* localHandle)
    {
        auto closeFunc = LocalHandleAdapter::GetInstance().closeLocalHandleFunc;
        if (env_ != nullptr && closeFunc != nullptr) {
            closeFunc(env_, localHandle);
        }
    }

    /**
     * Check if the current application is the main thread.
     */
    static bool IsAppMainThread();

    /**
     * Set app main thread watcher.
     *
     * @param callback Distribute Start Time callback.
     * @param callback Distribute End Time callback.
     */
    void SetMainLooperWatcher(const DistributeBeginTime begin, const DistributeEndTime end);

    /**
     * Obtains the EventRunner for the main thread of the application.
     *
     * @return Returns the EventRunner for the main thread of the application.
     */
    static std::shared_ptr<EventRunner> GetMainEventRunner();

private:
    explicit EventRunner(bool deposit, Mode runningMode = Mode::DEFAULT);

    friend class EventHandler;

    static std::shared_ptr<EventRunner> Create(const std::string &threadName, Mode mode,
        ThreadMode threadMode, EventLockType lockType);

    /**
     * Check whether this event runner is running.
     *
     * @return if this event runner is running return true otherwise return false
     */
    inline bool IsRunning() const
    {
        // If this runner is deposited, it it always running
        return (deposit_ && runningMode_ == Mode::DEFAULT) || (running_.load());
    }

    /**
     * Start event running for no_wait mode in new thread.
     */
    void StartRunningForNoWait();

    int64_t deliveryTimeout_ = 0;
    int64_t distributeTimeout_ = 0;
    int64_t timeout_ = 0;
    bool deposit_{true};
    std::atomic<bool> running_{false};
    std::shared_ptr<EventQueue> queue_;
    std::shared_ptr<EventInnerRunner> innerRunner_;
    static std::shared_ptr<EventRunner> mainRunner_;
    std::string currentEventInfo_;
    Mode runningMode_ = Mode::DEFAULT;
    ThreadMode threadMode_ = ThreadMode::NEW_THREAD;
    std::string runnerId_;
    void* env_{nullptr};
};
}  // namespace AppExecFwk
namespace EventHandling = AppExecFwk;
}  // namespace OHOS

#endif  // #ifndef BASE_EVENTHANDLER_INTERFACES_INNER_API_EVENT_RUNNER_H
