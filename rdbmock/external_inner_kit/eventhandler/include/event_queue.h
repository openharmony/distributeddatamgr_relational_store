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

#ifndef BASE_EVENTHANDLER_INTERFACES_INNER_API_EVENT_QUEUE_H
#define BASE_EVENTHANDLER_INTERFACES_INNER_API_EVENT_QUEUE_H

#include <array>
#include <atomic>
#include <functional>
#include <list>
#include <map>
#include <mutex>

#include "inner_event.h"
#include "event_handler_errors.h"
#include "file_descriptor_listener.h"
#include "dumper.h"
#include "lock_base.h"

namespace OHOS {
namespace AppExecFwk {
class IoWaiter;
class EventHandler;
class DeamonIoWaiter;
struct PendingTaskInfo;

enum class VsyncPolicy: uint32_t {
    DISABLE_VSYNC_FIRST = 0,
    VSYNC_FIRST_WITH_DEFAULT_BARRIER,
    VSYNC_FIRST_WITHOUT_DEFAULT_BARRIER,
};

enum class EventInsertType: uint32_t {
    // Insert event at end
    AT_END = 0,
    // Insert event at front
    AT_FRONT
};

enum class Observer {
    ARKTS_GC,
};

enum class EventRunnerStage {
    // enter loop
    STAGE_ENTRY_RUNNER = 1<<0,
    // exit loop
    STAGE_EXIT_RUNNER = 1<<1,
    // waiting
    STAGE_BEFORE_WAITING = 1<<2,
    // recover form sleeping
    STAGE_AFTER_WAITING = 1<<3,
    // insert vip task
    STAGE_VIP_EXISTED = 1<<4,
    // current queue not exists vip task
    STAGE_VIP_NONE = 1<<5,
    // invaild key
    STAGE_INVAILD = 0,
};

struct StageInfo {
    // STAGE_BEFORE_WAITING, timesteap
    int64_t timestamp;
    // STAGE_BEFORE_WAITING, milliseconds
    int32_t sleepTime;
    // STAGE_AFTER_WAITING
    int reason;
};

using EventRunnerObserverCallBack = std::function<int(EventRunnerStage stage, const StageInfo* info)>;

struct EventRunnerObserver {
    Observer observer;
    uint32_t stages;
    EventRunnerObserverCallBack notifyCb;
    void ClearObserver()
    {
        stages = static_cast<uint32_t>(EventRunnerStage::STAGE_INVAILD);
        notifyCb = nullptr;
    }
};

struct ObserverTrace {
    std::string source;
    std::string stage;
    ObserverTrace() {};
    ObserverTrace(std::string currentSource, std::string currentStage)
        : source(currentSource), stage(currentStage) {}
    std::string getTraceInfo()
    {
        std::string traceInfo;
        traceInfo.append("Et-obs:");
        if (stage.empty()) {
            traceInfo.append(" ");
        } else {
            traceInfo.append(stage);
        }
        traceInfo.append(",");
        if (!source.empty()) {
            traceInfo.append(source);
        }
        return traceInfo;
    }
};

#define NOW_NS std::chrono::duration_cast<std::chrono::nanoseconds>( \
    InnerEvent::Clock::now().time_since_epoch()).count()
#define CHECK_VSYNC_DELAY_NS        1000000
#define MAX_INIT_VSYNC_PERIOD_NS    34000000
#define MAX_CHECK_VSYNC_PERIOD_NS   69000000

enum class VsyncBarrierOption {
    // Not required handling the designated task before handling the vsync.
    NO_BARRIER = 0,
    // Required handling the designated task before handling vsync when it is sended by the main thread itself.
    NEED_BARRIER = 1,
    // Required handling the designated task before handling vsync for all situations.
    FORCE_BARRIER = 2,
};

class EventQueue {
public:
    // Priority for the events
    enum class Priority : uint32_t {
        // The highest priority queue, should be distributed until the tasks in the queue are completed.
        VIP = 0,
        // Event that should be distributed at once if possible.
        IMMEDIATE,
        // High priority event, sorted by handle time, should be distributed before low priority event.
        HIGH,
        // Normal event, sorted by handle time.
        LOW,
        // Event that should be distributed only if no other event right now.
        IDLE,
    };

    EventQueue();
    explicit EventQueue(const std::shared_ptr<IoWaiter> &ioWaiter);
    explicit EventQueue(EventLockType lockType);
    explicit EventQueue(const std::shared_ptr<IoWaiter> &ioWaiter, EventLockType lockType);
    virtual ~EventQueue();
    DISALLOW_COPY_AND_MOVE(EventQueue);

    /**
     * Insert an event into event queue with different priority.
     * The events will be sorted by handle time.
     *
     * @param event Event instance which should be added into event queue.
     * @param Priority Priority of the event
     * @param insertType The type of insertint event to queue
     *
     * @see #Priority
     */
    virtual bool Insert(InnerEvent::Pointer &event, Priority priority = Priority::LOW,
        EventInsertType insertType = EventInsertType::AT_END,
        VsyncBarrierOption option = VsyncBarrierOption::NO_BARRIER) = 0;

    /**
     * Remove events if its owner is invalid, for base queue.
     */
    virtual void RemoveOrphan() {};

    /**
     * Remove events if its owner is invalid, for ffrt queue.
     */
    virtual void RemoveOrphanByHandlerId(const std::string& handlerId) { (void)handlerId; };

    /**
     * Remove all events.
     */
    virtual void RemoveAll() = 0;

    /**
     * Remove events with specified requirements.
     *
     * @param owner Owner of the event which is point to an instance of 'EventHandler'.
     */
    virtual void Remove(const std::shared_ptr<EventHandler> &owner) = 0;

    /**
     * Remove events with specified requirements.
     *
     * @param owner Owner of the event which is point to an instance of 'EventHandler'.
     * @param innerEventId Remove events by event id.
     */
    virtual void Remove(const std::shared_ptr<EventHandler> &owner, uint32_t innerEventId) = 0;

    /**
     * Remove events with specified requirements.
     *
     * @param owner Owner of the event which is point to an instance of 'EventHandler'.
     * @param innerEventId Remove events by event id.
     * @param param Remove events by value of param.
     */
    virtual void Remove(const std::shared_ptr<EventHandler> &owner, uint32_t innerEventId, int64_t param) = 0;

    /**
     * Remove events with specified requirements.
     *
     * @param owner Owner of the event which is point to an instance of 'EventHandler'.
     * @param name Remove events by name of the task.
     */
    virtual bool Remove(const std::shared_ptr<EventHandler> &owner, const std::string &name) = 0;

    /**
     * Add file descriptor listener for a file descriptor.
     *
     * @param fileDescriptor File descriptor.
     * @param events Events from file descriptor, such as input, output, error
     * @param listener Listener callback.
     * @return Return 'ERR_OK' on success.
     */
    virtual ErrCode AddFileDescriptorListener(int32_t fileDescriptor, uint32_t events,
        const std::shared_ptr<FileDescriptorListener> &listener, const std::string &taskName,
        Priority priority = Priority::HIGH) = 0;

    /**
     * Remove all file descriptor listeners for a specified owner.
     *
     * @param owner Owner of the event which is point to an instance of 'FileDescriptorListener'.
     */
    virtual void RemoveFileDescriptorListener(const std::shared_ptr<EventHandler> &owner) = 0;

    /**
     * Remove file descriptor listener for a file descriptor.
     *
     * @param fileDescriptor File descriptor.
     */
    virtual void RemoveFileDescriptorListener(int32_t fileDescriptor) = 0;

    /**
     * Prepare event queue, before calling {@link #GetEvent}.
     * If {@link #Finish} is called, prepare event queue again, before calling {@link #GetEvent}.
     */
    virtual void Prepare() = 0;

    /**
     * Exit from blocking in {@link #GetEvent}, and mark the event queue finished.
     * After calling {@link #Finish}, {@link #GetEvent} never returns any event, until {@link #Prepare} is called.
     */
    virtual void Finish() = 0;

    /**
     * Get event from event queue one by one.
     * Before calling this method, developers should call {@link #Prepare} first.
     * If none should be handled right now, the thread will be blocked in this method.
     * Call {@link #Finish} to exit from blocking.
     *
     * @return Returns nullptr if event queue is not prepared yet, or {@link #Finish} is called.
     * Otherwise returns event instance.
     */
    virtual InnerEvent::Pointer GetEvent();

    /**
     * Get expired event from event queue one by one.
     * Before calling this method, developers should call {@link #Prepare} first.
     *
     * @param nextExpiredTime Output the expired time for the next event.
     * @return Returns nullptr if none in event queue is expired.
     * Otherwise returns event instance.
     */
    virtual InnerEvent::Pointer GetExpiredEvent(InnerEvent::TimePoint &nextExpiredTime);

    /**
     * Prints out the internal information about an object in the specified format,
     * helping you diagnose internal errors of the object.
     *
     * @param dumper The Dumper object you have implemented to process the output internal information.
     */
    virtual void Dump(Dumper &dumper) = 0;

    /**
     * Print out the internal information about an object in the specified format,
     * helping you diagnose internal errors of the object.
     *
     * @param queueInfo queue Info.
     */
    virtual void DumpQueueInfo(std::string& queueInfo) = 0;

    /**
     * Checks whether the current EventHandler is idle.
     *
     * @return Returns true if all events have been processed; returns false otherwise.
     */
    virtual bool IsIdle() = 0;

    /**
     * Check whether this event queue is empty.
     *
     * @return If queue is empty return true otherwise return false.
     */
    virtual bool IsQueueEmpty() = 0;

    /**
     * Check whether an event with the given ID can be found among the events that have been sent but not processed.
     *
     * @param owner Owner of the event which is point to an instance of 'EventHandler'.
     * @param innerEventId The id of the event.
     */
    virtual bool HasInnerEvent(const std::shared_ptr<EventHandler> &owner, uint32_t innerEventId) = 0;

    /**
     * Check whether an event carrying the given param can be found among the events that have been sent but not
     * processed.
     *
     * @param owner The owner of the event which is point to an instance of 'EventHandler'.
     * @param param The basic parameter of the event.
     */
    virtual bool HasInnerEvent(const std::shared_ptr<EventHandler> &owner, int64_t param) = 0;

    virtual void PushHistoryQueueBeforeDistribute(const InnerEvent::Pointer &event) { (void)event; }

    virtual void PushHistoryQueueAfterDistribute() {}

    virtual bool HasPreferEvent(int basePrio) = 0;

    virtual std::string DumpCurrentQueueSize() = 0;

    /**
     * Check whether there are currenty file descriptors is need to be processed.
     */
    void CheckFileDescriptorEvent();

    /**
     * Set waiter mode, true for deamon io waiter
     */
    void SetIoWaiter(bool useDeamonIoWaiter)
    {
        useDeamonIoWaiter_ = useDeamonIoWaiter;
    }

    /**
     * Get ffrt queue handler type, only for ffrt thread mode.
     */
    virtual void* GetFfrtQueue() { return nullptr; }

    /**
     * Insert task to ffrt queue, and wait to handled, only for ffrt thread mode.
     */
    virtual bool InsertSyncEvent(InnerEvent::Pointer &event, Priority priority = Priority::LOW,
        EventInsertType insertType = EventInsertType::AT_END)
    {
        (void)event;
        (void)priority;
        (void)insertType;
        return true;
    }

    /**
     * Get pending task info
     */
    virtual PendingTaskInfo QueryPendingTaskInfo(int32_t fileDescriptor) = 0;
    /**
     * add observer
     *
     * @param observer runner observer.
     * @param stages The stages of observer
     * @param callback observer callback.
     */
    void AddObserver(Observer observer, uint32_t stages, EventRunnerObserverCallBack callback)
    {
        observer_.observer = observer;
        observer_.notifyCb = callback;
        observer_.stages = stages;
    }

    /**
     * Cancel And Wait
     */
    virtual void CancelAndWait() = 0;

    /**
     * notify GC Observer vip events finished
     */
    virtual void NotifyObserverVipDone(const InnerEvent::Pointer &event);

    /**
     * Get the first event handle time in the prioritized task queue.
     *
     * @param now Current timeStamp.
     * @param priority The specified priority.
     * @param onlyCheckVsync Only check Vsync.
     */
    virtual uint64_t GetQueueFirstEventHandleTime(uint64_t now, int32_t priority, bool onlyCheckVsync = true) = 0;

    /**
     * Set the first force enable time for AppVsync.
     * @enable Enable or not
     * @timeout The timeout duration in nanoseconds
     */
    void SetVsyncFirstForceEnableTime(bool enable, uint64_t timeout);

    /**
     * Set the lazy mode for AppVsync
     */
    void SetVsyncLazyMode(bool isLazy);

    /**
     * Set the policy of AppVsync
     */
    void SetVsyncPolicy(VsyncPolicy vsyncPolicy);

    /**
     * the vsync task is comming.
     */
    inline void DispatchVsyncTaskNotify()
    {
        ++sumOfPendingVsync_;
        vsyncRecvTime_ = NOW_NS;
        if (vsyncRecvTime_ > vsyncCheckTime_) {
            vsyncRecvTime_ = vsyncCheckTime_;
        }
        needEpoll_ = true;
        vsyncCheckTime_ = INT64_MAX;
    }

    /**
     * handling the vsync task is completed.
    */
    inline void HandleVsyncTaskCompletely()
    {
        vsyncCompleteTime_ = NOW_NS;
    }

    /**
     * the vsync task be handled.
     */
    inline void HandleVsyncTaskNotify()
    {
        --sumOfPendingVsync_;
    }

    /**
     * set the barrier mode.
     */
    inline void SetBarrierMode(bool isBarrierMode)
    {
        isBarrierMode_ = isBarrierMode;
        enterBarrierTime_ = !isBarrierMode ? INT64_MAX : NOW_NS;
    }

    /**
     * get the barrier mode.
     */
    inline bool IsBarrierMode()
    {
        return isBarrierMode_;
    }

    /**
     * update the timestamp of epoll vsyncfd.
     */
    inline void UpdateVsyncCheckTime(int64_t lastFrameTime, int64_t period)
    {
        //In order to epolling vsync fd successfully, we delay a time(CHECK_VSYNC_DELAY_NS).
        if (__builtin_expect(period > 0, 1)) {
            int64_t now = NOW_NS;
            vsyncPeriod_ = (period > MAX_INIT_VSYNC_PERIOD_NS) ? MAX_INIT_VSYNC_PERIOD_NS : period;
            vsyncCheckTime_ = (lastFrameTime > now) ? (now + CHECK_VSYNC_DELAY_NS + ((lastFrameTime - now) % period)) :
                (now + period + CHECK_VSYNC_DELAY_NS - ((now - lastFrameTime) % period));
        }
    }

protected:
    void RemoveInvalidFileDescriptor();

    /**
     * Add file descriptor base.
     *
     * @param fileDescriptor File descriptor.
     * @param events Events from file descriptor, such as input, output, error
     * @param listener Listener callback.
     * @param taskName task name.
     * @param Priority Priority of the event.
     * @return Return result ErrCode.
     */
    ErrCode AddFileDescriptorListenerBase(int32_t fileDescriptor, uint32_t events,
        const std::shared_ptr<FileDescriptorListener> &listener, const std::string &taskName,
        Priority priority);

    /**
     * Add file descriptor by fd.
     *
     * @param fileDescriptor File descriptor.
     * @param events Events from file descriptor, such as input, output, error
     * @param taskName task name.
     * @param listener Listener callback.
     * @param Priority Priority of the event.
     * @return Return result boolean.
     */
    bool AddFileDescriptorByFd(int32_t fileDescriptor, uint32_t events, const std::string &taskName,
        const std::shared_ptr<FileDescriptorListener>& listener, EventQueue::Priority priority);

    bool EnsureIoWaiterLocked(const std::shared_ptr<FileDescriptorListener>& listener);

    /**
     * handle file descriptor event.
     *
     * @param fileDescriptor File descriptor.
     * @param events Events from file descriptor, such as input, output, error
     * @param name task name.
     * @param Priority Priority of the event.
     */
    void HandleFileDescriptorEvent(int32_t fileDescriptor, uint32_t events, const std::string &name,
        Priority priority);

    /**
     * remove listener by owner.
     *
     * @param owner current eventhandler.
     */
    void RemoveListenerByOwner(const std::shared_ptr<EventHandler> &owner);

    /**
     * remove listener by fd.
     *
     * @param fileDescriptor fd.
     */
    void RemoveListenerByFd(int32_t fileDescriptor);

    void PrepareBase();

    void FinishBase();

    void WaitUntilLocked(const InnerEvent::TimePoint &when, UniqueLockBase &lock, bool vsyncOnly = false);

    /**
     * Try epoll fds according to the vsync info.
     */
    void TryEpollFd(const InnerEvent::TimePoint &when, UniqueLockBase &lock);

    std::unique_ptr<LockBase> queueLock_;

    std::atomic_bool usable_ {true};

    bool isIdle_ {true};

    // Mark if the event queue is finished.
    bool finished_ {true};

    // IO waiter used to block if no events while calling 'GetEvent'.
    std::shared_ptr<IoWaiter> ioWaiter_;

    // select different epoll
    bool useDeamonIoWaiter_ = false;

    // File descriptor listeners to handle IO events.
    std::map<int32_t, std::shared_ptr<FileDescriptorListener>> listeners_;

    EventRunnerObserver observer_ = {.stages = static_cast<uint32_t>(EventRunnerStage::STAGE_INVAILD),
        .notifyCb = nullptr};

    int8_t sumOfPendingVsync_ = 0;
    bool needEpoll_ = false;
    std::atomic_bool isLazyMode_ = true;
    bool isBarrierMode_ = false;
    VsyncPolicy vsyncPolicy_ = VsyncPolicy::VSYNC_FIRST_WITH_DEFAULT_BARRIER;
    VsyncPolicy vsyncOriginPolicy_ = VsyncPolicy::VSYNC_FIRST_WITH_DEFAULT_BARRIER;
    int64_t enterBarrierTime_ = INT64_MAX;
    int64_t vsyncPeriod_ = MAX_INIT_VSYNC_PERIOD_NS;
    int64_t vsyncCheckTime_ = INT64_MAX;
    int64_t vsyncRecvTime_ = INT64_MAX;
    int64_t vsyncCompleteTime_ = 0;
    int64_t vsyncFirstForceEnableEndTime_ = 0;

private:
    std::shared_ptr<FileDescriptorListener> GetListenerByfd(int32_t fileDescriptor);

    void InitializeLocks(EventLockType lockType);
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // #ifndef BASE_EVENTHANDLER_INTERFACES_INNER_API_EVENT_QUEUE_H
