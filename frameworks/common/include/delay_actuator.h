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

#ifndef NATIVE_RDB_INCLUDE_DELAY_ACTUATOR_H
#define NATIVE_RDB_INCLUDE_DELAY_ACTUATOR_H
#include <functional>
#include <memory>
#include "executor_pool.h"
namespace OHOS {
class ActuatorBase : public std::enable_shared_from_this<ActuatorBase> {
public:
    static constexpr uint32_t DEFAULT_FIRST_DELAY_INTERVAL = 0;
    static constexpr uint32_t DEFAULT_MIN_EXECUTE_INTERVAL = 200;
    static constexpr uint32_t DEFAULT_MAX_EXECUTE_INTERVAL = 500;
    static const uint32_t INVALID_INTERVAL = UINT32_MAX;
    void SetExecutorPool(std::shared_ptr<ExecutorPool> pool)
    {
        pool_ = std::move(pool);
    }
    void Suspend()
    {
        isSuspend_ = true;
    }
    void Active()
    {
        isSuspend_ = false;
    }

    class Defer final {
    public:
        Defer(std::vector<std::shared_ptr<ActuatorBase>> actuators) : actuators_(std::move(actuators))
        {
            for (auto actuator : actuators_) {
                if (actuator) {
                    actuator->Suspend();
                    actuator->StopTimer(false);
                }
            }
        }
        Defer(std::shared_ptr<ActuatorBase> actuator) : Defer(std::vector<std::shared_ptr<ActuatorBase>>({actuator}))
        {}
        ~Defer()
        {
            for (auto actuator : actuators_) {
                if (actuator) {
                    actuator->Active();
                    actuator->StartTimer();
                }
            }
        }
        Defer(const Defer &defer) = delete;
        Defer(Defer &&defer) = delete;
        Defer &operator=(const Defer &defer) = delete;
        Defer &operator=(Defer &&defer) = delete;
        void *operator new(size_t size) = delete;
        void *operator new[](size_t size) = delete;
        void operator delete(void *) = delete;
        void operator delete[](void *) = delete;

    private:
        std::vector<std::shared_ptr<ActuatorBase>> actuators_;
    };
protected:
    ActuatorBase(uint32_t firstInterval = DEFAULT_FIRST_DELAY_INTERVAL,
        uint32_t minInterval = DEFAULT_MIN_EXECUTE_INTERVAL, uint32_t maxInterval = DEFAULT_MAX_EXECUTE_INTERVAL)
        : firstDelayInterval_(firstInterval), minExecuteInterval_(minInterval), maxExecuteInterval_(maxInterval)
    {
    }
    virtual ~ActuatorBase()
    {
        StopTimer(true);
    }

    void StartTimer()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pool_ == nullptr || isSuspend_) {
            return;
        }
        auto weakThis = weak_from_this();
        if (forceTaskId_ == Executor::INVALID_TASK_ID && maxExecuteInterval_ != INVALID_INTERVAL) {
            forceTaskId_ = pool_->Schedule(std::chrono::milliseconds(maxExecuteInterval_), [weakThis]() {
                auto self = weakThis.lock();
                if (self != nullptr) {
                    self->ExecuteTask();
                    self->lastExecuteTimePoint_ = GetTimeStamp();
                }
            });
        }
        if (firstDelayInterval_ == INVALID_INTERVAL || minExecuteInterval_ == INVALID_INTERVAL) {
            return;
        }
        if (delayTaskId_ == Executor::INVALID_TASK_ID) {
            delayTaskId_ =
                pool_->Schedule(std::chrono::milliseconds(lastExecuteTimePoint_ <= GetTimeStamp() - minExecuteInterval_
                                                              ? firstDelayInterval_
                                                              : minExecuteInterval_),
                    [weakThis]() {
                        auto self = weakThis.lock();
                        if (self != nullptr) {
                            self->ExecuteTask();
                            self->lastExecuteTimePoint_ = GetTimeStamp();
                        }
                    });
        } else {
            delayTaskId_ = pool_->Reset(delayTaskId_, std::chrono::milliseconds(minExecuteInterval_));
        }
    }
    void StopTimer(bool wait)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pool_ != nullptr) {
            pool_->Remove(forceTaskId_, wait);
            pool_->Remove(delayTaskId_, wait);
        }
        forceTaskId_ = Executor::INVALID_TASK_ID;
        delayTaskId_ = Executor::INVALID_TASK_ID;
    }

    virtual void ExecuteTask() {};
    static inline uint64_t GetTimeStamp()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }
private:
    ExecutorPool::TaskId delayTaskId_ = ExecutorPool::INVALID_TASK_ID;
    ExecutorPool::TaskId forceTaskId_ = ExecutorPool::INVALID_TASK_ID;
    std::shared_ptr<ExecutorPool> pool_ = nullptr;
    bool isSuspend_ = false;
    std::atomic_uint64_t lastExecuteTimePoint_ = 0;
    uint32_t const firstDelayInterval_ = DEFAULT_FIRST_DELAY_INTERVAL;
    uint32_t const minExecuteInterval_ = DEFAULT_MIN_EXECUTE_INTERVAL;
    uint32_t const maxExecuteInterval_ = DEFAULT_MAX_EXECUTE_INTERVAL;
    mutable std::mutex mutex_;
};

template<class T, class MergeFunc = std::function<void(T &out, T &&input)>, class Task = std::function<int32_t(T &&)>>
class DelayActuator : public ActuatorBase {
public:
    DelayActuator(MergeFunc mergeFunc = nullptr, uint32_t firstInterval = DEFAULT_FIRST_DELAY_INTERVAL,
        uint32_t minInterval = DEFAULT_MIN_EXECUTE_INTERVAL, uint32_t maxInterval = DEFAULT_MAX_EXECUTE_INTERVAL)
        : ActuatorBase(firstInterval, minInterval, maxInterval), data_(T()), mergeFunc_(mergeFunc)
    {
    }
    ~DelayActuator() {}
    
    void SetTask(Task task)
    {
        task_ = std::move(task);
    }
    template<class D = T>
    void Execute(D &&value)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (mergeFunc_) {
                mergeFunc_(data_, std::forward<D>(value));
            } else {
                data_ = T{std::move(value)};
            }
        }
        StartTimer();
    }

private:
    Task task_;
    T data_;
    MergeFunc mergeFunc_;
    std::mutex mutex_;

    void ExecuteTask() override
    {
        StopTimer(false);
        T data;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            data = std::move(data_);
            data_ = T();
        }
        if (task_) {
            task_(std::move(data));
        }
    }
};
} // namespace OHOS
#endif // NATIVE_RDB_INCLUDE_DELAY_ACTUATOR_H