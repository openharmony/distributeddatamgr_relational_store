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
#include "napi_datashare_observer.h"

#include <uv.h>
#include "datashare_log.h"

namespace OHOS {
namespace DataShare {
void NAPIDataShareObserver::ReleaseJSCallback()
{
    if (ref_ == nullptr) {
        LOG_ERROR("NAPIDataShareObserver::ReleaseJSCallback, ref_ is null.");
        return;
    }
    napi_delete_reference(env_, ref_);
    LOG_INFO("NAPIDataShareObserver::%{public}s, called. end", __func__);
}

void NAPIDataShareObserver::SetAssociatedObject(DSHelperOnOffCB* object)
{
    onCB_ = object;
    LOG_INFO("NAPIDataShareObserver::%{public}s, called. end", __func__);
}

void NAPIDataShareObserver::ChangeWorkPre()
{
    LOG_INFO("NAPIDataShareObserver::%{public}s, called.", __func__);
    std::lock_guard<std::mutex> lock_l(mutex_);
    workPre_ = 1;
    LOG_INFO("NAPIDataShareObserver::%{public}s, called. end %{public}d", __func__, workPre_);
}
void NAPIDataShareObserver::ChangeWorkRun()
{
    workRun_ = 1;
    LOG_INFO("NAPIDataShareObserver::%{public}s, called. end %{public}d", __func__, workRun_);
}
void NAPIDataShareObserver::ChangeWorkInt()
{
    intrust_ = 1;
    LOG_INFO("NAPIDataShareObserver::%{public}s, called. end %{public}d", __func__, intrust_);
}

void NAPIDataShareObserver::ChangeWorkPreDone()
{
    LOG_INFO("NAPIDataShareObserver::%{public}s, called.", __func__);
    std::lock_guard<std::mutex> lock_l(mutex_);
    workPre_ = 0;
    LOG_INFO("NAPIDataShareObserver::%{public}s, called. end %{public}d", __func__, workPre_);
}

void NAPIDataShareObserver::ChangeWorkRunDone()
{
    workRun_ = 0;
    intrust_ = 0;
    LOG_INFO("NAPIDataShareObserver::%{public}s, called end %{public}d %{public}d", __func__, workRun_, intrust_);
}

int NAPIDataShareObserver::GetWorkPre()
{
    LOG_INFO("NAPIDataShareObserver::%{public}s, called.", __func__);
    std::lock_guard<std::mutex> lock_l(mutex_);
    LOG_INFO("NAPIDataShareObserver::%{public}s, called. end %{public}d", __func__, workPre_);
    return workPre_;
}

int NAPIDataShareObserver::GetWorkInt()
{
    LOG_INFO("NAPIDataShareObserver::%{public}s, called. end %{public}d", __func__, intrust_);
    return intrust_;
}

int NAPIDataShareObserver::GetWorkRun()
{
    LOG_INFO("NAPIDataShareObserver::%{public}s, called. %{public}d", __func__, workRun_);
    return workRun_;
}

const DSHelperOnOffCB* NAPIDataShareObserver::GetAssociatedObject(void)
{
    LOG_INFO("NAPIDataShareObserver::%{public}s, called.", __func__);
    return onCB_;
}

void NAPIDataShareObserver::SetEnv(const napi_env &env)
{
    env_ = env;
    LOG_INFO("NAPIDataShareObserver::%{public}s, called. end", __func__);
}

void NAPIDataShareObserver::SetCallbackRef(const napi_ref &ref)
{
    ref_ = ref;
    LOG_INFO("NAPIDataShareObserver::%{public}s, called. end", __func__);
}

static void OnChangeJSThreadWorker(uv_work_t *work, int status)
{
    LOG_INFO("OnChange, uv_queue_work");
    if (work == nullptr) {
        LOG_ERROR("OnChange, uv_queue_work input work is nullptr");
        return;
    }
    DSHelperOnOffCB *onCB = (DSHelperOnOffCB *)work->data;
    NAPIDataShareObserver* obs = onCB->observer;
    onCB->observer = nullptr;
    if (obs != nullptr) {
        obs->ChangeWorkRun();
    }
    napi_value result[ARGS_TWO] = {0};
    result[PARAM0] = GetCallbackErrorValue(onCB->cbBase.cbInfo.env, NO_ERROR);
    napi_value callback = 0;
    napi_value undefined = 0;
    napi_get_undefined(onCB->cbBase.cbInfo.env, &undefined);
    napi_value callResult = 0;
    napi_get_reference_value(onCB->cbBase.cbInfo.env, onCB->cbBase.cbInfo.callback, &callback);
    napi_call_function(onCB->cbBase.cbInfo.env, undefined, callback, ARGS_TWO, &result[PARAM0], &callResult);
    if (obs != nullptr) {
        if (obs->GetWorkInt() == 1) {
            obs->ReleaseJSCallback();
            const DSHelperOnOffCB* assicuated = obs->GetAssociatedObject();
            if (assicuated != nullptr) {
                LOG_INFO("OnChange, uv_queue_work ReleaseJSCallback Called");
                obs->SetAssociatedObject(nullptr);
                delete assicuated;
                assicuated = nullptr;
            }
        } else {
            obs->ChangeWorkRunDone();
            obs->ChangeWorkPreDone();
        }
    }
    delete onCB;
    onCB = nullptr;
    if (work != nullptr) {
        delete work;
    }
    LOG_INFO("OnChange, uv_queue_work. end");
}

void NAPIDataShareObserver::OnChange()
{
    if (ref_ == nullptr) {
        LOG_ERROR("%{public}s, OnChange ref is nullptr.", __func__);
        return;
    }
    ChangeWorkPre();
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        LOG_ERROR("%{public}s, loop == nullptr.", __func__);
        ChangeWorkPreDone();
        return;
    }
    uv_work_t *work = new uv_work_t;
    if (work == nullptr) {
        LOG_ERROR("%{public}s, work==nullptr.", __func__);
        ChangeWorkPreDone();
        return;
    }
    DSHelperOnOffCB *onCB = new (std::nothrow) DSHelperOnOffCB;
    if (onCB == nullptr) {
        LOG_ERROR("%{public}s, onCB == nullptr.", __func__);
        if (work != nullptr) {
            delete work;
            work = nullptr;
        }
        ChangeWorkPreDone();
        return;
    }
    onCB->cbBase.cbInfo.env = env_;
    onCB->cbBase.cbInfo.callback = ref_;
    onCB->observer = this;
    work->data = (void *)onCB;
    int rev = uv_queue_work(
        loop,
        work,
        [](uv_work_t *work) {},
        OnChangeJSThreadWorker);
    if (rev != 0) {
        delete onCB;
        onCB = nullptr;
        if (work != nullptr) {
            delete work;
            work = nullptr;
        }
    }
    LOG_INFO("%{public}s, called. end", __func__);
}
}  // namespace DataShare
}  // namespace OHOS
