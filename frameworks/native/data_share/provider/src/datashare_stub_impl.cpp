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

#include "datashare_stub_impl.h"

#include "datashare_log.h"

namespace OHOS {
namespace DataShare {
std::shared_ptr<JsDataShareExtAbility> DataShareStubImpl::GetOwner()
{
    return extension_;
}

std::vector<std::string> DataShareStubImpl::GetFileTypes(const Uri &uri, const std::string &mimeTypeFilter)
{
    LOG_INFO("begin.");
    std::vector<std::string> ret;
    std::function<void()> syncTaskFunc = [=, &ret, client = sptr<DataShareStubImpl>(this)]() {
        auto extension = client->GetOwner();
        if (extension == nullptr) {
            LOG_ERROR("%{public}s end failed.", __func__);
            return;
        }
        ret = extension->GetFileTypes(uri, mimeTypeFilter);
    };
    uvQueue_->SyncCall(syncTaskFunc);
    LOG_INFO("end successfully.");
    return ret;
}

int DataShareStubImpl::OpenFile(const Uri &uri, const std::string &mode)
{
    LOG_INFO("begin.");
    int ret = -1;
    std::function<void()> syncTaskFunc = [=, &ret, client = sptr<DataShareStubImpl>(this)]() {
        auto extension = client->GetOwner();
        if (extension == nullptr) {
            LOG_ERROR("%{public}s end failed.", __func__);
            return;
        }
        ret = extension->OpenFile(uri, mode);
    };
    uvQueue_->SyncCall(syncTaskFunc);
    LOG_INFO("end successfully.");
    return ret;
}

int DataShareStubImpl::OpenRawFile(const Uri &uri, const std::string &mode)
{
    LOG_INFO("begin.");
    int ret = -1;
    std::function<void()> syncTaskFunc = [=, &ret, client = sptr<DataShareStubImpl>(this)]() {
        auto extension = client->GetOwner();
        if (extension == nullptr) {
            LOG_ERROR("%{public}s end failed.", __func__);
            return;
        }
        ret = extension->OpenRawFile(uri, mode);
    };
    uvQueue_->SyncCall(syncTaskFunc);
    LOG_INFO("end successfully.");
    return ret;
}

int DataShareStubImpl::Insert(const Uri &uri, const DataShareValuesBucket &value)
{
    LOG_INFO("begin.");
    int ret = 0;
    std::function<void()> syncTaskFunc = [=, &ret, client = sptr<DataShareStubImpl>(this)]() {
        auto extension = client->GetOwner();
        if (extension == nullptr) {
            LOG_ERROR("%{public}s end failed.", __func__);
            return;
        }
        ret = extension->Insert(uri, value);
    };
    uvQueue_->SyncCall(syncTaskFunc);
    LOG_INFO("end successfully.");
    return ret;
}

int DataShareStubImpl::Update(const Uri &uri, const DataSharePredicates &predicates,
    const DataShareValuesBucket &value)
{
    LOG_INFO("begin.");
    int ret = 0;
    std::function<void()> syncTaskFunc = [=, &ret, client = sptr<DataShareStubImpl>(this)]() {
        auto extension = client->GetOwner();
        if (extension == nullptr) {
            LOG_ERROR("%{public}s end failed.", __func__);
            return;
        }
        ret = extension->Update(uri, predicates, value);
    };
    uvQueue_->SyncCall(syncTaskFunc);
    LOG_INFO("end successfully.");
    return ret;
}

int DataShareStubImpl::Delete(const Uri &uri, const DataSharePredicates &predicates)
{
    LOG_INFO("begin.");
    int ret = 0;
    std::function<void()> syncTaskFunc = [=, &ret, client = sptr<DataShareStubImpl>(this)]() {
        auto extension = client->GetOwner();
        if (extension == nullptr) {
            LOG_ERROR("%{public}s end failed.", __func__);
            return;
        }
        ret = extension->Delete(uri, predicates);
    };
    uvQueue_->SyncCall(syncTaskFunc);
    LOG_INFO("end successfully.");
    return ret;
}

std::shared_ptr<DataShareResultSet> DataShareStubImpl::Query(const Uri &uri,
    const DataSharePredicates &predicates, std::vector<std::string> &columns)
{
    LOG_INFO("begin.");
    std::shared_ptr<DataShareAbstractResultSet> ret = nullptr;
    std::function<void()> syncTaskFunc = [=, &columns, &ret, client = sptr<DataShareStubImpl>(this)]() {
        auto extension = client->GetOwner();
        if (extension == nullptr) {
            LOG_ERROR("%{public}s end failed.", __func__);
            return;
        }
        ret = extension->Query(uri, predicates, columns);
    };
    uvQueue_->SyncCall(syncTaskFunc);
    std::shared_ptr<DataShareResultSet> resultSet = std::make_shared<DataShareResultSet>(ret);
    LOG_INFO("end successfully.");
    return resultSet;
}

std::string DataShareStubImpl::GetType(const Uri &uri)
{
    LOG_INFO("begin.");
    std::string ret = "";
    std::function<void()> syncTaskFunc = [=, &ret, client = sptr<DataShareStubImpl>(this)]() {
        auto extension = client->GetOwner();
        if (extension == nullptr) {
            LOG_ERROR("%{public}s end failed.", __func__);
            return;
        }
        ret = extension->GetType(uri);
    };
    uvQueue_->SyncCall(syncTaskFunc);
    LOG_INFO("end successfully.");
    return ret;
}

int DataShareStubImpl::BatchInsert(const Uri &uri, const std::vector<DataShareValuesBucket> &values)
{
    LOG_INFO("begin.");
    int ret = 0;
    std::function<void()> syncTaskFunc = [=, &ret, client = sptr<DataShareStubImpl>(this)]() {
        auto extension = client->GetOwner();
        if (extension == nullptr) {
            LOG_ERROR("%{public}s end failed.", __func__);
            return;
        }
        ret = extension->BatchInsert(uri, values);
    };
    uvQueue_->SyncCall(syncTaskFunc);
    LOG_INFO("end successfully.");
    return ret;
}

bool DataShareStubImpl::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    LOG_INFO("begin.");
    bool ret = false;
    std::function<void()> syncTaskFunc = [=, &dataObserver, &ret, client = sptr<DataShareStubImpl>(this)]() {
        auto extension = client->GetOwner();
        if (extension == nullptr) {
            LOG_ERROR("%{public}s end failed.", __func__);
            return;
        }
        ret = extension->RegisterObserver(uri, dataObserver);
    };
    uvQueue_->SyncCall(syncTaskFunc);
    LOG_INFO("end successfully.");
    return ret;
}

bool DataShareStubImpl::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    LOG_INFO("begin.");
    bool ret = false;
    std::function<void()> syncTaskFunc = [=, &dataObserver, &ret, client = sptr<DataShareStubImpl>(this)]() {
        auto extension = client->GetOwner();
        if (extension == nullptr) {
            LOG_ERROR("%{public}s end failed.", __func__);
            return;
        }
        ret = extension->UnregisterObserver(uri, dataObserver);
    };
    uvQueue_->SyncCall(syncTaskFunc);
    LOG_INFO("end successfully.");
    return ret;
}

bool DataShareStubImpl::NotifyChange(const Uri &uri)
{
    LOG_INFO("begin.");
    bool ret = false;
    std::function<void()> syncTaskFunc = [=, &ret, client = sptr<DataShareStubImpl>(this)]() {
        auto extension = client->GetOwner();
        if (extension == nullptr) {
            LOG_ERROR("%{public}s end failed.", __func__);
            return;
        }
        ret = extension->NotifyChange(uri);
    };
    uvQueue_->SyncCall(syncTaskFunc);
    LOG_INFO("end successfully.");
    return ret;
}

Uri DataShareStubImpl::NormalizeUri(const Uri &uri)
{
    LOG_INFO("begin.");
    Uri urivalue("");
    std::function<void()> syncTaskFunc = [=, &urivalue, client = sptr<DataShareStubImpl>(this)]() {
        auto extension = client->GetOwner();
        if (extension == nullptr) {
            LOG_ERROR("%{public}s end failed.", __func__);
            return;
        }
        urivalue = extension->NormalizeUri(uri);
    };
    uvQueue_->SyncCall(syncTaskFunc);
    LOG_INFO("end successfully.");
    return urivalue;
}

Uri DataShareStubImpl::DenormalizeUri(const Uri &uri)
{
    LOG_INFO("begin.");
    Uri urivalue("");
    std::function<void()> syncTaskFunc = [=, &urivalue, client = sptr<DataShareStubImpl>(this)]() {
        auto extension = client->GetOwner();
        if (extension == nullptr) {
            LOG_ERROR("%{public}s end failed.", __func__);
            return;
        }
        urivalue = extension->DenormalizeUri(uri);
    };
    uvQueue_->SyncCall(syncTaskFunc);
    LOG_INFO("end successfully.");
    return urivalue;
}

std::vector<std::shared_ptr<DataShareResult>> DataShareStubImpl::ExecuteBatch(
    const std::vector<std::shared_ptr<DataShareOperation>> &operations)
{
    LOG_INFO("begin.");
    std::vector<std::shared_ptr<DataShareResult>> results;
    std::function<void()> syncTaskFunc = [=, &results, client = sptr<DataShareStubImpl>(this)]() {
        auto extension = client->GetOwner();
        if (extension == nullptr) {
            LOG_ERROR("%{public}s end failed.", __func__);
            return;
        }
        results = extension->ExecuteBatch(operations);
    };
    uvQueue_->SyncCall(syncTaskFunc);
    LOG_INFO("end successfully.");
    return results;
}
} // namespace DataShare
} // namespace OHOS
