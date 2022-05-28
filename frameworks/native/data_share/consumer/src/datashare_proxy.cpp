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

#include "datashare_proxy.h"

#include <string_ex.h>

#include "datashare_result_set.h"
#include "data_ability_observer_interface.h"
#include "data_ability_operation.h"
#include "data_ability_predicates.h"
#include "datashare_log.h"
#include "ipc_types.h"
#include "ishared_result_set.h"
#include "pac_map.h"

namespace OHOS {
namespace DataShare {
std::vector<std::string> DataShareProxy::GetFileTypes(const Uri &uri, const std::string &mimeTypeFilter)
{
    LOG_INFO("begin.");
    std::vector<std::string> types;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(DataShareProxy::GetDescriptor())) {
        LOG_ERROR("%{public}s WriteInterfaceToken failed", __func__);
        return types;
    }

    if (!data.WriteParcelable(&uri)) {
        LOG_ERROR("fail to WriteParcelable uri");
        return types;
    }

    if (!data.WriteString(mimeTypeFilter)) {
        LOG_ERROR("fail to WriteString mimeTypeFilter");
        return types;
    }

    int32_t err = Remote()->SendRequest(CMD_GET_FILE_TYPES, data, reply, option);
    if (err != NO_ERROR) {
        LOG_ERROR("GetFileTypes fail to SendRequest. err: %d", err);
    }

    if (!reply.ReadStringVector(&types)) {
        LOG_ERROR("fail to ReadStringVector types");
    }

    LOG_INFO("end successfully.");
    return types;
}

int DataShareProxy::OpenFile(const Uri &uri, const std::string &mode)
{
    LOG_INFO("begin.");
    int fd = -1;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataShareProxy::GetDescriptor())) {
        LOG_ERROR("%{public}s WriteInterfaceToken failed", __func__);
        return fd;
    }

    if (!data.WriteParcelable(&uri)) {
        LOG_ERROR("fail to WriteParcelable uri");
        return fd;
    }

    if (!data.WriteString(mode)) {
        LOG_ERROR("fail to WriteString mode");
        return fd;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = Remote()->SendRequest(CMD_OPEN_FILE, data, reply, option);
    if (err != NO_ERROR) {
        LOG_ERROR("OpenFile fail to SendRequest. err: %d", err);
        return fd;
    }

    fd = reply.ReadFileDescriptor();
    if (fd == -1) {
        LOG_ERROR("fail to ReadFileDescriptor fd");
        return fd;
    }

    LOG_INFO("end successfully.");
    return fd;
}

int DataShareProxy::OpenRawFile(const Uri &uri, const std::string &mode)
{
    LOG_INFO("begin.");
    int fd = -1;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataShareProxy::GetDescriptor())) {
        LOG_ERROR("%{public}s WriteInterfaceToken failed", __func__);
        return fd;
    }

    if (!data.WriteParcelable(&uri)) {
        LOG_ERROR("fail to WriteParcelable uri");
        return fd;
    }

    if (!data.WriteString(mode)) {
        LOG_ERROR("fail to WriteString mode");
        return fd;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = Remote()->SendRequest(CMD_OPEN_RAW_FILE, data, reply, option);
    if (err != NO_ERROR) {
        LOG_ERROR("OpenRawFile fail to SendRequest. err: %d", err);
        return fd;
    }

    if (!reply.ReadInt32(fd)) {
        LOG_ERROR("fail to ReadInt32 fd");
        return fd;
    }

    LOG_INFO("end successfully.");
    return fd;
}

int DataShareProxy::Insert(const Uri &uri, const DataShareValuesBucket &value)
{
    LOG_INFO("begin.");
    int index = -1;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataShareProxy::GetDescriptor())) {
        LOG_ERROR("%{public}s WriteInterfaceToken failed", __func__);
        return index;
    }

    if (!data.WriteParcelable(&uri)) {
        LOG_ERROR("fail to WriteParcelable uri");
        return index;
    }

    if (!DataShareValuesBucket::Marshalling(value)) {
        LOG_ERROR("fail to WriteParcelable value");
        return index;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = Remote()->SendRequest(CMD_INSERT, data, reply, option);
    if (err != NO_ERROR) {
        LOG_ERROR("Insert fail to SendRequest. err: %d", err);
        return index;
    }

    if (!reply.ReadInt32(index)) {
        LOG_ERROR("fail to ReadInt32 index");
        return index;
    }

    LOG_INFO("end successfully.");
    return index;
}

int DataShareProxy::Update(const Uri &uri, const DataSharePredicates &predicates,
    const DataShareValuesBucket &value)
{
    LOG_INFO("begin.");
    int index = -1;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataShareProxy::GetDescriptor())) {
        LOG_ERROR("%{public}s WriteInterfaceToken failed", __func__);
        return index;
    }

    if (!data.WriteParcelable(&uri)) {
        LOG_ERROR("fail to WriteParcelable uri");
        return index;
    }

    if (!data.WriteParcelable(&predicates)) {
        LOG_ERROR("fail to WriteParcelable predicates");
        return index;
    }

    if (!DataShareValuesBucket::Marshalling(value, data)) {
        LOG_ERROR("fail to WriteParcelable value");
        return index;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = Remote()->SendRequest(CMD_UPDATE, data, reply, option);
    if (err != NO_ERROR) {
        LOG_ERROR("Update fail to SendRequest. err: %d", err);
        return index;
    }

    if (!reply.ReadInt32(index)) {
        LOG_ERROR("fail to ReadInt32 index");
        return index;
    }

    LOG_INFO("end successfully.");
    return index;
}

int DataShareProxy::Delete(const Uri &uri, const DataSharePredicates &predicates)
{
    LOG_INFO("begin.");
    int index = -1;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataShareProxy::GetDescriptor())) {
        LOG_ERROR("%{public}s WriteInterfaceToken failed", __func__);
        return index;
    }

    if (!data.WriteParcelable(&uri)) {
        LOG_ERROR("fail to WriteParcelable uri");
        return index;
    }

    if (!data.WriteParcelable(&predicates)) {
        LOG_ERROR("fail to WriteParcelable predicates");
        return index;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = Remote()->SendRequest(CMD_DELETE, data, reply, option);
    if (err != NO_ERROR) {
        LOG_ERROR("Delete fail to SendRequest. err: %d", err);
        return index;
    }

    if (!reply.ReadInt32(index)) {
        LOG_ERROR("fail to ReadInt32 index");
        return index;
    }

    LOG_INFO("end successfully.");
    return index;
}

std::shared_ptr<DataShareResultSet> DataShareProxy::Query(const Uri &uri,
    const DataSharePredicates &predicates, std::vector<std::string> &columns)
{
    LOG_INFO("begin.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataShareProxy::GetDescriptor())) {
        LOG_ERROR("%{public}s WriteInterfaceToken failed", __func__);
        return nullptr;
    }

    if (!data.WriteParcelable(&uri)) {
        LOG_ERROR("fail to WriteParcelable uri");
        return nullptr;
    }

    if (!data.WriteParcelable(&predicates)) {
        LOG_ERROR("fail to WriteParcelable predicates");
        return nullptr;
    }

    if (!data.WriteStringVector(columns)) {
        LOG_ERROR("fail to WriteStringVector columns");
        return nullptr;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = Remote()->SendRequest(CMD_QUERY, data, reply, option);
    if (err != NO_ERROR) {
        LOG_ERROR("Query fail to SendRequest. err: %d", err);
        return nullptr;
    }
    LOG_INFO("end successfully.");
    return ISharedResultSet::ReadFromParcel(reply);
}

std::string DataShareProxy::GetType(const Uri &uri)
{
    LOG_INFO("begin.");
    std::string type;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataShareProxy::GetDescriptor())) {
        LOG_ERROR("%{public}s WriteInterfaceToken failed", __func__);
        return type;
    }
    if (!data.WriteParcelable(&uri)) {
        LOG_ERROR("fail to WriteParcelable uri");
        return type;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = Remote()->SendRequest(CMD_GET_TYPE, data, reply, option);
    if (err != NO_ERROR) {
        LOG_ERROR("GetFileTypes fail to SendRequest. err: %d", err);
        return type;
    }

    type = reply.ReadString();
    if (type.empty()) {
        LOG_ERROR("fail to ReadString type");
        return type;
    }

    LOG_INFO("end successfully.");
    return type;
}

int DataShareProxy::BatchInsert(const Uri &uri, const std::vector<DataShareValuesBucket> &values)
{
    LOG_INFO("begin.");
    int ret = -1;
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataShareProxy::GetDescriptor())) {
        LOG_ERROR("%{public}s WriteInterfaceToken failed", __func__);
        return ret;
    }

    if (!data.WriteParcelable(&uri)) {
        LOG_ERROR("fail to WriteParcelable uri");
        return ret;
    }

    int count = (int)values.size();
    if (!data.WriteInt32(count)) {
        LOG_ERROR("fail to WriteInt32 ret");
        return ret;
    }

    for (int i = 0; i < count; i++) {
        if (!DataShareValuesBucket::Marshalling(values[i], data)) {
            LOG_ERROR("fail to WriteParcelable ret, index = %{public}d", i);
            return ret;
        }
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = Remote()->SendRequest(CMD_BATCH_INSERT, data, reply, option);
    if (err != NO_ERROR) {
        LOG_ERROR("GetFileTypes fail to SendRequest. err: %d", err);
        return ret;
    }

    if (!reply.ReadInt32(ret)) {
        LOG_ERROR("fail to ReadInt32 index");
        return ret;
    }

    LOG_INFO("end successfully.");
    return ret;
}

bool DataShareProxy::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    LOG_INFO("begin.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataShareProxy::GetDescriptor())) {
        LOG_ERROR("%{public}s WriteInterfaceToken failed", __func__);
        return false;
    }

    if (!data.WriteParcelable(&uri)) {
        LOG_ERROR("%{public}s failed to WriteParcelable uri ", __func__);
        return false;
    }

    if (!data.WriteRemoteObject(dataObserver->AsObject())) {
        LOG_ERROR("%{public}s failed to WriteParcelable dataObserver ", __func__);
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t result = Remote()->SendRequest(CMD_REGISTER_OBSERVER, data, reply, option);
    if (result == ERR_NONE) {
        LOG_INFO("SendRequest ok, retval is %{public}d", reply.ReadInt32());
    } else {
        LOG_ERROR("SendRequest error, result=%{public}d", result);
        return false;
    }
    LOG_INFO("end.");
    return true;
}

bool DataShareProxy::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    LOG_INFO("begin.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataShareProxy::GetDescriptor())) {
        LOG_ERROR("%{public}s WriteInterfaceToken failed", __func__);
        return false;
    }

    if (!data.WriteParcelable(&uri)) {
        LOG_ERROR("%{public}s failed to WriteParcelable uri ", __func__);
        return false;
    }

    if (!data.WriteRemoteObject(dataObserver->AsObject())) {
        LOG_ERROR("%{public}s failed to WriteParcelable dataObserver ", __func__);
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t result = Remote()->SendRequest(CMD_UNREGISTER_OBSERVER, data, reply, option);
    if (result == ERR_NONE) {
        LOG_INFO("SendRequest ok, retval is %{public}d", reply.ReadInt32());
    } else {
        LOG_ERROR("SendRequest error, result=%{public}d", result);
        return false;
    }
    LOG_INFO("end successfully.");
    return true;
}

bool DataShareProxy::NotifyChange(const Uri &uri)
{
    LOG_INFO("begin.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataShareProxy::GetDescriptor())) {
        LOG_ERROR("%{public}s WriteInterfaceToken failed", __func__);
        return false;
    }

    if (!data.WriteParcelable(&uri)) {
        LOG_ERROR("%{public}s failed to WriteParcelable uri ", __func__);
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t result = Remote()->SendRequest(CMD_NOTIFY_CHANGE, data, reply, option);
    if (result == ERR_NONE) {
        LOG_INFO("SendRequest ok, retval is %{public}d", reply.ReadInt32());
    } else {
        LOG_ERROR("SendRequest error, result=%{public}d", result);
        return false;
    }
    LOG_INFO("end successfully.");
    return true;
}

Uri DataShareProxy::NormalizeUri(const Uri &uri)
{
    LOG_INFO("begin.");
    Uri urivalue("");
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataShareProxy::GetDescriptor())) {
        LOG_ERROR("%{public}s WriteInterfaceToken failed", __func__);
        return urivalue;
    }

    if (!data.WriteParcelable(&uri)) {
        LOG_ERROR("fail to WriteParcelable uri");
        return urivalue;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = Remote()->SendRequest(CMD_NORMALIZE_URI, data, reply, option);
    if (err != NO_ERROR) {
        LOG_ERROR("NormalizeUri fail to SendRequest. err: %d", err);
        return urivalue;
    }

    std::unique_ptr<Uri> info(reply.ReadParcelable<Uri>());
    if (!info) {
        LOG_ERROR("ReadParcelable value is nullptr.");
        return urivalue;
    }
    LOG_INFO("end successfully.");
    return *info;
}

Uri DataShareProxy::DenormalizeUri(const Uri &uri)
{
    LOG_INFO("begin.");
    Uri urivalue("");
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataShareProxy::GetDescriptor())) {
        LOG_ERROR("%{public}s WriteInterfaceToken failed", __func__);
        return urivalue;
    }

    if (!data.WriteParcelable(&uri)) {
        LOG_ERROR("fail to WriteParcelable uri");
        return urivalue;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = Remote()->SendRequest(CMD_DENORMALIZE_URI, data, reply, option);
    if (err != NO_ERROR) {
        LOG_ERROR("DenormalizeUri fail to SendRequest. err: %d", err);
        return urivalue;
    }

    std::unique_ptr<Uri> info(reply.ReadParcelable<Uri>());
    if (!info) {
        LOG_ERROR("ReadParcelable value is nullptr.");
        return urivalue;
    }
    LOG_INFO("end successfully.");
    return *info;
}

std::vector<std::shared_ptr<DataShareResult>> DataShareProxy::ExecuteBatch(
    const std::vector<std::shared_ptr<DataShareOperation>> &operations)
{
    LOG_INFO("begin.");
    MessageParcel data;
    std::vector<std::shared_ptr<DataShareResult>> results;
    results.clear();

    if (!data.WriteInterfaceToken(DataShareProxy::GetDescriptor())) {
        LOG_ERROR("%{public}s WriteInterfaceToken failed", __func__);
        return results;
    }

    int count = (int)operations.size();
    if (!data.WriteInt32(count)) {
        LOG_ERROR("fail to WriteInt32 ret");
        return results;
    }

    for (int i = 0; i < count; i++) {
        if (!data.WriteParcelable(operations[i].get())) {
            LOG_ERROR("fail to WriteParcelable ret, index = %{public}d", i);
            return results;
        }
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = Remote()->SendRequest(CMD_EXECUTE_BATCH, data, reply, option);
    if (err != NO_ERROR) {
        LOG_ERROR("fail to SendRequest. err: %{public}d", err);
        return results;
    }

    int total = 0;
    if (!reply.ReadInt32(total)) {
        LOG_ERROR("fail to ReadInt32 count %{public}d", total);
        return results;
    }

    for (int i = 0; i < total; i++) {
        DataShareResult *result = reply.ReadParcelable<DataShareResult>();
        if (result == nullptr) {
            LOG_ERROR("result is nullptr, index = %{public}d", i);
            return results;
        }
        std::shared_ptr<DataShareResult> dataAbilityResult(result);
        results.push_back(dataAbilityResult);
    }
    LOG_INFO("end successfully.");
    return results;
}
} // namespace DataShare
} // namespace OHOS
