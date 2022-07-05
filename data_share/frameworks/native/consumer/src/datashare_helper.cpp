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

#include "datashare_helper.h"

#include "datashare_result_set.h"
#include "data_ability_observer_interface.h"
#include "datashare_log.h"
#include "idatashare.h"

namespace OHOS {
namespace DataShare {
using namespace AppExecFwk;
namespace {
const std::string SCHEME_DATASHARE = "datashare";
constexpr int INVALID_VALUE = -1;
}  // namespace

std::mutex DataShareHelper::oplock_;

DataShareHelper::DataShareHelper(const sptr<IRemoteObject> &token,
    const Uri &uri, const sptr<IDataShare> &dataShareProxy, sptr<DataShareConnection> dataShareConnection)
{
    LOG_INFO("DataShareHelper::DataShareHelper start");
    token_ = token;
    uri_ = uri;
    dataShareProxy_ = dataShareProxy;
    dataShareConnection_ = dataShareConnection;
    LOG_INFO("DataShareHelper::DataShareHelper end");
}

void DataShareHelper::AddDataShareDeathRecipient(const sptr<IRemoteObject> &token)
{
    LOG_INFO("DataShareHelper::AddDataShareDeathRecipient start.");
    if (token != nullptr && callerDeathRecipient_ != nullptr) {
        LOG_INFO("token RemoveDeathRecipient.");
        token->RemoveDeathRecipient(callerDeathRecipient_);
    }
    if (callerDeathRecipient_ == nullptr) {
        std::weak_ptr<DataShareHelper> thisWeakPtr(shared_from_this());
        callerDeathRecipient_ =
            new DataShareDeathRecipient([thisWeakPtr](const wptr<IRemoteObject> &remote) {
                auto dataShareHelper = thisWeakPtr.lock();
                if (dataShareHelper) {
                    dataShareHelper->OnSchedulerDied(remote);
                }
            });
    }
    if (token != nullptr) {
        LOG_INFO("token AddDeathRecipient.");
        token->AddDeathRecipient(callerDeathRecipient_);
    }
    LOG_INFO("DataShareHelper::AddDataShareDeathRecipient end.");
}

void DataShareHelper::OnSchedulerDied(const wptr<IRemoteObject> &remote)
{
    LOG_INFO("start.");
    std::lock_guard<std::mutex> guard(lock_);
    auto object = remote.promote();
    object = nullptr;
    dataShareProxy_ = nullptr;
    dataShareConnection_->ConnectDataShareExtAbility(uri_, token_);
    LOG_INFO("DataShareHelper::OnSchedulerDied end.");
}

/**
 * @brief You can use this method to specify the Uri of the data to operate and set the binding relationship
 * between the ability using the Data template (data share for short) and the associated client process in
 * a DataShareHelper instance.
 *
 * @param context Indicates the Context object on OHOS.
 * @param strUri Indicates the database table or disk file to operate.
 *
 * @return Returns the created DataShareHelper instance.
 */
std::shared_ptr<DataShareHelper> DataShareHelper::Creator(
    const std::shared_ptr<Context> &context, const std::string &strUri)
{
    LOG_INFO("DataShareHelper::Creator with context and uri called start.");
    if (context == nullptr) {
        LOG_ERROR("DataShareHelper::Creator failed, context == nullptr");
        return nullptr;
    }
    sptr<IRemoteObject> token = context->GetToken();
    return Creator(token, strUri);
}

/**
 * @brief You can use this method to specify the Uri of the data to operate and set the binding relationship
 * between the ability using the Data template (data share for short) and the associated client process in
 * a DataShareHelper instance.
 *
 * @param context Indicates the Context object on OHOS.
 * @param strUri Indicates the database table or disk file to operate.
 *
 * @return Returns the created DataShareHelper instance.
 */
std::shared_ptr<DataShareHelper> DataShareHelper::Creator(
    const std::shared_ptr<OHOS::AbilityRuntime::Context> &context, const std::string &strUri)
{
    LOG_INFO("DataShareHelper::Creator with runtime context and uri called start.");
    if (context == nullptr) {
        LOG_ERROR("DataShareHelper::Creator failed, context == nullptr");
        return nullptr;
    }
    sptr<IRemoteObject> token = context->GetToken();
    return Creator(token, strUri);
}

/**
 * @brief You can use this method to specify the Uri of the data to operate and set the binding relationship
 * between the ability using the Data template (data share for short) and the associated client process in
 * a DataShareHelper instance.
 *
 * @param token Indicates the System token.
 * @param strUri Indicates the database table or disk file to operate.
 *
 * @return Returns the created DataShareHelper instance.
 */
std::shared_ptr<DataShareHelper> DataShareHelper::Creator(const sptr<IRemoteObject> &token, const std::string &strUri)
{
    LOG_INFO("DataShareHelper::Creator with runtime token and uri called start.");
    if (token == nullptr) {
        LOG_ERROR("DataShareHelper::Creator failed, token == nullptr");
        return nullptr;
    }

    Uri uri(strUri);
    if (uri.GetScheme() != SCHEME_DATASHARE) {
        LOG_ERROR("DataShareHelper::Creator failed, the Scheme is not datashare, Scheme: %{public}s",
            uri.GetScheme().c_str());
        return nullptr;
    }

    LOG_INFO("DataShareHelper::Creator before ConnectDataShareExtAbility.");
    sptr<DataShareConnection> dataShareConnection = new (std::nothrow) DataShareConnection(uri);
    if (!dataShareConnection->IsExtAbilityConnected()) {
        dataShareConnection->ConnectDataShareExtAbility(uri, token);
    }
    sptr<IDataShare> dataShareProxy = dataShareConnection->GetDataShareProxy();
    if (dataShareProxy == nullptr) {
        LOG_ERROR("DataShareHelper::Creator get invalid dataShareProxy");
        if (dataShareConnection->IsExtAbilityConnected()) {
            dataShareConnection->DisconnectDataShareExtAbility();
        }
        return nullptr;
    }
    LOG_INFO("DataShareHelper::Creator after ConnectDataShareExtAbility.");

    DataShareHelper *ptrDataShareHelper =
        new (std::nothrow) DataShareHelper(token, uri, dataShareProxy, dataShareConnection);
    if (ptrDataShareHelper == nullptr) {
        LOG_ERROR("DataShareHelper::Creator failed, create DataShareHelper failed");
        if (dataShareConnection->IsExtAbilityConnected()) {
            dataShareConnection->DisconnectDataShareExtAbility();
        }
        return nullptr;
    }

    LOG_INFO("DataShareHelper::Creator out.");
    return std::shared_ptr<DataShareHelper>(ptrDataShareHelper);
}

/**
 * @brief Releases the client resource of the data share.
 * You should call this method to releases client resource after the data operations are complete.
 *
 * @return Returns true if the resource is successfully released; returns false otherwise.
 */
bool DataShareHelper::Release()
{
    LOG_INFO("DataShareHelper::Release start.");
    LOG_INFO("DataShareHelper::Release before DisconnectDataShareExtAbility.");
    if (dataShareConnection_->IsExtAbilityConnected()) {
        dataShareConnection_->DisconnectDataShareExtAbility();
    }
    LOG_INFO("DataShareHelper::Release after DisconnectDataShareExtAbility.");
    dataShareProxy_ = nullptr;
    dataShareConnection_ = nullptr;
    uri_ = Uri("");
    LOG_INFO("DataShareHelper::Release end.");
    return true;
}

/**
 * @brief Obtains the MIME types of files supported.
 *
 * @param uri Indicates the path of the files to obtain.
 * @param mimeTypeFilter Indicates the MIME types of the files to obtain. This parameter cannot be null.
 *
 * @return Returns the matched MIME types. If there is no match, null is returned.
 */
std::vector<std::string> DataShareHelper::GetFileTypes(Uri &uri, const std::string &mimeTypeFilter)
{
    LOG_INFO("DataShareHelper::GetFileTypes start.");
    std::vector<std::string> matchedMIMEs;
    if (!CheckUriParam(uri)) {
        LOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return matchedMIMEs;
    }

    if (dataShareProxy_ == nullptr) {
        dataShareProxy_ = dataShareConnection_->GetDataShareProxy();
    }

    if (dataShareProxy_) {
        AddDataShareDeathRecipient(dataShareProxy_->AsObject());
    } else {
        LOG_ERROR("%{public}s failed with invalid dataShareProxy_", __func__);
        return matchedMIMEs;
    }

    LOG_INFO("DataShareHelper::GetFileTypes before dataShareProxy_->GetFileTypes.");
    matchedMIMEs = dataShareProxy_->GetFileTypes(uri, mimeTypeFilter);
    LOG_INFO("DataShareHelper::GetFileTypes after dataShareProxy_->GetFileTypes.");

    LOG_INFO("DataShareHelper::GetFileTypes end.");
    return matchedMIMEs;
}

/**
 * @brief Opens a file in a specified remote path.
 *
 * @param uri Indicates the path of the file to open.
 * @param mode Indicates the file open mode, which can be "r" for read-only access, "w" for write-only access
 * (erasing whatever data is currently in the file), "wt" for write access that truncates any existing file,
 * "wa" for write-only access to append to any existing data, "rw" for read and write access on any existing data,
 *  or "rwt" for read and write access that truncates any existing file.
 *
 * @return Returns the file descriptor.
 */
int DataShareHelper::OpenFile(Uri &uri, const std::string &mode)
{
    LOG_INFO("DataShareHelper::OpenFile start.");
    int fd = INVALID_VALUE;
    if (!CheckUriParam(uri)) {
        LOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return fd;
    }

    if (dataShareProxy_ == nullptr) {
        dataShareProxy_ = dataShareConnection_->GetDataShareProxy();
    }

    if (dataShareProxy_) {
        AddDataShareDeathRecipient(dataShareProxy_->AsObject());
    } else {
        LOG_ERROR("%{public}s failed with invalid dataShareProxy_", __func__);
        return fd;
    }

    LOG_INFO("DataShareHelper::OpenFile before dataShareProxy_->OpenFile.");
    fd = dataShareProxy_->OpenFile(uri, mode);
    LOG_INFO("DataShareHelper::OpenFile after dataShareProxy_->OpenFile.");

    LOG_INFO("DataShareHelper::OpenFile end.");
    return fd;
}

/**
 * @brief This is like openFile, open a file that need to be able to return sub-sections of files，often assets
 * inside of their .hap.
 *
 * @param uri Indicates the path of the file to open.
 * @param mode Indicates the file open mode, which can be "r" for read-only access, "w" for write-only access
 * (erasing whatever data is currently in the file), "wt" for write access that truncates any existing file,
 * "wa" for write-only access to append to any existing data, "rw" for read and write access on any existing
 * data, or "rwt" for read and write access that truncates any existing file.
 *
 * @return Returns the RawFileDescriptor object containing file descriptor.
 */
int DataShareHelper::OpenRawFile(Uri &uri, const std::string &mode)
{
    LOG_INFO("DataShareHelper::OpenRawFile start.");
    int fd = INVALID_VALUE;
    if (!CheckUriParam(uri)) {
        LOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return fd;
    }

    if (dataShareProxy_ == nullptr) {
        dataShareProxy_ = dataShareConnection_->GetDataShareProxy();
    }

    if (dataShareProxy_) {
        AddDataShareDeathRecipient(dataShareProxy_->AsObject());
    } else {
        LOG_ERROR("%{public}s failed with invalid dataShareProxy_", __func__);
        return fd;
    }

    LOG_INFO("DataShareHelper::OpenRawFile before dataShareProxy_->OpenRawFile.");
    fd = dataShareProxy_->OpenRawFile(uri, mode);
    LOG_INFO("DataShareHelper::OpenRawFile after dataShareProxy_->OpenRawFile.");

    LOG_INFO("DataShareHelper::OpenRawFile end.");
    return fd;
}

/**
 * @brief Inserts a single data record into the database.
 *
 * @param uri Indicates the path of the data to operate.
 * @param value Indicates the data record to insert. If this parameter is null, a blank row will be inserted.
 *
 * @return Returns the index of the inserted data record.
 */
int DataShareHelper::Insert(Uri &uri, const DataShareValuesBucket &value)
{
    LOG_INFO("DataShareHelper::Insert start.");
    int index = INVALID_VALUE;
    if (!CheckUriParam(uri)) {
        LOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return index;
    }

    if (dataShareProxy_ == nullptr) {
        dataShareProxy_ = dataShareConnection_->GetDataShareProxy();
    }

    if (dataShareProxy_) {
        AddDataShareDeathRecipient(dataShareProxy_->AsObject());
    } else {
        LOG_ERROR("%{public}s failed with invalid dataShareProxy_", __func__);
        return index;
    }

    LOG_INFO("DataShareHelper::Insert before dataShareProxy_->Insert.");
    index = dataShareProxy_->Insert(uri, value);
    LOG_INFO("DataShareHelper::Insert after dataShareProxy_->Insert.");

    LOG_INFO("DataShareHelper::Insert end.");
    return index;
}

/**
 * @brief Updates data records in the database.
 *
 * @param uri Indicates the path of data to update.
 * @param predicates Indicates filter criteria. You should define the processing logic when this parameter is null.
 * @param value Indicates the data to update. This parameter can be null.
 *
 * @return Returns the number of data records updated.
 */
int DataShareHelper::Update(
    Uri &uri, const DataSharePredicates &predicates, const DataShareValuesBucket &value)
{
    LOG_INFO("DataShareHelper::Update start.");
    int index = INVALID_VALUE;
    if (!CheckUriParam(uri)) {
        LOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return index;
    }

    if (dataShareProxy_ == nullptr) {
        dataShareProxy_ = dataShareConnection_->GetDataShareProxy();
    }

    if (dataShareProxy_) {
        AddDataShareDeathRecipient(dataShareProxy_->AsObject());
    } else {
        LOG_ERROR("%{public}s failed with invalid dataShareProxy_", __func__);
        return index;
    }

    LOG_INFO("DataShareHelper::Update before dataShareProxy_->Update.");
    index = dataShareProxy_->Update(uri, predicates, value);
    LOG_INFO("DataShareHelper::Update after dataShareProxy_->Update.");

    LOG_INFO("DataShareHelper::Update end.");
    return index;
}

/**
 * @brief Deletes one or more data records from the database.
 *
 * @param uri Indicates the path of the data to operate.
 * @param predicates Indicates filter criteria. You should define the processing logic when this parameter is null.
 *
 * @return Returns the number of data records deleted.
 */
int DataShareHelper::Delete(Uri &uri, const DataSharePredicates &predicates)
{
    LOG_INFO("DataShareHelper::Delete start.");
    int index = INVALID_VALUE;
    if (!CheckUriParam(uri)) {
        LOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return index;
    }

    if (dataShareProxy_ == nullptr) {
        dataShareProxy_ = dataShareConnection_->GetDataShareProxy();
    }

    if (dataShareProxy_) {
        AddDataShareDeathRecipient(dataShareProxy_->AsObject());
    } else {
        LOG_ERROR("%{public}s failed with invalid dataShareProxy_", __func__);
        return index;
    }

    LOG_INFO("DataShareHelper::Delete before dataShareProxy_->Delete.");
    index = dataShareProxy_->Delete(uri, predicates);
    LOG_INFO("DataShareHelper::Delete after dataShareProxy_->Delete.");

    LOG_INFO("DataShareHelper::Delete end.");
    return index;
}

/**
 * @brief Deletes one or more data records from the database.
 *
 * @param uri Indicates the path of data to query.
 * @param predicates Indicates filter criteria. You should define the processing logic when this parameter is null.
 * @param columns Indicates the columns to query. If this parameter is null, all columns are queried.
 *
 * @return Returns the query result.
 */
std::shared_ptr<DataShareResultSet> DataShareHelper::Query(
    Uri &uri, const DataSharePredicates &predicates, std::vector<std::string> &columns)
{
    LOG_INFO("DataShareHelper::Query start.");
    std::shared_ptr<DataShareResultSet> resultset = nullptr;

    if (!CheckUriParam(uri)) {
        LOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return resultset;
    }

    if (dataShareProxy_ == nullptr) {
        dataShareProxy_ = dataShareConnection_->GetDataShareProxy();
    }

    if (dataShareProxy_) {
        AddDataShareDeathRecipient(dataShareProxy_->AsObject());
    } else {
        LOG_ERROR("%{public}s failed with invalid dataShareProxy_", __func__);
        return resultset;
    }

    LOG_INFO("DataShareHelper::Query before dataShareProxy_->Query.");
    resultset = dataShareProxy_->Query(uri, predicates, columns);
    LOG_INFO("DataShareHelper::Query after dataShareProxy_->Query.");

    LOG_INFO("DataShareHelper::Query end.");
    return resultset;
}

/**
 * @brief Obtains the MIME type matching the data specified by the URI of the data share. This method should be
 * implemented by a data share. Data abilities supports general data types, including text, HTML, and JPEG.
 *
 * @param uri Indicates the URI of the data.
 *
 * @return Returns the MIME type that matches the data specified by uri.
 */
std::string DataShareHelper::GetType(Uri &uri)
{
    LOG_INFO("DataShareHelper::GetType start.");
    std::string type;
    if (!CheckUriParam(uri)) {
        LOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return type;
    }

    if (dataShareProxy_ == nullptr) {
        dataShareProxy_ = dataShareConnection_->GetDataShareProxy();
    }

    if (dataShareProxy_) {
        AddDataShareDeathRecipient(dataShareProxy_->AsObject());
    } else {
        LOG_ERROR("%{public}s failed with invalid dataShareProxy_", __func__);
        return type;
    }

    LOG_INFO("DataShareHelper::GetType before dataShareProxy_->GetType.");
    type = dataShareProxy_->GetType(uri);
    LOG_INFO("DataShareHelper::GetType after dataShareProxy_->GetType.");

    LOG_INFO("DataShareHelper::GetType end.");
    return type;
}

/**
 * @brief Inserts multiple data records into the database.
 *
 * @param uri Indicates the path of the data to operate.
 * @param values Indicates the data records to insert.
 *
 * @return Returns the number of data records inserted.
 */
int DataShareHelper::BatchInsert(Uri &uri, const std::vector<DataShareValuesBucket> &values)
{
    LOG_INFO("DataShareHelper::BatchInsert start.");
    int ret = INVALID_VALUE;
    if (!CheckUriParam(uri)) {
        LOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return ret;
    }

    if (dataShareProxy_ == nullptr) {
        dataShareProxy_ = dataShareConnection_->GetDataShareProxy();
    }

    if (dataShareProxy_) {
        AddDataShareDeathRecipient(dataShareProxy_->AsObject());
    } else {
        LOG_ERROR("%{public}s failed with invalid dataShareProxy_", __func__);
        return ret;
    }

    LOG_INFO("DataShareHelper::BatchInsert before dataShareProxy_->BatchInsert.");
    ret = dataShareProxy_->BatchInsert(uri, values);
    LOG_INFO("DataShareHelper::BatchInsert after dataShareProxy_->BatchInsert.");

    LOG_INFO("DataShareHelper::BatchInsert end.");
    return ret;
}

bool DataShareHelper::CheckUriParam(const Uri &uri)
{
    LOG_INFO("DataShareHelper::CheckUriParam start.");
    Uri checkUri(uri.ToString());
    if (!CheckOhosUri(checkUri)) {
        LOG_ERROR("DataShareHelper::CheckUriParam failed. CheckOhosUri uri failed");
        return false;
    }

    if (uri_.ToString().empty()) {
        if (!CheckOhosUri(uri_)) {
            LOG_ERROR("DataShareHelper::CheckUriParam failed. CheckOhosUri uri_ failed");
            return false;
        }

        std::vector<std::string> checkSegments;
        checkUri.GetPathSegments(checkSegments);

        std::vector<std::string> segments;
        uri_.GetPathSegments(segments);

        if (checkSegments[0] != segments[0]) {
            LOG_ERROR("DataShareHelper::CheckUriParam failed. the datashare in uri doesn't equal the one in uri_.");
            return false;
        }
    }
    LOG_INFO("DataShareHelper::CheckUriParam end.");
    return true;
}

bool DataShareHelper::CheckOhosUri(const Uri &uri)
{
    LOG_INFO("DataShareHelper::CheckOhosUri start.");
    Uri checkUri(uri.ToString());
    if (checkUri.GetScheme() != SCHEME_DATASHARE) {
        LOG_ERROR("DataShareHelper::CheckOhosUri failed. uri is not a datashare one.");
        return false;
    }

    std::vector<std::string> segments;
    checkUri.GetPathSegments(segments);
    if (segments.empty()) {
        LOG_ERROR("DataShareHelper::CheckOhosUri failed. There is no segments in the uri.");
        return false;
    }

    if (checkUri.GetPath() == "") {
        LOG_ERROR("DataShareHelper::CheckOhosUri failed. The path in the uri is empty.");
        return false;
    }
    LOG_INFO("DataShareHelper::CheckOhosUri end.");
    return true;
}

/**
 * @brief Registers an observer to DataObsMgr specified by the given Uri.
 *
 * @param uri, Indicates the path of the data to operate.
 * @param dataObserver, Indicates the IDataAbilityObserver object.
 */
void DataShareHelper::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    LOG_INFO("DataShareHelper::RegisterObserver start.");
    if (!CheckUriParam(uri)) {
        LOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return;
    }

    if (dataObserver == nullptr) {
        LOG_ERROR("%{public}s called. dataObserver is nullptr", __func__);
        return;
    }

    Uri tmpUri(uri.ToString());
    std::lock_guard<std::mutex> lock_l(oplock_);
    if (uri_.ToString().empty()) {
        auto datashare = registerMap_.find(dataObserver);
        if (datashare == registerMap_.end()) {
            if (!dataShareConnection_->IsExtAbilityConnected()) {
                dataShareConnection_->ConnectDataShareExtAbility(uri, token_);
            }
            dataShareProxy_ = dataShareConnection_->GetDataShareProxy();
            registerMap_.emplace(dataObserver, dataShareProxy_);
            uriMap_.emplace(dataObserver, tmpUri.GetPath());
        } else {
            auto path = uriMap_.find(dataObserver);
            if (path->second != tmpUri.GetPath()) {
                LOG_ERROR("DataShareHelper::RegisterObserver failed input uri's path is not equal the one the "
                         "observer used");
                return;
            }
            dataShareProxy_ = datashare->second;
        }
    } else {
        dataShareProxy_ = dataShareConnection_->GetDataShareProxy();
    }

    if (dataShareProxy_ == nullptr) {
        LOG_ERROR("DataShareHelper::RegisterObserver failed dataShareProxy_ == nullptr");
        registerMap_.erase(dataObserver);
        uriMap_.erase(dataObserver);
        return;
    }
    dataShareProxy_->RegisterObserver(uri, dataObserver);
    LOG_INFO("DataShareHelper::RegisterObserver end.");
}

/**
 * @brief Deregisters an observer used for DataObsMgr specified by the given Uri.
 *
 * @param uri, Indicates the path of the data to operate.
 * @param dataObserver, Indicates the IDataAbilityObserver object.
 */
void DataShareHelper::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    LOG_INFO("DataShareHelper::UnregisterObserver start.");
    if (!CheckUriParam(uri)) {
        LOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return;
    }

    if (dataObserver == nullptr) {
        LOG_ERROR("%{public}s called. dataObserver is nullptr", __func__);
        return;
    }

    Uri tmpUri(uri.ToString());
    std::lock_guard<std::mutex> lock_l(oplock_);
    if (uri_.ToString().empty()) {
        auto datashare = registerMap_.find(dataObserver);
        if (datashare == registerMap_.end()) {
            return;
        }
        auto path = uriMap_.find(dataObserver);
        if (path->second != tmpUri.GetPath()) {
            LOG_ERROR("DataShareHelper::UnregisterObserver failed input uri's path is not equal the one the "
                     "observer used");
            return;
        }
        dataShareProxy_ = datashare->second;
    } else {
        dataShareProxy_ = dataShareConnection_->GetDataShareProxy();
    }

    if (dataShareProxy_ == nullptr) {
        LOG_ERROR("DataShareHelper::UnregisterObserver failed dataShareProxy_ == nullptr");
        return;
    }

    dataShareProxy_->UnregisterObserver(uri, dataObserver);
    if (uri_.ToString().empty()) {
        LOG_INFO("DataShareHelper::UnregisterObserver before DisconnectDataShareExtAbility.");
        if (dataShareConnection_->IsExtAbilityConnected()) {
            dataShareConnection_->DisconnectDataShareExtAbility();
        }
        LOG_INFO("DataShareHelper::UnregisterObserver after DisconnectDataShareExtAbility.");
        dataShareProxy_ = nullptr;
    }
    registerMap_.erase(dataObserver);
    uriMap_.erase(dataObserver);
    LOG_INFO("DataShareHelper::UnregisterObserver end.");
}

/**
 * @brief Notifies the registered observers of a change to the data resource specified by Uri.
 *
 * @param uri, Indicates the path of the data to operate.
 */
void DataShareHelper::NotifyChange(const Uri &uri)
{
    LOG_INFO("DataShareHelper::NotifyChange start.");
    if (!CheckUriParam(uri)) {
        LOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return;
    }

    if (dataShareProxy_ == nullptr) {
        dataShareProxy_ = dataShareConnection_->GetDataShareProxy();
    }

    if (dataShareProxy_) {
        AddDataShareDeathRecipient(dataShareProxy_->AsObject());
    } else {
        LOG_ERROR("%{public}s failed with invalid dataShareProxy_", __func__);
        return;
    }

    LOG_INFO("DataShareHelper::NotifyChange before dataShareProxy_->NotifyChange.");
    dataShareProxy_->NotifyChange(uri);
    LOG_INFO("DataShareHelper::NotifyChange after dataShareProxy_->NotifyChange.");

    LOG_INFO("DataShareHelper::NotifyChange end.");
}

/**
 * @brief Converts the given uri that refer to the data share into a normalized URI. A normalized URI can be used
 * across devices, persisted, backed up, and restored. It can refer to the same item in the data share even if the
 * context has changed. If you implement URI normalization for a data share, you must also implement
 * denormalizeUri(ohos.utils.net.Uri) to enable URI denormalization. After this feature is enabled, URIs passed to any
 * method that is called on the data share must require normalization verification and denormalization. The default
 * implementation of this method returns null, indicating that this data share does not support URI normalization.
 *
 * @param uri Indicates the Uri object to normalize.
 *
 * @return Returns the normalized Uri object if the data share supports URI normalization; returns null otherwise.
 */
Uri DataShareHelper::NormalizeUri(Uri &uri)
{
    LOG_INFO("DataShareHelper::NormalizeUri start.");
    Uri urivalue("");
    if (!CheckUriParam(uri)) {
        LOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return urivalue;
    }

    if (dataShareProxy_ == nullptr) {
        dataShareProxy_ = dataShareConnection_->GetDataShareProxy();
    }

    if (dataShareProxy_) {
        AddDataShareDeathRecipient(dataShareProxy_->AsObject());
    } else {
        LOG_ERROR("%{public}s failed with invalid dataShareProxy_", __func__);
        return urivalue;
    }

    LOG_INFO("DataShareHelper::NormalizeUri before dataShareProxy_->NormalizeUri.");
    urivalue = dataShareProxy_->NormalizeUri(uri);
    LOG_INFO("DataShareHelper::NormalizeUri after dataShareProxy_->NormalizeUri.");

    LOG_INFO("DataShareHelper::NormalizeUri end.");
    return urivalue;
}

/**
 * @brief Converts the given normalized uri generated by normalizeUri(ohos.utils.net.Uri) into a denormalized one.
 * The default implementation of this method returns the original URI passed to it.
 *
 * @param uri uri Indicates the Uri object to denormalize.
 *
 * @return Returns the denormalized Uri object if the denormalization is successful; returns the original Uri passed to
 * this method if there is nothing to do; returns null if the data identified by the original Uri cannot be found in
 * the current environment.
 */
Uri DataShareHelper::DenormalizeUri(Uri &uri)
{
    LOG_INFO("DataShareHelper::DenormalizeUri start.");
    Uri urivalue("");
    if (!CheckUriParam(uri)) {
        LOG_ERROR("%{public}s called. CheckUriParam uri failed", __func__);
        return urivalue;
    }

    if (dataShareProxy_ == nullptr) {
        dataShareProxy_ = dataShareConnection_->GetDataShareProxy();
    }

    if (dataShareProxy_) {
        AddDataShareDeathRecipient(dataShareProxy_->AsObject());
    } else {
        LOG_ERROR("%{public}s failed with invalid dataShareProxy_", __func__);
        return urivalue;
    }

    LOG_INFO("DataShareHelper::DenormalizeUri before dataShareProxy_->DenormalizeUri.");
    urivalue = dataShareProxy_->DenormalizeUri(uri);
    LOG_INFO("DataShareHelper::DenormalizeUri after dataShareProxy_->DenormalizeUri.");

    LOG_INFO("DataShareHelper::DenormalizeUri end.");
    return urivalue;
}

void DataShareDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    LOG_INFO("recv DataShareDeathRecipient death notice");
    if (handler_) {
        handler_(remote);
    }
    LOG_INFO("DataShareHelper::OnRemoteDied end.");
}

DataShareDeathRecipient::DataShareDeathRecipient(RemoteDiedHandler handler) : handler_(handler)
{}

DataShareDeathRecipient::~DataShareDeathRecipient()
{}
}  // namespace DataShare
}  // namespace OHOS