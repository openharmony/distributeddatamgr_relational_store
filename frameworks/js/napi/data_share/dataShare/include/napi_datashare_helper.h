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

#ifndef NAPI_DATASHARE_HELPER_H
#define NAPI_DATASHARE_HELPER_H
#include "napi_datashare_observer.h"
#include "data_share_common.h"

namespace OHOS {
namespace DataShare {
/**
 * @brief DataShareHelper NAPI module registration.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param exports An empty object via the exports parameter as a convenience.
 *
 * @return The return value from Init is treated as the exports object for the module.
 */
napi_value DataShareHelperInit(napi_env env, napi_value exports);
napi_value DataShareHelperConstructor(napi_env env, napi_callback_info info);

/**
 * @brief DataShareHelper NAPI method : insert.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_Insert(napi_env env, napi_callback_info info);

/**
 * @brief Insert processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param insertCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value InsertWrap(napi_env env, napi_callback_info info, DSHelperInsertCB *insertCB);

/**
 * @brief Insert Async.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param args Indicates the arguments passed into the callback.
 * @param argcPromise Asynchronous data processing.
 * @param insertCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value InsertAsync(napi_env env, napi_value *args, const size_t argCallback, DSHelperInsertCB *insertCB);

/**
 * @brief Insert Promise.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param insertCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value InsertPromise(napi_env env, DSHelperInsertCB *insertCB);

/**
 * @brief Insert asynchronous processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param data Point to asynchronous processing of data.
 */
void InsertExecuteCB(napi_env env, void *data);

/**
 * @brief The callback at the end of the asynchronous callback.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param data Point to asynchronous processing of data.
 */
void InsertAsyncCompleteCB(napi_env env, napi_status status, void *data);

/**
 * @brief The callback at the end of the Promise callback.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param data Point to asynchronous processing of data.
 */
void InsertPromiseCompleteCB(napi_env env, napi_status status, void *data);

/**
 * @brief DataShareHelper NAPI method : notifyChange.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_NotifyChange(napi_env env, napi_callback_info info);

/**
 * @brief NotifyChange processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param notifyChangeCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value NotifyChangeWrap(napi_env env, napi_callback_info info, DSHelperNotifyChangeCB *notifyChangeCB);

/**
 * @brief NotifyChange Async.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param args Indicates the arguments passed into the callback.
 * @param argcPromise Asynchronous data processing.
 * @param notifyChangeCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value NotifyChangeAsync(
    napi_env env, napi_value *args, size_t argcAsync, const size_t argcPromise, DSHelperNotifyChangeCB *notifyChangeCB);

/**
 * @brief NotifyChange Promise.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param notifyChangeCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value NotifyChangePromise(napi_env env, DSHelperNotifyChangeCB *notifyChangeCB);

/**
 * @brief NotifyChange asynchronous processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param data Point to asynchronous processing of data.
 */
void NotifyChangeExecuteCB(napi_env env, void *data);

/**
 * @brief The callback at the end of the asynchronous callback.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param data Point to asynchronous processing of data.
 */
void NotifyChangeAsyncCompleteCB(napi_env env, napi_status status, void *data);

/**
 * @brief The callback at the end of the Promise callback.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param data Point to asynchronous processing of data.
 */
void NotifyChangePromiseCompleteCB(napi_env env, napi_status status, void *data);

/**
 * @brief DataShareHelper NAPI method : on.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_Register(napi_env env, napi_callback_info info);

/**
 * @brief On processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param insertCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value RegisterWrap(napi_env env, napi_callback_info info, DSHelperOnOffCB *insertCB);

/**
 * @brief On Async.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param args Indicates the arguments passed into the callback.
 * @param argcPromise Asynchronous data processing.
 * @param insertCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value RegisterAsync(
    napi_env env, napi_value *args, size_t argcAsync, const size_t argcPromise, DSHelperOnOffCB *insertCB);

/**
 * @brief On asynchronous processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param data Point to asynchronous processing of data.
 */
void RegisterExecuteCB(napi_env env, void *data);
void RegisterCompleteCB(napi_env env, napi_status status, void *data);

/**
 * @brief DataShareHelper NAPI method : off.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_UnRegister(napi_env env, napi_callback_info info);

/**
 * @brief Off processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param insertCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value UnRegisterWrap(napi_env env, napi_callback_info info, DSHelperOnOffCB *insertCB);

/**
 * @brief Off Async.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param args Indicates the arguments passed into the callback.
 * @param argcPromise Asynchronous data processing.
 * @param insertCB Process data asynchronously.
 *
 * @return Return JS data successfully, otherwise return nullptr.
 */
napi_value UnRegisterAsync(
    napi_env env, napi_value *args, size_t argcAsync, const size_t argcPromise, DSHelperOnOffCB *insertCB);

/**
 * @brief Off asynchronous processing function.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param data Point to asynchronous processing of data.
 */
void UnRegisterExecuteCB(napi_env env, void *data);
void UnRegisterCompleteCB(napi_env env, napi_status status, void *data);
void FindRegisterObs(napi_env env, DSHelperOnOffCB *data);
/**
 * @brief Parse the ValuesBucket parameters.
 *
 * @param param Indicates the want parameters saved the parse result.
 * @param env The environment that the Node-API call is invoked under.
 * @param args Indicates the arguments passed into the callback.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value UnwrapValuesBucket(std::string &value, napi_env env, napi_value args);

static std::vector<DSHelperOnOffCB *> registerInstances_;
napi_value NAPI_Release(napi_env env, napi_callback_info info);

napi_value ReleaseWrap(napi_env env, napi_callback_info info, DSHelperReleaseCB *releaseCB);

napi_value ReleaseAsync(napi_env env, napi_value *args, const size_t argCallback, DSHelperReleaseCB *releaseCB);

napi_value ReleasePromise(napi_env env, DSHelperReleaseCB *releaseCB);

void ReleaseExecuteCB(napi_env env, void *data);

void ReleaseAsyncCompleteCB(napi_env env, napi_status status, void *data);

void ReleasePromiseCompleteCB(napi_env env, napi_status status, void *data);

napi_value NAPI_GetType(napi_env env, napi_callback_info info);
napi_value NAPI_GetType(napi_env env, napi_callback_info info);
napi_value GetTypeWrap(napi_env env, napi_callback_info info, DSHelperGetTypeCB *gettypeCB);
napi_value GetTypeAsync(napi_env env, napi_value *args, const size_t argCallback, DSHelperGetTypeCB *gettypeCB);
napi_value GetTypePromise(napi_env env, DSHelperGetTypeCB *gettypeCB);
void GetTypeExecuteCB(napi_env env, void *data);
void GetTypeAsyncCompleteCB(napi_env env, napi_status status, void *data);
void GetTypePromiseCompleteCB(napi_env env, napi_status status, void *data);

napi_value NAPI_GetFileTypes(napi_env env, napi_callback_info info);
napi_value NAPI_GetFileTypes(napi_env env, napi_callback_info info);
napi_value GetFileTypesWrap(napi_env env, napi_callback_info info, DSHelperGetFileTypesCB *getfiletypesCB);
napi_value GetFileTypesAsync(
    napi_env env, napi_value *args, const size_t argCallback, DSHelperGetFileTypesCB *getfiletypesCB);
napi_value GetFileTypesPromise(napi_env env, DSHelperGetFileTypesCB *getfiletypesCB);
void GetFileTypesExecuteCB(napi_env env, void *data);
void GetFileTypesAsyncCompleteCB(napi_env env, napi_status status, void *data);
void GetFileTypesPromiseCompleteCB(napi_env env, napi_status status, void *data);
napi_value WrapGetFileTypesCB(napi_env env, const DSHelperGetFileTypesCB &getfiletypesCB);

napi_value NAPI_NormalizeUri(napi_env env, napi_callback_info info);
napi_value NAPI_NormalizeUri(napi_env env, napi_callback_info info);
napi_value NormalizeUriWrap(napi_env env, napi_callback_info info, DSHelperNormalizeUriCB *normalizeuriCB);
napi_value NormalizeUriAsync(
    napi_env env, napi_value *args, const size_t argCallback, DSHelperNormalizeUriCB *normalizeuriCB);
napi_value NormalizeUriPromise(napi_env env, DSHelperNormalizeUriCB *normalizeuriCB);
void NormalizeUriExecuteCB(napi_env env, void *data);
void NormalizeUriAsyncCompleteCB(napi_env env, napi_status status, void *data);
void NormalizeUriPromiseCompleteCB(napi_env env, napi_status status, void *data);

napi_value NAPI_DenormalizeUri(napi_env env, napi_callback_info info);
napi_value NAPI_DenormalizeUri(napi_env env, napi_callback_info info);
napi_value DenormalizeUriWrap(napi_env env, napi_callback_info info, DSHelperDenormalizeUriCB *denormalizeuriCB);
napi_value DenormalizeUriAsync(
    napi_env env, napi_value *args, const size_t argCallback, DSHelperDenormalizeUriCB *denormalizeuriCB);
napi_value DenormalizeUriPromise(napi_env env, DSHelperDenormalizeUriCB *denormalizeuriCB);
void DenormalizeUriExecuteCB(napi_env env, void *data);
void DenormalizeUriAsyncCompleteCB(napi_env env, napi_status status, void *data);
void DenormalizeUriPromiseCompleteCB(napi_env env, napi_status status, void *data);

napi_value NAPI_Delete(napi_env env, napi_callback_info info);

napi_value DeleteWrap(napi_env env, napi_callback_info info, DSHelperDeleteCB *deleteCB);
napi_value DeleteAsync(napi_env env, napi_value *args, const size_t argCallback, DSHelperDeleteCB *deleteCB);

napi_value DeletePromise(napi_env env, DSHelperDeleteCB *deleteCB);

void DeleteExecuteCB(napi_env env, void *data);

void DeleteAsyncCompleteCB(napi_env env, napi_status status, void *data);

void DeletePromiseCompleteCB(napi_env env, napi_status status, void *data);

napi_value NAPI_Update(napi_env env, napi_callback_info info);

napi_value UpdateWrap(napi_env env, napi_callback_info info, DSHelperUpdateCB *updateCB);
napi_value UpdateAsync(napi_env env, napi_value *args, const size_t argCallback, DSHelperUpdateCB *updateCB);

napi_value UpdatePromise(napi_env env, DSHelperUpdateCB *updateCB);

void UpdateExecuteCB(napi_env env, void *data);

void UpdateAsyncCompleteCB(napi_env env, napi_status status, void *data);

void UpdatePromiseCompleteCB(napi_env env, napi_status status, void *data);

napi_value NAPI_OpenFile(napi_env env, napi_callback_info info);

napi_value OpenFileWrap(napi_env env, napi_callback_info info, DSHelperOpenFileCB *openFileCB);
napi_value OpenFileAsync(napi_env env, napi_value *args, const size_t argCallback, DSHelperOpenFileCB *openFileCB);

napi_value OpenFilePromise(napi_env env, DSHelperOpenFileCB *openFileCB);

void OpenFileExecuteCB(napi_env env, void *data);

void OpenFileAsyncCompleteCB(napi_env env, napi_status status, void *data);

void OpenFilePromiseCompleteCB(napi_env env, napi_status status, void *data);

napi_value NAPI_BatchInsert(napi_env env, napi_callback_info info);

napi_value BatchInsertWrap(napi_env env, napi_callback_info info, DSHelperBatchInsertCB *batchInsertCB);
napi_value BatchInsertAsync(
    napi_env env, napi_value *args, const size_t argCallback, DSHelperBatchInsertCB *batchInsertCB);

napi_value BatchInsertPromise(napi_env env, DSHelperBatchInsertCB *batchInsertCB);

void BatchInsertExecuteCB(napi_env env, void *data);

void BatchInsertAsyncCompleteCB(napi_env env, napi_status status, void *data);

void BatchInsertPromiseCompleteCB(napi_env env, napi_status status, void *data);

std::vector<DataShareValuesBucket> NapiValueObject(napi_env env, napi_value param);

bool UnwrapArrayObjectFromJS(napi_env env, napi_value param, std::vector<DataShareValuesBucket> &value);

napi_value NAPI_Query(napi_env env, napi_callback_info info);

napi_value QueryWrap(napi_env env, napi_callback_info info, DSHelperQueryCB *queryCB);

napi_value QueryAsync(napi_env env, napi_value *args, const size_t argCallback, DSHelperQueryCB *queryCB);

napi_value QueryPromise(napi_env env, DSHelperQueryCB *queryCB);

void QueryExecuteCB(napi_env env, void *data);

void QueryAsyncCompleteCB(napi_env env, napi_status status, void *data);

void QueryPromiseCompleteCB(napi_env env, napi_status status, void *data);

napi_value WrapResultSet(napi_env env, const std::shared_ptr<DataShareResultSet> &resultSet);

void AnalysisValuesBucket(DataShareValuesBucket &value, const napi_env &env, const napi_value &arg);
void SetValuesBucketObject(
    DataShareValuesBucket &valuesBucket, const napi_env &env, std::string keyStr, napi_value value);

void UnwrapDataSharePredicates(DataSharePredicates &predicates, napi_env env, napi_value value);
}  // namespace DataShare
}  // namespace OHOS
#endif /* NAPI_DATASHARE_HELPER_H */
