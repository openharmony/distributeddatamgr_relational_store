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

#include "datashare_ext_ability.h"

#include "ability_loader.h"
#include "connection_manager.h"
#include "datashare_log.h"
#include "js_datashare_ext_ability.h"
#include "runtime.h"
#include "datashare_ext_ability_context.h"

namespace OHOS {
namespace DataShare {
using namespace OHOS::AppExecFwk;

CreatorFunc DataShareExtAbility::creator_ = nullptr;
void DataShareExtAbility::SetCreator(const CreatorFunc& creator)
{
    creator_ = creator;
}

DataShareExtAbility* DataShareExtAbility::Create(const std::unique_ptr<Runtime>& runtime)
{
    if (!runtime) {
        return new DataShareExtAbility();
    }

    if (creator_) {
        return creator_(runtime);
    }

    LOG_INFO("DataShareExtAbility::Create runtime");
    switch (runtime->GetLanguage()) {
        case Runtime::Language::JS:
            return JsDataShareExtAbility::Create(runtime);

        default:
            return new DataShareExtAbility();
    }
}

void DataShareExtAbility::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application,
    std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    ExtensionBase<DataShareExtAbilityContext>::Init(record, application, handler, token);
    LOG_INFO("DataShareExtAbility begin init context");
}

std::vector<std::string> DataShareExtAbility::GetFileTypes(const Uri &uri, const std::string &mimeTypeFilter)
{
    LOG_INFO("begin.");
    std::vector<std::string> ret;
    LOG_INFO("end.");
    return ret;
}

int DataShareExtAbility::OpenFile(const Uri &uri, const std::string &mode)
{
    LOG_INFO("begin.");
    LOG_INFO("end.");
    return 0;
}

int DataShareExtAbility::OpenRawFile(const Uri &uri, const std::string &mode)
{
    LOG_INFO("begin.");
    LOG_INFO("end.");
    return 0;
}

int DataShareExtAbility::Insert(const Uri &uri, const DataShareValuesBucket &value)
{
    LOG_INFO("begin.");
    LOG_INFO("end.");
    return 0;
}

int DataShareExtAbility::Update(const Uri &uri, const DataSharePredicates &predicates,
    const DataShareValuesBucket &value)
{
    LOG_INFO("begin.");
    LOG_INFO("end.");
    return 0;
}

int DataShareExtAbility::Delete(const Uri &uri, const DataSharePredicates &predicates)
{
    LOG_INFO("begin.");
    LOG_INFO("end.");
    return 0;
}

std::shared_ptr<DataShareAbstractResultSet> DataShareExtAbility::Query(const Uri &uri,
    const DataSharePredicates &predicates, std::vector<std::string> &columns)
{
    LOG_INFO("begin.");
    std::shared_ptr<DataShareAbstractResultSet> ret;
    LOG_INFO("end.");
    return ret;
}

std::string DataShareExtAbility::GetType(const Uri &uri)
{
    LOG_INFO("begin.");
    LOG_INFO("end.");
    return "";
}

int DataShareExtAbility::BatchInsert(const Uri &uri, const std::vector<DataShareValuesBucket> &values)
{
    LOG_INFO("begin.");
    LOG_INFO("end.");
    return 0;
}

bool DataShareExtAbility::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    LOG_INFO("begin.");
    LOG_INFO("end.");
    return true;
}

bool DataShareExtAbility::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    LOG_INFO("begin.");
    LOG_INFO("end.");
    return true;
}

bool DataShareExtAbility::NotifyChange(const Uri &uri)
{
    LOG_INFO("begin.");
    LOG_INFO("end.");
    return true;
}

Uri DataShareExtAbility::NormalizeUri(const Uri &uri)
{
    LOG_INFO("begin.");
    Uri urivalue("");
    LOG_INFO("end.");
    return urivalue;
}

Uri DataShareExtAbility::DenormalizeUri(const Uri &uri)
{
    LOG_INFO("begin.");
    Uri urivalue("");
    LOG_INFO("end.");
    return urivalue;
}

std::vector<std::shared_ptr<DataShareResult>> DataShareExtAbility::ExecuteBatch(
    const std::vector<std::shared_ptr<DataShareOperation>> &operations)
{
    LOG_INFO("begin.");
    std::vector<std::shared_ptr<DataShareResult>> results;
    LOG_INFO("end.");
    return results;
}
} // namespace DataShare
} // namespace OHOS