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

#ifndef DISTRIBUTED_RDB_IRDB_SERVICE_H
#define DISTRIBUTED_RDB_IRDB_SERVICE_H

#include <string>

#include "distributeddata_relational_store_ipc_interface_code.h"
#include "iremote_broker.h"
#include "rdb_service.h"

namespace OHOS::DistributedRdb {
class IRdbService : public RdbService, public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DistributedRdb.IRdbService");
};

class IKvStoreDataService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DistributedKv.IKvStoreDataService");
    virtual sptr<IRemoteObject> GetFeatureInterface(const std::string &name) = 0;
    virtual int32_t RegisterDeathObserver(
        const std::string &bundleName, sptr<IRemoteObject> observer, const std::string &featureName) = 0;
    virtual int32_t Exit(const std::string &featureName) = 0;
};
} // namespace OHOS::DistributedRdb
#endif
