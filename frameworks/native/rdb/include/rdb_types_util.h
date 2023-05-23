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

#ifndef DISTRIBUTED_RDB_RDB_TYPES_UTIL_H
#define DISTRIBUTED_RDB_RDB_TYPES_UTIL_H
#include "itypes_util.h"
#include "rdb_types.h"
#include "value_object.h"
#include "values_bucket.h"
#include "rdb_visibility.h"
namespace OHOS::ITypesUtil {
using SubOption = DistributedRdb::SubscribeOption;
using SyncerParam = DistributedRdb::RdbSyncerParam;
using SyncOption = DistributedRdb::SyncOption;
using RdbPredicates = DistributedRdb::RdbPredicates;
using RdbOperation = DistributedRdb::RdbPredicateOperation;
using ValueObject = NativeRdb::ValueObject;
using ValuesBucket = NativeRdb::ValuesBucket;
using Asset = NativeRdb::AssetValue;
template<>
API_EXPORT bool Marshalling(const SyncerParam &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(SyncerParam &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const SyncOption &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(SyncOption &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const RdbPredicates &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(RdbPredicates &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const RdbOperation &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(RdbOperation &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const ValueObject &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(ValueObject &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const ValuesBucket &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(ValuesBucket &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const Asset &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(Asset &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const SubOption &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(SubOption &output, MessageParcel &data);
}
#endif // DISTRIBUTED_RDB_RDB_TYPES_UTIL_H
