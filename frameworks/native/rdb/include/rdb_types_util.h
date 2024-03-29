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
#include "rdb_service.h"
#include "rdb_types.h"
#include "rdb_visibility.h"
#include "value_object.h"
#include "values_bucket.h"

namespace OHOS::ITypesUtil {
using SubOption = DistributedRdb::SubscribeOption;
using SyncerParam = DistributedRdb::RdbSyncerParam;
using Option = DistributedRdb::RdbService::Option;
using RdbPredicates = DistributedRdb::PredicatesMemo;
using RdbOperation = DistributedRdb::RdbPredicateOperation;
using ValueObject = NativeRdb::ValueObject;
using ValuesBucket = NativeRdb::ValuesBucket;
using Asset = NativeRdb::AssetValue;
using ProgressDetail = DistributedRdb::ProgressDetail;
using TableDetail = DistributedRdb::TableDetail;
using Statistic = DistributedRdb::Statistic;
using Observer = DistributedRdb::RdbStoreObserver;
using Origin = DistributedRdb::Origin;
using ChangeInfo = Observer::ChangeInfo;
using PrimaryKey = Observer::PrimaryKey;
using PrimaryKeys = std::vector<PrimaryKey>[Observer::CHG_TYPE_BUTT];
using RdbChangedData = DistributedRdb::RdbChangedData;
using RdbProperties = DistributedRdb::RdbChangeProperties;
using Reference = DistributedRdb::Reference;
using BigInt = NativeRdb::BigInteger;
template<>
API_EXPORT bool Marshalling(const SyncerParam &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(SyncerParam &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const Option &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(Option &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const RdbPredicates &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(RdbPredicates &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const RdbOperation &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(RdbOperation &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const SubOption &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(SubOption &output, MessageParcel &data);
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
template<>
API_EXPORT bool Marshalling(const ProgressDetail &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(ProgressDetail &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const TableDetail &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(TableDetail &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const Statistic &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(Statistic &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const PrimaryKeys &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(PrimaryKeys &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const Origin &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(Origin &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const RdbChangedData &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(RdbChangedData &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const RdbProperties &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(RdbProperties &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const Reference &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(Reference &output, MessageParcel &data);
template<>
API_EXPORT bool Marshalling(const BigInt &input, MessageParcel &data);
template<>
API_EXPORT bool Unmarshalling(BigInt &output, MessageParcel &data);
}
#endif // DISTRIBUTED_RDB_RDB_TYPES_UTIL_H
