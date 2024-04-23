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

#include "rdb_types_util.h"
namespace OHOS::ITypesUtil {
template<>
bool Marshalling(const SyncerParam &input, MessageParcel &data)
{
    return ITypesUtil::Marshal(data, input.bundleName_, input.hapName_, input.storeName_, input.area_,
        input.level_, input.type_, input.isEncrypt_, input.password_, input.customDir_, input.isAutoClean_,
        input.isSearchable_);
}
template<>
bool Unmarshalling(SyncerParam &output, MessageParcel &data)
{
    return ITypesUtil::Unmarshal(data, output.bundleName_, output.hapName_, output.storeName_, output.area_,
        output.level_, output.type_, output.isEncrypt_, output.password_, output.customDir_, output.isAutoClean_,
        output.isSearchable_);
}

template<>
bool Marshalling(const Option &input, MessageParcel &data)
{
    return ITypesUtil::Marshal(data, input.mode, input.seqNum, input.isAsync, input.isAutoSync, input.isCompensation);
}

template<>
bool Unmarshalling(Option &output, MessageParcel &data)
{
    return ITypesUtil::Unmarshal(
        data, output.mode, output.seqNum, output.isAsync, output.isAutoSync, output.isCompensation);
}

template<>
bool Marshalling(const RdbPredicates &input, MessageParcel &data)
{
    return ITypesUtil::Marshal(data, input.tables_, input.devices_, input.operations_);
}
template<>
bool Unmarshalling(RdbPredicates &output, MessageParcel &data)
{
    return ITypesUtil::Unmarshal(data, output.tables_, output.devices_, output.operations_);
}

template<>
bool Marshalling(const RdbOperation &input, MessageParcel &data)
{
    return ITypesUtil::Marshal(data, static_cast<int32_t>(input.operator_), input.field_, input.values_);
}

template<>
bool Unmarshalling(RdbOperation &output, MessageParcel &data)
{
    int32_t option;
    auto ret = ITypesUtil::Unmarshal(data, option, output.field_, output.values_);
    output.operator_ = static_cast<decltype(output.operator_)>(option);
    return ret;
}

template<>
bool Marshalling(const SubOption &input, MessageParcel &data)
{
    return ITypesUtil::Marshal(data, static_cast<int32_t>(input.mode));
}

template<>
bool Unmarshalling(SubOption &output, MessageParcel &data)
{
    int32_t mode = static_cast<int32_t>(output.mode);
    auto ret = ITypesUtil::Unmarshal(data, mode);
    output.mode = static_cast<decltype(output.mode)>(mode);
    return ret;
}
template<>
bool Marshalling(const ValueObject &input, MessageParcel &data)
{
    return Marshal(data, input.value);
}
template<>
bool Unmarshalling(ValueObject &output, MessageParcel &data)
{
    return Unmarshal(data, output.value);
}

template<>
bool Marshalling(const ValuesBucket &input, MessageParcel &data)
{
    return Marshal(data, input.values_);
}
template<>
bool Unmarshalling(ValuesBucket &output, MessageParcel &data)
{
    return Unmarshal(data, output.values_);
}

template<>
bool Marshalling(const Asset &input, MessageParcel &data)
{
    return Marshal(data, input.version, input.name, input.size, input.modifyTime, input.uri);
}
template<>
bool Unmarshalling(Asset &output, MessageParcel &data)
{
    return Unmarshal(data, output.version, output.name, output.size, output.modifyTime, output.uri);
}
template<>
bool Marshalling(const ProgressDetail &input, MessageParcel &data)
{
    return Marshal(data, input.progress, input.code, input.details);
}
template<>
bool Unmarshalling(ProgressDetail &output, MessageParcel &data)
{
    return Unmarshal(data, output.progress, output.code, output.details);
}
template<>
bool Marshalling(const TableDetail &input, MessageParcel &data)
{
    return Marshal(data, input.upload, input.download);
}
template<>
bool Unmarshalling(TableDetail &output, MessageParcel &data)
{
    return Unmarshal(data, output.upload, output.download);
}
template<>
bool Marshalling(const Statistic &input, MessageParcel &data)
{
    return Marshal(data, input.total, input.success, input.failed, input.untreated);
}
template<>
bool Unmarshalling(Statistic &output, MessageParcel &data)
{
    return Unmarshal(data, output.total, output.success, output.failed, output.untreated);
}

template<>
bool Marshalling(const PrimaryKeys &input, MessageParcel &data)
{
    return Marshal(data, input[Observer::CHG_TYPE_INSERT], input[Observer::CHG_TYPE_UPDATE],
        input[Observer::CHG_TYPE_DELETE]);
}
template<>
bool Unmarshalling(PrimaryKeys &output, MessageParcel &data)
{
    return Unmarshal(data, output[Observer::CHG_TYPE_INSERT], output[Observer::CHG_TYPE_UPDATE],
        output[Observer::CHG_TYPE_DELETE]);
}

template<>
bool Marshalling(const Origin &input, MessageParcel &data)
{
    return Marshal(data, input.origin, input.dataType, input.id, input.store);
}
template<>
bool Unmarshalling(Origin &output, MessageParcel &data)
{
    return Unmarshal(data, output.origin, output.dataType, output.id, output.store);
}

template<>
bool Marshalling(const RdbChangedData &input, MessageParcel &data)
{
    return Marshal(data, input.tableData);
}
template<>
bool Unmarshalling(RdbChangedData &output, MessageParcel &data)
{
    return Unmarshal(data, output.tableData);
}

template<>
bool Marshalling(const RdbProperties &input, MessageParcel &data)
{
    return Marshal(data, input.isTrackedDataChange);
}
template<>
bool Unmarshalling(RdbProperties &output, MessageParcel &data)
{
    return Unmarshal(data, output.isTrackedDataChange);
}

template<>
bool Marshalling(const Reference &input, MessageParcel &data)
{
    return Marshal(data, input.sourceTable, input.targetTable, input.refFields);
}
template<>
bool Unmarshalling(Reference &output, MessageParcel &data)
{
    return Unmarshal(data, output.sourceTable, output.targetTable, output.refFields);
}

template<>
bool Marshalling(const BigInt& input, MessageParcel& data)
{
    return ITypesUtil::Marshal(data, input.Sign(), input.Value());
}

template<>
bool Unmarshalling(BigInt& output, MessageParcel& data)
{
    int32_t sign = 0;
    std::vector<uint64_t> value;
    if (!ITypesUtil::Unmarshal(data, sign, value)) {
        return false;
    }
    output = BigInt(sign, std::move(value));
    return true;
}
}