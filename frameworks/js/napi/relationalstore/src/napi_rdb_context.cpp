/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "napi_rdb_context.h"

using namespace OHOS::RelationalStoreJsKit;

namespace OHOS {
namespace RelationalStoreJsKit {
constexpr int32_t KEY_INDEX = 0;
constexpr int32_t VALUE_INDEX = 1;
std::shared_ptr<NativeRdb::RdbStore> RdbStoreContextBase::StealRdbStore()
{
    auto rdb = std::move(rdbStore);
    rdbStore = nullptr;
    return rdb;
}
int ParseTransactionOptions(
    const napi_env &env, size_t argc, napi_value *argv, std::shared_ptr<CreateTransactionContext> context)
{
    context->transactionOptions.transactionType = Transaction::DEFERRED;
    if (argc > 0 && !JSUtils::IsNull(env, argv[0])) {
        auto status = JSUtils::Convert2Value(env, argv[0], context->transactionOptions);
        CHECK_RETURN_SET(status == napi_ok, std::make_shared<ParamError>("options", "a transactionOptions"));
    }
    return OK;
}
int ParseTableName(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    context->tableName = JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->tableName.empty(), std::make_shared<ParamError>("table", "not empty string."));
    return OK;
}

int ParseCursor(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    double cursor = 0;
    auto status = JSUtils::Convert2Value(env, arg, cursor);
    CHECK_RETURN_SET(status == napi_ok && cursor > 0, std::make_shared<ParamError>("cursor", "valid cursor."));
    context->cursor = static_cast<uint64_t>(cursor);
    return OK;
}

int ParseCryptoParam(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    auto status = JSUtils::Convert2Value(env, arg, context->cryptoParam);
    CHECK_RETURN_SET(status == napi_ok, std::make_shared<ParamError>("cryptoParam", "valid cryptoParam."));
    return OK;
}

int ParseColumnName(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    context->columnName = JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->columnName.empty(), std::make_shared<ParamError>("columnName", "not empty string."));
    return OK;
}

int ParsePrimaryKey(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    JSUtils::Convert2Value(env, arg, context->keys);
    CHECK_RETURN_SET(!context->keys.empty(), std::make_shared<ParamError>("PRIKey", "number or string."));
    return OK;
}

int ParseDevice(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    context->device = JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->device.empty(), std::make_shared<ParamError>("device", "not empty"));
    return OK;
}

int ParseSrcType(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    std::string value = "";
    int32_t status = JSUtils::Convert2Value(env, arg, value);
    CHECK_RETURN_SET(status == napi_ok, std::make_shared<ParamError>("srcName", "not null"));
    context->srcName = value;
    return OK;
}

int ParseTablesName(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    int32_t ret = JSUtils::Convert2Value(env, arg, context->tablesNames);
    CHECK_RETURN_SET(ret == napi_ok, std::make_shared<ParamError>("tablesNames", "not empty string."));
    return OK;
}

int ParseSyncModeArg(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    napi_valuetype type = napi_undefined;
    napi_typeof(env, arg, &type);
    CHECK_RETURN_SET(type == napi_number, std::make_shared<ParamError>("mode", "a SyncMode Type."));
    napi_status status = napi_get_value_int32(env, arg, &context->enumArg);
    CHECK_RETURN_SET(status == napi_ok, std::make_shared<ParamError>("mode", "a SyncMode Type."));
    bool checked = context->enumArg == 0 || context->enumArg == 1;
    CHECK_RETURN_SET(checked, std::make_shared<ParamError>("mode", "a SyncMode of device."));
    return OK;
}

int ParseDistributedTypeArg(
    const napi_env &env, size_t argc, napi_value *argv, std::shared_ptr<RdbStoreContext> context)
{
    context->distributedType = DistributedRdb::DISTRIBUTED_DEVICE;
    if (argc > 1) {
        auto status = JSUtils::Convert2ValueExt(env, argv[1], context->distributedType);
        bool checked = status == napi_ok && context->distributedType >= DistributedRdb::DISTRIBUTED_DEVICE &&
                       context->distributedType <= DistributedRdb::DISTRIBUTED_CLOUD;
        CHECK_RETURN_SET(JSUtils::IsNull(env, argv[1]) || checked,
            std::make_shared<ParamError>("distributedType", "a DistributedType"));
    }
    return OK;
}

int ParseDistributedConfigArg(
    const napi_env &env, size_t argc, napi_value *argv, std::shared_ptr<RdbStoreContext> context)
{
    context->distributedConfig = { false };
    // '2' Ensure that the incoming argv contains 3 parameter
    if (argc > 2) {
        auto status = JSUtils::Convert2Value(env, argv[2], context->distributedConfig);
        bool checked = status == napi_ok || JSUtils::IsNull(env, argv[2]);
        CHECK_RETURN_SET(checked, std::make_shared<ParamError>("distributedConfig", "a DistributedConfig type"));
    }
    return OK;
}

int ParseCloudSyncModeArg(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    auto status = JSUtils::Convert2ValueExt(env, arg, context->syncMode);
    bool checked = (status == napi_ok && context->syncMode >= DistributedRdb::TIME_FIRST &&
                    context->syncMode <= DistributedRdb::CLOUD_FIRST);
    CHECK_RETURN_SET(checked, std::make_shared<ParamError>("mode", "a SyncMode of cloud."));
    return OK;
}

int ParseCallback(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, arg, &valueType);
    CHECK_RETURN_SET(
        (status == napi_ok && valueType == napi_function), std::make_shared<ParamError>("callback", "a function."));
    NAPI_CALL_BASE(env, napi_create_reference(env, arg, 1, &context->callback_), ERR);
    return OK;
}

int ParseCloudSyncCallback(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, arg, &valueType);
    CHECK_RETURN_SET(valueType == napi_function, std::make_shared<ParamError>("progress", "a callback type"));
    NAPI_CALL_BASE(env, napi_create_reference(env, arg, 1, &context->asyncHolder), ERR);
    return OK;
}

int ParsePredicates(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    auto status = napi_unwrap(env, arg, reinterpret_cast<void **>(&context->predicatesProxy));
    CHECK_RETURN_SET(status == napi_ok && context->predicatesProxy != nullptr,
        std::make_shared<ParamError>("predicates", "an RdbPredicates."));
    context->tableName = context->predicatesProxy->GetPredicates()->GetTableName();
    context->rdbPredicates = context->predicatesProxy->GetPredicates();
    return OK;
}

int ParseSrcName(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    context->srcName = JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->srcName.empty(), std::make_shared<ParamError>("srcName", "not empty"));
    return OK;
}

int ParseColumns(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    napi_valuetype type = napi_undefined;
    napi_typeof(env, arg, &type);
    if (type == napi_undefined || type == napi_null) {
        return OK;
    }
    int32_t ret = JSUtils::Convert2Value(env, arg, context->columns);
    CHECK_RETURN_SET(ret == napi_ok, std::make_shared<ParamError>("columns", "a string array"));
    return OK;
}

int ParseBindArgs(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    context->bindArgs.clear();
    napi_valuetype type = napi_undefined;
    napi_typeof(env, arg, &type);
    if (type == napi_undefined || type == napi_null) {
        return OK;
    }
    bool isArray = false;
    napi_status status = napi_is_array(env, arg, &isArray);
    CHECK_RETURN_SET(status == napi_ok && isArray, std::make_shared<ParamError>("values", "a BindArgs array."));

    uint32_t arrLen = 0;
    status = napi_get_array_length(env, arg, &arrLen);
    CHECK_RETURN_SET(status == napi_ok, std::make_shared<ParamError>("values", "not empty."));
    for (size_t i = 0; i < arrLen; ++i) {
        napi_value element = nullptr;
        napi_get_element(env, arg, i, &element);
        ValueObject valueObject;
        int32_t ret = JSUtils::Convert2Value(env, element, valueObject.value);
        CHECK_RETURN_SET(ret == OK, std::make_shared<ParamError>(std::to_string(i), "ValueObject"));
        // The blob is an empty vector.
        // If the API version is less than 14, and insert null. Otherwise, insert an empty vector.
        if (valueObject.GetType() == ValueObject::TYPE_BLOB && JSUtils::GetHapVersion() < 14) {
            std::vector<uint8_t> tmpValue;
            valueObject.GetBlob(tmpValue);
            if (tmpValue.empty()) {
                valueObject = ValueObject();
            }
        }
        context->bindArgs.push_back(std::move(valueObject));
    }
    return OK;
}

int ParseSql(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    context->sql = JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->sql.empty(), std::make_shared<ParamError>("sql", "not empty"));
    return OK;
}

int ParseTxId(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    int64_t txId = 0;
    auto status = JSUtils::Convert2ValueExt(env, arg, txId);
    CHECK_RETURN_SET(status == napi_ok && txId >= 0, std::make_shared<ParamError>("txId", "not invalid txId"));
    context->txId = txId;
    return OK;
}

int ParseSendableValuesBucket(const napi_env env, const napi_value map, std::shared_ptr<RdbStoreContext> context)
{
    uint32_t length = 0;
    napi_status status = napi_map_get_size(env, map, &length);
    auto error = std::make_shared<ParamError>("ValuesBucket is invalid.");
    CHECK_RETURN_SET(status == napi_ok && length > 0, error);
    napi_value entries = nullptr;
    status = napi_map_get_entries(env, map, &entries);
    CHECK_RETURN_SET(status == napi_ok, std::make_shared<InnerError>("napi_map_get_entries failed."));
    for (uint32_t i = 0; i < length; ++i) {
        napi_value iter = nullptr;
        status = napi_map_iterator_get_next(env, entries, &iter);
        CHECK_RETURN_SET(status == napi_ok, std::make_shared<InnerError>("napi_map_iterator_get_next failed."));
        napi_value values = nullptr;
        status = napi_get_named_property(env, iter, "value", &values);
        CHECK_RETURN_SET(status == napi_ok, std::make_shared<InnerError>("napi_get_named_property value failed."));
        napi_value key = nullptr;
        status = napi_get_element(env, values, KEY_INDEX, &key);
        CHECK_RETURN_SET(status == napi_ok, std::make_shared<InnerError>("napi_get_element key failed."));
        std::string keyStr = JSUtils::Convert2String(env, key);
        napi_value value = nullptr;
        status = napi_get_element(env, values, VALUE_INDEX, &value);
        CHECK_RETURN_SET(status == napi_ok, std::make_shared<InnerError>("napi_get_element value failed."));
        ValueObject valueObject;
        int32_t ret = JSUtils::Convert2Value(env, value, valueObject.value);
        if (ret == napi_ok) {
            context->valuesBucket.Put(keyStr, valueObject);
        } else if (ret != napi_generic_failure) {
            CHECK_RETURN_SET(false, std::make_shared<ParamError>("The value type of " + keyStr, "invalid."));
        }
    }
    return OK;
}

int ParseValuesBucket(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    bool isMap = false;
    napi_status status = napi_is_map(env, arg, &isMap);
    CHECK_RETURN_SET(
        status == napi_ok, std::make_shared<InnerError>("call napi_is_map failed" + std::to_string(status)));
    if (isMap) {
        return ParseSendableValuesBucket(env, arg, context);
    }
    napi_value keys = nullptr;
    napi_get_all_property_names(env, arg, napi_key_own_only,
        static_cast<napi_key_filter>(napi_key_enumerable | napi_key_skip_symbols), napi_key_numbers_to_strings, &keys);
    uint32_t arrLen = 0;
    status = napi_get_array_length(env, keys, &arrLen);
    CHECK_RETURN_SET(status == napi_ok && arrLen > 0, std::make_shared<ParamError>("ValuesBucket is invalid"));

    for (size_t i = 0; i < arrLen; ++i) {
        napi_value key = nullptr;
        status = napi_get_element(env, keys, i, &key);
        CHECK_RETURN_SET(status == napi_ok, std::make_shared<ParamError>("ValuesBucket is invalid."));
        std::string keyStr = JSUtils::Convert2String(env, key);
        napi_value value = nullptr;
        napi_get_property(env, arg, key, &value);
        ValueObject valueObject;
        int32_t ret = JSUtils::Convert2Value(env, value, valueObject.value);
        // The blob is an empty vector.
        // If the API version is less than 14, and insert null. Otherwise, insert an empty vector.
        if (ret == napi_ok && valueObject.GetType() == ValueObject::TYPE_BLOB && JSUtils::GetHapVersion() < 14) {
            std::vector<uint8_t> tmpValue;
            valueObject.GetBlob(tmpValue);
            if (tmpValue.empty()) {
                valueObject = ValueObject();
            }
        }
        if (ret == napi_ok) {
            context->valuesBucket.Put(keyStr, valueObject);
        } else if (ret != napi_generic_failure) {
            CHECK_RETURN_SET(false, std::make_shared<ParamError>("The value type of " + keyStr, "invalid."));
        }
    }
    return OK;
}

int ParseValuesBuckets(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    bool isArray = false;
    napi_status status = napi_is_array(env, arg, &isArray);
    CHECK_RETURN_SET(status == napi_ok && isArray, std::make_shared<ParamError>("ValuesBuckets is invalid."));

    uint32_t arrLen = 0;
    status = napi_get_array_length(env, arg, &arrLen);
    CHECK_RETURN_SET(status == napi_ok && arrLen > 0, std::make_shared<ParamError>("ValuesBuckets is invalid."));

    for (uint32_t i = 0; i < arrLen; ++i) {
        napi_value obj = nullptr;
        status = napi_get_element(env, arg, i, &obj);
        CHECK_RETURN_SET(status == napi_ok, std::make_shared<InnerError>("napi_get_element failed."));

        CHECK_RETURN_ERR(ParseValuesBucket(env, obj, context) == OK);
        context->sharedValuesBuckets.Put(context->valuesBucket);
        context->valuesBucket.Clear();
    }
    return OK;
}

int ParseConflictResolution(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    int32_t conflictResolution = 0;
    napi_get_value_int32(env, arg, &conflictResolution);
    int32_t min = static_cast<int32_t>(NativeRdb::ConflictResolution::ON_CONFLICT_NONE);
    int32_t max = static_cast<int32_t>(NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    bool checked = (conflictResolution >= min) && (conflictResolution <= max);
    CHECK_RETURN_SET(checked, std::make_shared<ParamError>("conflictResolution", "a ConflictResolution."));
    context->conflictResolution = static_cast<NativeRdb::ConflictResolution>(conflictResolution);
    return OK;
}
} // namespace RelationalStoreJsKit
} // namespace OHOS