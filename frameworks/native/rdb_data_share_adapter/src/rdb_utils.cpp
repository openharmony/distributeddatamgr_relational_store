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
#define LOG_TAG "RdbUtils"
#include "rdb_utils.h"

#include "logger.h"
#include "raw_data_parser.h"
#include "datashare_abs_predicates.h"
#include "datashare_values_bucket.h"

using namespace OHOS::Rdb;
using namespace OHOS::RdbDataShareAdapter;
using namespace OHOS::DataShare;
using namespace OHOS::NativeRdb;

class RdbUtilsImpl : public RdbUtils {
private:
    static void NoSupport(const OperationItem &item, RdbPredicates &query);
    static void EqualTo(const OperationItem &item, RdbPredicates &predicates);
    static void NotEqualTo(const OperationItem &item, RdbPredicates &predicates);
    static void GreaterThan(const OperationItem &item, RdbPredicates &predicates);
    static void LessThan(const OperationItem &item, RdbPredicates &predicates);
    static void GreaterThanOrEqualTo(const OperationItem &item, RdbPredicates &predicates);
    static void LessThanOrEqualTo(const OperationItem &item, RdbPredicates &predicates);
    static void And(const OperationItem &item, RdbPredicates &predicates);
    static void Or(const OperationItem &item, RdbPredicates &predicates);
    static void IsNull(const OperationItem &item, RdbPredicates &predicates);
    static void IsNotNull(const OperationItem &item, RdbPredicates &predicates);
    static void In(const OperationItem &item, RdbPredicates &predicates);
    static void NotIn(const OperationItem &item, RdbPredicates &predicates);
    static void Like(const OperationItem &item, RdbPredicates &predicates);
    static void NotLike(const OperationItem &item, RdbPredicates &predicates);
    static void OrderByAsc(const OperationItem &item, RdbPredicates &predicates);
    static void OrderByDesc(const OperationItem &item, RdbPredicates &predicates);
    static void Limit(const OperationItem &item, RdbPredicates &predicates);
    static void Offset(const OperationItem &item, RdbPredicates &predicates);
    static void BeginWrap(const OperationItem &item, RdbPredicates &predicates);
    static void EndWrap(const OperationItem &item, RdbPredicates &predicates);
    static void BeginsWith(const OperationItem &item, RdbPredicates &predicates);
    static void EndsWith(const OperationItem &item, RdbPredicates &predicates);
    static void Distinct(const OperationItem &item, RdbPredicates &predicates);
    static void GroupBy(const OperationItem &item, RdbPredicates &predicates);
    static void IndexedBy(const OperationItem &item, RdbPredicates &predicates);
    static void Contains(const OperationItem &item, RdbPredicates &predicates);
    static void NotContains(const OperationItem &item, RdbPredicates &predicates);
    static void Glob(const OperationItem &item, RdbPredicates &predicates);
    static void Between(const OperationItem &item, RdbPredicates &predicates);
    static void NotBetween(const OperationItem &item, RdbPredicates &predicates);
    static void CrossJoin(const OperationItem &item, RdbPredicates &predicates);
    static void InnerJoin(const OperationItem &item, RdbPredicates &predicates);
    static void LeftOuterJoin(const OperationItem &item, RdbPredicates &predicates);
    static void Using(const OperationItem &item, RdbPredicates &predicates);
    static void On(const OperationItem &item, RdbPredicates &predicates);
    using OperateHandler = void (*)(const OperationItem &, RdbPredicates &);
    static OHOS::NativeRdb::ValueObject ToValueObject(const DataSharePredicatesObject &predicatesObject);

public:
RDB_UTILS_PUSH_WARNING
RDB_UTILS_DISABLE_WARNING("-Wc99-designator")
    static constexpr OperateHandler HANDLERS[LAST_TYPE] = {
        [INVALID_OPERATION] = &RdbUtilsImpl::NoSupport,
        [EQUAL_TO] = &RdbUtilsImpl::EqualTo,
        [NOT_EQUAL_TO] = &RdbUtilsImpl::NotEqualTo,
        [GREATER_THAN] = &RdbUtilsImpl::GreaterThan,
        [LESS_THAN] = &RdbUtilsImpl::LessThan,
        [GREATER_THAN_OR_EQUAL_TO] = &RdbUtilsImpl::GreaterThanOrEqualTo,
        [LESS_THAN_OR_EQUAL_TO] = &RdbUtilsImpl::LessThanOrEqualTo,
        [AND] = &RdbUtilsImpl::And,
        [OR] = &RdbUtilsImpl::Or,
        [IS_NULL] = &RdbUtilsImpl::IsNull,
        [IS_NOT_NULL] = &RdbUtilsImpl::IsNotNull,
        [SQL_IN] = &RdbUtilsImpl::In,
        [NOT_IN] = &RdbUtilsImpl::NotIn,
        [LIKE] = &RdbUtilsImpl::Like,
        [UNLIKE] = &RdbUtilsImpl::NoSupport,
        [ORDER_BY_ASC] = &RdbUtilsImpl::OrderByAsc,
        [ORDER_BY_DESC] = &RdbUtilsImpl::OrderByDesc,
        [LIMIT] = &RdbUtilsImpl::Limit,
        [OFFSET] = &RdbUtilsImpl::Offset,
        [BEGIN_WARP] = &RdbUtilsImpl::BeginWrap,
        [END_WARP] = &RdbUtilsImpl::EndWrap,
        [BEGIN_WITH] = &RdbUtilsImpl::BeginsWith,
        [END_WITH] = &RdbUtilsImpl::EndsWith,
        [IN_KEY] = &RdbUtilsImpl::NoSupport,
        [DISTINCT] = &RdbUtilsImpl::Distinct,
        [GROUP_BY] = &RdbUtilsImpl::GroupBy,
        [INDEXED_BY] = &RdbUtilsImpl::IndexedBy,
        [CONTAINS] = &RdbUtilsImpl::Contains,
        [GLOB] = &RdbUtilsImpl::Glob,
        [BETWEEN] = &RdbUtilsImpl::Between,
        [NOTBETWEEN] = &RdbUtilsImpl::NotBetween,
        [KEY_PREFIX] = &RdbUtilsImpl::NoSupport,
        [CROSSJOIN] = &RdbUtilsImpl::CrossJoin,
        [INNERJOIN] = &RdbUtilsImpl::InnerJoin,
        [LEFTOUTERJOIN] = &RdbUtilsImpl::LeftOuterJoin,
        [USING] = &RdbUtilsImpl::Using,
        [ON] = &RdbUtilsImpl::On,
    };
RDB_UTILS_POP_WARNING
};

ValuesBucket RdbUtils::ToValuesBucket(DataShareValuesBucket valuesBucket)
{
    std::map<std::string, ValueObject> valuesMap;
    for (auto &[key, dsValue] : valuesBucket.valuesMap) {
        ValueObject::Type value;
        RawDataParser::Convert(std::move(dsValue), value);
        valuesMap.insert(std::pair<std::string, ValueObject>(key, std::move(value)));
    }
    return ValuesBucket(valuesMap);
}

RdbPredicates RdbUtils::ToPredicates(const DataShareAbsPredicates &predicates, const std::string &table)
{
    RdbPredicates rdbPredicates(table);
    if (predicates.GetSettingMode() == QUERY_LANGUAGE) {
        rdbPredicates.SetWhereClause(predicates.GetWhereClause());
        rdbPredicates.SetWhereArgs(predicates.GetWhereArgs());
        rdbPredicates.SetOrder(predicates.GetOrder());
    }

    const auto &operations = predicates.GetOperationList();
    for (const auto &oper : operations) {
        if (oper.operation >= 0 && oper.operation < LAST_TYPE) {
            (*RdbUtilsImpl::HANDLERS[oper.operation])(oper, rdbPredicates);
        }
    }
    return rdbPredicates;
}

OHOS::NativeRdb::ValueObject RdbUtilsImpl::ToValueObject(const DataSharePredicatesObject &predicatesObject)
{
    if (auto *val = std::get_if<int>(&predicatesObject.value)) {
        return ValueObject(*val);
    }
    ValueObject::Type value;
    RawDataParser::Convert(std::move(predicatesObject.value), value);
    return value;
}

std::shared_ptr<ResultSetBridge> RdbUtils::ToResultSetBridge(std::shared_ptr<ResultSet> resultSet)
{
    if (resultSet == nullptr) {
        LOG_ERROR("resultSet is null.");
        return nullptr;
    }
    return std::make_shared<RdbResultSetBridge>(resultSet);
}

void RdbUtilsImpl::NoSupport(const OperationItem &item, RdbPredicates &query)
{
    LOG_ERROR("invalid operation:%{public}d", item.operation);
}

void RdbUtilsImpl::EqualTo(const OperationItem &item, RdbPredicates &predicates)
{
    // 2 is the number of argument item.singleParams
    if (item.singleParams.size() < 2) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.EqualTo(item.GetSingle(0), ToValueObject(item.GetSingle(1)));
}

void RdbUtilsImpl::NotEqualTo(const OperationItem &item, RdbPredicates &predicates)
{
    // 2 is the number of argument item.singleParams
    if (item.singleParams.size() < 2) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.NotEqualTo(item.GetSingle(0), ToValueObject(item.GetSingle(1)));
}

void RdbUtilsImpl::GreaterThan(const OperationItem &item, RdbPredicates &predicates)
{
    // 2 is the number of argument item.singleParams
    if (item.singleParams.size() < 2) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.GreaterThan(item.GetSingle(0), ToValueObject(item.GetSingle(1)));
}

void RdbUtilsImpl::LessThan(const OperationItem &item, RdbPredicates &predicates)
{
    // 2 is the number of argument item.singleParams
    if (item.singleParams.size() < 2) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.LessThan(item.GetSingle(0), ToValueObject(item.GetSingle(1)));
}

void RdbUtilsImpl::GreaterThanOrEqualTo(const OperationItem &item, RdbPredicates &predicates)
{
    // 2 is the number of argument item.singleParams
    if (item.singleParams.size() < 2) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.GreaterThanOrEqualTo(item.GetSingle(0), ToValueObject(item.GetSingle(1)));
}

void RdbUtilsImpl::LessThanOrEqualTo(const OperationItem &item, RdbPredicates &predicates)
{
    // 2 is the number of argument item.singleParams
    if (item.singleParams.size() < 2) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.LessThanOrEqualTo(item.GetSingle(0), ToValueObject(item.GetSingle(1)));
}

void RdbUtilsImpl::And(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.And();
}

void RdbUtilsImpl::Or(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.Or();
}

void RdbUtilsImpl::IsNull(const OperationItem &item, RdbPredicates &predicates)
{
    if (item.singleParams.size() < 1) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.IsNull(item.GetSingle(0));
}

void RdbUtilsImpl::IsNotNull(const OperationItem &item, RdbPredicates &predicates)
{
    if (item.singleParams.size() < 1) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.IsNotNull(item.GetSingle(0));
}

void RdbUtilsImpl::In(const OperationItem &item, RdbPredicates &predicates)
{
    if (item.singleParams.size() < 1 || item.multiParams.size() < 1) {
        LOG_ERROR(
            "SingleParams size is %{public}zu, MultiParams size is %{public}zu",
            item.singleParams.size(), item.multiParams.size());
        return;
    }
    predicates.In(item.GetSingle(0), MutliValue(item.multiParams[0]));
}

void RdbUtilsImpl::NotIn(const OperationItem &item, RdbPredicates &predicates)
{
    if (item.singleParams.size() < 1 || item.multiParams.size() < 1) {
        LOG_ERROR(
            "SingleParams size is %{public}zu, MultiParams size is %{public}zu",
            item.singleParams.size(), item.multiParams.size());
        return;
    }
    predicates.NotIn(item.GetSingle(0), MutliValue(item.multiParams[0]));
}

void RdbUtilsImpl::Like(const OperationItem &item, RdbPredicates &predicates)
{
    // 2 is the number of argument item.singleParams
    if (item.singleParams.size() < 2) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.Like(item.GetSingle(0), ToValueObject(item.GetSingle(1)));
}

void RdbUtilsImpl::NotLike(const OperationItem &item, RdbPredicates &predicates)
{
    // 2 is the number of argument item.singleParams
    if (item.singleParams.size() < 2) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.NotLike(item.GetSingle(0), ToValueObject(item.GetSingle(1)));
}

void RdbUtilsImpl::OrderByAsc(const OperationItem &item, RdbPredicates &predicates)
{
    if (item.singleParams.size() < 1) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.OrderByAsc(item.GetSingle(0));
}

void RdbUtilsImpl::OrderByDesc(const OperationItem &item, RdbPredicates &predicates)
{
    if (item.singleParams.size() < 1) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.OrderByDesc(item.GetSingle(0));
}

void RdbUtilsImpl::Limit(const OperationItem &item, RdbPredicates &predicates)
{
    // 2 is the number of argument item.singleParams
    if (item.singleParams.size() < 2) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.Limit(item.GetSingle(0));
    predicates.Offset(item.GetSingle(1));
}

void RdbUtilsImpl::Offset(const OperationItem &item, RdbPredicates &predicates)
{
    if (item.singleParams.size() < 1) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.Offset(item.GetSingle(0));
}

void RdbUtilsImpl::BeginWrap(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.BeginWrap();
}

void RdbUtilsImpl::EndWrap(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.EndWrap();
}

void RdbUtilsImpl::BeginsWith(const OperationItem &item, RdbPredicates &predicates)
{
    // 2 is the number of argument item.singleParams
    if (item.singleParams.size() < 2) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.BeginsWith(item.GetSingle(0), ToValueObject(item.GetSingle(1)));
}

void RdbUtilsImpl::EndsWith(const OperationItem &item, RdbPredicates &predicates)
{
    // 2 is the number of argument item.singleParams
    if (item.singleParams.size() < 2) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.EndsWith(item.GetSingle(0), ToValueObject(item.GetSingle(1)));
}

void RdbUtilsImpl::Distinct(const OperationItem &item, RdbPredicates &predicates)
{
    predicates.Distinct();
}

void RdbUtilsImpl::GroupBy(const OperationItem &item, RdbPredicates &predicates)
{
    if (item.multiParams.size() < 1) {
        LOG_ERROR("MultiParams is missing elements, size is %{public}zu", item.multiParams.size());
        return;
    }
    predicates.GroupBy(MutliValue(item.multiParams[0]));
}

void RdbUtilsImpl::IndexedBy(const OperationItem &item, RdbPredicates &predicates)
{
    if (item.singleParams.size() < 1) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.IndexedBy(item.GetSingle(0));
}

void RdbUtilsImpl::Contains(const OperationItem &item, RdbPredicates &predicates)
{
    // 2 is the number of argument item.singleParams
    if (item.singleParams.size() < 2) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.Contains(item.GetSingle(0), ToValueObject(item.GetSingle(1)));
}

void RdbUtilsImpl::NotContains(const OperationItem &item, RdbPredicates &predicates)
{
    // 2 is the number of argument item.singleParams
    if (item.singleParams.size() < 2) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.NotContains(item.GetSingle(0), ToValueObject(item.GetSingle(1)));
}

void RdbUtilsImpl::Glob(const OperationItem &item, RdbPredicates &predicates)
{
    // 2 is the number of argument item.singleParams
    if (item.singleParams.size() < 2) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.Glob(item.GetSingle(0), ToValueObject(item.GetSingle(1)));
}

void RdbUtilsImpl::Between(const OperationItem &item, RdbPredicates &predicates)
{
    // 3 is the number of argument item.singleParams
    if (item.singleParams.size() < 3) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    // singleParams[2] is another param
    predicates.Between(item.GetSingle(0), ToValueObject(item.GetSingle(1)), ToValueObject(item.GetSingle(2)));
}

void RdbUtilsImpl::NotBetween(const OperationItem &item, RdbPredicates &predicates)
{
    // 3 is the number of argument item.singleParams
    if (item.singleParams.size() < 3) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    // singleParams[2] is another param
    predicates.NotBetween(item.GetSingle(0), ToValueObject(item.GetSingle(1)), ToValueObject(item.GetSingle(2)));
}

void RdbUtilsImpl::CrossJoin(const OperationItem &item, RdbPredicates &predicates)
{
    if (item.singleParams.size() < 1) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.CrossJoin(item.GetSingle(0));
}

void RdbUtilsImpl::InnerJoin(const OperationItem &item, RdbPredicates &predicates)
{
    if (item.singleParams.size() < 1) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.InnerJoin(item.GetSingle(0));
}

void RdbUtilsImpl::LeftOuterJoin(const OperationItem &item, RdbPredicates &predicates)
{
    if (item.singleParams.size() < 1) {
        LOG_ERROR("SingleParams is missing elements, size is %{public}zu", item.singleParams.size());
        return;
    }
    predicates.LeftOuterJoin(item.GetSingle(0));
}

void RdbUtilsImpl::Using(const OperationItem &item, RdbPredicates &predicates)
{
    if (item.multiParams.size() < 1) {
        LOG_ERROR("MultiParams is missing elements, size is %{public}zu", item.multiParams.size());
        return;
    }
    predicates.Using(MutliValue(item.multiParams[0]));
}

void RdbUtilsImpl::On(const OperationItem &item, RdbPredicates &predicates)
{
    if (item.multiParams.size() < 1) {
        LOG_ERROR("MultiParams is missing elements, size is %{public}zu", item.multiParams.size());
        return;
    }
    predicates.On(MutliValue(item.multiParams[0]));
}

RdbUtils::RdbUtils()
{
}

RdbUtils::~RdbUtils()
{
}
