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

#ifndef OHOS_RELATION_STORE_RDB_PREDICATES_IMPL_H
#define OHOS_RELATION_STORE_RDB_PREDICATES_IMPL_H

#include "ani_rdb_utils.h"

namespace OHOS {
namespace RdbTaihe {
using namespace taihe;
using namespace ohos::data::relationalStore;
using namespace OHOS;
using namespace OHOS::Rdb;
using namespace OHOS::RdbTaihe;
using ValueType = ohos::data::relationalStore::ValueType;
using ValueObject = OHOS::NativeRdb::ValueObject;

class RdbPredicatesImpl {
public:
    RdbPredicatesImpl();
    explicit RdbPredicatesImpl(const std::string &name);
    uintptr_t GetSpecificImplPtr();
    void InnerInDevices(array_view<string> devices);
    void InnerInAllDevices();
    void InnerEqualTo(string_view field, ValueType const &value);
    void InnerNotEqualTo(string_view field, ValueType const &value);
    void InnerBeginWrap();
    void InnerEndWrap();
    void InnerOr();
    void InnerAnd();
    void InnerContains(string_view field, string_view value);
    void InnerBeginsWith(string_view field, string_view value);
    void InnerEndsWith(string_view field, string_view value);
    void InnerIsNull(string_view field);
    void InnerIsNotNull(string_view field);
    void InnerLike(string_view field, string_view value);
    void InnerGlob(string_view field, string_view value);
    void InnerBetween(string_view field, ValueType const &low, ValueType const &high);
    void InnerNotBetween(string_view field, ValueType const &low, ValueType const &high);
    void InnerGreaterThan(string_view field, ValueType const &value);
    void InnerLessThan(string_view field, ValueType const &value);
    void InnerGreaterThanOrEqualTo(string_view field, ValueType const &value);
    void InnerLessThanOrEqualTo(string_view field, ValueType const &value);
    void InnerOrderByAsc(string_view field);
    void InnerOrderByDesc(string_view field);
    void InnerDistinct();
    void InnerLimitAs(int32_t value);
    void InnerOffsetAs(int32_t rowOffset);
    void InnerGroupBy(array_view<string> fields);
    void InnerIndexedBy(string_view field);
    void InnerInValues(string_view field, array_view<ValueType> value);
    void InnerNotInValues(string_view field, array_view<ValueType> value);
    void InnerNotContains(string_view field, string_view value);
    void InnerNotLike(string_view field, string_view value);
    std::shared_ptr<OHOS::NativeRdb::RdbPredicates> GetNativePtr();

private:
    std::shared_ptr<OHOS::NativeRdb::RdbPredicates> nativeRdbPredicates_;
};
}
}
#endif // OHOS_RELATION_STORE_RDB_PREDICATES_IMPL_H