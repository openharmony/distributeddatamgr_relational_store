/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect, Assert } from 'deccjsunit/index';
import dataRdb from '@ohos.data.rdb';
import featureAbility from '@ohos.ability.featureAbility';
import deviceInfo from '@ohos.deviceInfo';

const TAG = "[RDB_PREDICATES_PERF]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
+ "name TEXT, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const dbName = "predicatesperf.db"
const STORE_CONFIG = {
    name: dbName,
}
let context = featureAbility.getContext();
var rdbStore = undefined;

const base_count = 2000 // loop times
const base_line_tablet = 500 // callback tablet base line
const base_line_phone = 1000 // callback phone base line
let baseLineCallback

describe('predicatesPerf', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        if (deviceInfo.deviceType == "tablet") {
            baseLineCallback = base_line_tablet
        } else {
            baseLineCallback = base_line_phone
        }
    })
    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
    })
    afterEach(async function () {
        console.info(TAG + 'afterEach')
    })
    afterAll(async function () {
        console.info(TAG + 'afterAll')
    })

    console.log(TAG + "*************Unit Test Begin*************");

    it('SUB_DDM_PERF_RDB_Predicates_inDevices_001', 0, async function (done) {
        let deviceArray = new Array();
        deviceArray.push("123")
        let startTime = new Date().getTime()
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.inDevices(deviceArray);
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count
        console.info(TAG + " the Predicates_inDevices average time is: " + averageTime + " μs")
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_inAllDevices_001', 0, async function (done) {
        let startTime = new Date().getTime()
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.inAllDevices();
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count
        console.info(TAG + " the Predicates_inAllDevices average time is: " + averageTime + " μs")
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_equalTo_001', 0, async function (done) {
        let startTime = new Date().getTime()
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.equalTo("name", "lisi");
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count
        console.info(TAG + " the Predicates_equalTo average time is: " + averageTime + " μs")
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_notEqualTo_001', 0, async function (done) {
        let startTime = new Date().getTime()
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.notEqualTo("name", "lisi");
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count
        console.info(TAG + " the Predicates_notEqualTo average time is: " + averageTime + " μs")
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_beginWrap_001', 0, async function (done) {
        let startTime = new Date().getTime();
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.beginWrap();
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count;
        console.info(TAG + " the Predicates_beginWrap average time is: " + averageTime + " μs");
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_endWrap_001', 0, async function (done) {
        let startTime = new Date().getTime();
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.equalTo("name", "lisi");
                predicates.endWrap();
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count;
        console.info(TAG + " the Predicates_endWrap average time is: " + averageTime + " μs");
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_or_001', 0, async function (done) {
        let startTime = new Date().getTime();
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.equalTo("name", "lisi");
                predicates.or();
                predicates.equalTo("age", 18);
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count;
        console.info(TAG + " the Predicates_or average time is: " + averageTime + " μs");
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_and_001', 0, async function (done) {
        let startTime = new Date().getTime();
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.equalTo("name", "lisi");
                predicates.and();
                predicates.equalTo("name", "zs");
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count;
        console.info(TAG + " the Predicates_and average time is: " + averageTime + " μs");
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_contains_001', 0, async function (done) {
        let startTime = new Date().getTime();
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.contains("name", "lisi");
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count;
        console.info(TAG + " the Predicates_contains average time is: " + averageTime + " μs");
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_beginsWith_001', 0, async function (done) {
        let startTime = new Date().getTime();
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.beginsWith("name", "lisi");
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count;
        console.info(TAG + " the Predicates_beginsWith average time is: " + averageTime + " μs");
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_endWith_001', 0, async function (done) {
        let startTime = new Date().getTime();
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.endsWith("name", "lisi");
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count;
        console.info(TAG + " the Predicates_endWith average time is: " + averageTime + " μs");
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_isNull_001', 0, async function (done) {
        let startTime = new Date().getTime();
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.isNull("name");
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count;
        console.info(TAG + " the Predicates_isNull average time is: " + averageTime + " μs");
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_isNotNull_001', 0, async function (done) {
        let startTime = new Date().getTime();
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.isNotNull("name");
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count;
        console.info(TAG + " the Predicates_isNotNull average time is: " + averageTime + " μs");
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_like_001', 0, async function (done) {
        let startTime = new Date().getTime();
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.like("name", "li");
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count;
        console.info(TAG + " the Predicates_like average time is: " + averageTime + " μs");
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    // glob ???
    it('SUB_DDM_PERF_RDB_Predicates_glob_001', 0, async function (done) {
        let startTime = new Date().getTime();
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.glob("name", "li");
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count;
        console.info(TAG + " the Predicates_glob average time is: " + averageTime + " μs");
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_between_001', 0, async function (done) {
        let startTime = new Date().getTime();
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.between("age", 1, 100);
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count;
        console.info(TAG + " the Predicates_between average time is: " + averageTime + " μs");
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_notBetween_001', 0, async function (done) {
        let startTime = new Date().getTime();
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.notBetween("age", 1, 100);
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count;
        console.info(TAG + " the Predicates_notBetween average time is: " + averageTime + " μs");
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_greaterThan_001', 0, async function (done) {
        let startTime = new Date().getTime();
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.greaterThan("age", 1);
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count;
        console.info(TAG + " the Predicates_greaterThan average time is: " + averageTime + " μs");
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_lessThan_001', 0, async function (done) {
        let startTime = new Date().getTime();
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.lessThan("age", 1000);
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count;
        console.info(TAG + " the Predicates_lessThan average time is: " + averageTime + " μs");
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_greaterThanOrEqualTo_001', 0, async function (done) {
        let startTime = new Date().getTime();
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.greaterThanOrEqualTo("age", 1000);
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count;
        console.info(TAG + " the Predicates_greaterThanOrEqualTo average time is: " + averageTime + " μs");
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_lessThanOrEqualTo_001', 0, async function (done) {
        let startTime = new Date().getTime();
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.lessThanOrEqualTo("age", 1000);
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count;
        console.info(TAG + " the Predicates_lessThanOrEqualTo average time is: " + averageTime + " μs");
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_orderByAsc_001', 0, async function (done) {
        let startTime = new Date().getTime()
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.orderByAsc("name");
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count
        console.info(TAG + " the Predicates_orderByAsc average time is: " + averageTime + " μs")
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_orderByDesc_001', 0, async function (done) {
        let startTime = new Date().getTime()
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.orderByDesc("name");
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count
        console.info(TAG + " the Predicates_orderByDesc average time is: " + averageTime + " μs")
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_distinct_001', 0, async function (done) {
        let startTime = new Date().getTime()
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.distinct();
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count
        console.info(TAG + " the Predicates_distinct average time is: " + averageTime + " μs")
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_limitAs_001', 0, async function (done) {
        let startTime = new Date().getTime()
        for (let i = 0; i < base_count; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            predicates.limitAs(6);
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count
        console.info(TAG + " the Predicates_limitAs average time is: " + averageTime + " μs")
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_offsetAs_001', 0, async function (done) {
        let startTime = new Date().getTime()
        for (let i = 0; i < base_count; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            predicates.offsetAs(6);
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count
        console.info(TAG + " the Predicates_offsetAs average time is: " + averageTime + " μs")
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_groupBy_001', 0, async function (done) {
        let nameArr = new Array();
        nameArr.push("id");
        nameArr.push("name");
        let startTime = new Date().getTime()
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.groupBy(nameArr);
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count
        console.info(TAG + " the Predicates_groupBy average time is: " + averageTime + " μs")
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_indexedBy_001', 0, async function (done) {
        let startTime = new Date().getTime()
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.indexedBy("name");
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count
        console.info(TAG + " the Predicates_indexedBy average time is: " + averageTime + " μs")
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_in_001', 0, async function (done) {
        let nameArr = new Array();
        nameArr.push("id");
        nameArr.push("name");
        let startTime = new Date().getTime()
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.in("name", nameArr);
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count
        console.info(TAG + " the Predicates_in average time is: " + averageTime + " μs")
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    it('SUB_DDM_PERF_RDB_Predicates_notIn(_001', 0, async function (done) {
        let nameArr = new Array();
        nameArr.push("zhangsan");
        nameArr.push("lisi");
        let startTime = new Date().getTime()
        for (let i = 0; i < 200; i++) {
            let predicates = new dataRdb.RdbPredicates("test");
            for (let j = 0; j < 10; j++) {
                predicates.notIn("name", nameArr);
            }
        }
        let endTime = new Date().getTime();
        let averageTime = ((endTime - startTime) * 1000) / base_count
        console.info(TAG + " the Predicates_notIn( average time is: " + averageTime + " μs")
        expect(averageTime < baseLineCallback).assertTrue()
        done()
    })

    console.info(TAG + "*************Unit Test End*************")
})