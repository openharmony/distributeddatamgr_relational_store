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

const TAG = "[RDBSTORE_OTHERS_CALLBACK]";
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY AUTOINCREMENT, "
+ "name TEXT, age INTEGER, salary REAL, blobType BLOB)";

const DB_NAME = "rdbUpdateCallback.db";
const STORE_CONFIG = {
    name: DB_NAME,
}
let context = featureAbility.getContext();
var rdbStore = undefined;
const BASE_COUNT = 1000; // loop times
const SPECIAL_BASE_COUNT = 300;
const BASE_LINE_TABLE = 1800; // callback tablet base line
const BASE_LINE_PHONE = 15000; // callback phone base line
const BASE_LINE = (deviceInfo.deviceType == "tablet") ? BASE_LINE_TABLE : BASE_LINE_PHONE;

describe('rdbStoreOthersCallbackPerf', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll');
        rdbStore = await dataRdb.getRdbStore(context, STORE_CONFIG, 1);
    })
    beforeEach(async function () {
        console.info(TAG + 'beforeEach');
        await rdbStore.executeSql(CREATE_TABLE_TEST, null);
        await prepareTestData();
    })
    afterEach(async function () {
        console.info(TAG + 'afterEach');
        await rdbStore.executeSql("delete from test");
    })
    afterAll(async function () {
        console.info(TAG + 'afterAll');
        rdbStore = null;
        await dataRdb.deleteRdbStore(context, DB_NAME);
    })

    async function prepareTestData() {
        console.info(TAG + "prepare for query performance test");
        var u8 = new Uint8Array([1, 2, 3]);
        var valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket);
    }

    console.log(TAG + "*************Unit Test Begin*************");

    it('SUB_DDM_PERF_RDB_update_Callback_001', 0, async function (done) {
        let averageTime = 0;
        var uBlob = new Uint8Array([1, 2, 3])
        var updateVB = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": uBlob,
        }
        let predicates = new dataRdb.RdbPredicates("test");

        async function updateCallback(index) {
            predicates.equalTo("age", 18);
            rdbStore.update(updateVB, predicates, function (err, data) {
                if (index < SPECIAL_BASE_COUNT) {
                    updateCallback(index + 1);
                } else {
                    let endTime = new Date().getTime();
                    averageTime = ((endTime - startTime) * 1000) / SPECIAL_BASE_COUNT;
                    console.info(TAG + " the update_Callback average time is: " + averageTime + " μs");
                    expect(averageTime < BASE_LINE).assertTrue();
                    done();
                }
            })
        }

        let startTime = new Date().getTime();
        updateCallback(0);
    })

    it('SUB_DDM_PERF_RDB_delete_Callback_001', 0, async function (done) {
        let averageTime = 0;
        let predicates = new dataRdb.RdbPredicates("test");
        predicates.equalTo("age", 0);

        async function deleteCallback(index) {
            rdbStore.delete(predicates, function (err, data) {
                if (index < BASE_COUNT) {
                    deleteCallback(index + 1)
                } else {
                    let endTime = new Date().getTime();
                    averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
                    console.info(TAG + " the delete_Callback average time is: " + averageTime + " μs");
                    expect(averageTime < BASE_LINE).assertTrue();
                    done();
                }
            })
        }

        let startTime = new Date().getTime();
        deleteCallback(0);
    })

    it('SUB_DDM_PERF_RDB_querySql_Callback_001', 0, async function (done) {
        let averageTime = 0;

        async function querySqlCallback(index) {
            rdbStore.querySql("select * from test", [], function (err, data) {
                if (index < BASE_COUNT) {
                    querySqlCallback(index + 1);
                } else {
                    let endTime = new Date().getTime();
                    averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
                    console.info(TAG + " the querySql_Callback average time is: " + averageTime + " μs");
                    expect(averageTime < BASE_LINE).assertTrue();
                    done();
                }
            })
        }

        let startTime = new Date().getTime();
        querySqlCallback(0);
    })

    it('SUB_DDM_PERF_RDB_executeSql_Callback_001', 0, async function (done) {
        let averageTime = 0;

        async function executeSqlCallback(index) {
            rdbStore.executeSql("insert into test (name, age) values ('tom', 22)", function (err, data) {
                if (index < SPECIAL_BASE_COUNT) {
                    executeSqlCallback(index + 1);
                } else {
                    let endTime = new Date().getTime();
                    averageTime = ((endTime - startTime) * 1000) / SPECIAL_BASE_COUNT;
                    console.info(TAG + " the executeSql_Callback average time is: " + averageTime + " μs");
                    expect(averageTime < BASE_LINE).assertTrue();
                    done();
                }
            })
        }

        let startTime = new Date().getTime();
        executeSqlCallback(0);
    })

    it('SUB_DDM_PERF_RDB_backup_Callback_001', 0, async function (done) {
        let averageTime = 0;

        async function backupCallback(index) {
            rdbStore.backup("backup.db", function (err, data) {
                if (index < BASE_COUNT) {
                    backupCallback(index + 1);
                } else {
                    let endTime = new Date().getTime();
                    averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
                    console.info(TAG + " the backup_Callback average time is: " + averageTime + " μs");
                    expect(averageTime < BASE_LINE).assertTrue();
                    done();
                }
            })
        }

        let startTime = new Date().getTime();
        backupCallback(0);
    })

    it('SUB_DDM_PERF_RDB_restore_Callback_001', 0, async function (done) {
        let averageTime = 0;

        async function restoreCallback(index) {
            rdbStore.restore("backup.db", function (err, data) {
                if (index < BASE_COUNT) {
                    restoreCallback(index + 1);
                } else {
                    let endTime = new Date().getTime();
                    averageTime = ((endTime - startTime) * 1000) / BASE_COUNT;
                    console.info(TAG + " the restore_Callback average time is: " + averageTime + " μs");
                    expect(averageTime < BASE_LINE).assertTrue();
                    dataRdb.deleteRdbStore(context, "backup.db", function (err, data) {
                        done();
                    })
                }
            })
        }

        let startTime = new Date().getTime();
        restoreCallback(0);
    })
})
