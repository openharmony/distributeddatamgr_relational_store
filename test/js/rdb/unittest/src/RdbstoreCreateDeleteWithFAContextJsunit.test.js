/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import dataRdb from '@ohos.data.rdb';
import featureAbility from '@ohos.ability.featureAbility';

const TAG = "[RDB_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " + "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const STORE_CONFIG = {
    name: "CreateDeleteWithFAContextTest.db",
}

describe('rdbStoreCreateDeleteWithFAContextTest', function () {
    beforeAll(function () {
        console.info(TAG + 'beforeAll')
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
    /**
     * @tc.name rdb delete test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Delete_0010
     * @tc.desc rdb delete test
     */
    it('testRdbStoreCreateDeleteWithFAContextTest0001', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCreateDeleteWithFAContextTest0001 start *************");
        let context = featureAbility.getContext()
        var rdbStore = await dataRdb.getRdbStore(context, STORE_CONFIG, 1);
        rdbStore = null
        await dataRdb.deleteRdbStore(context, "CreateDeleteWithFAContextTest.db");
        done()
        console.log(TAG + "************* testRdbStoreCreateDeleteWithFAContextTest0001 end *************");
    })

    /**
     * @tc.name rdb delete test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Delete_0020
     * @tc.desc rdb delete test
     */
    it('testRdbStoreCreateDeleteWithFAContextTest0002', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCreateDeleteWithFAContextTest0002 start *************");
        let context = featureAbility.getContext()
        var rdbStore = await dataRdb.getRdbStore(context, STORE_CONFIG, 1);
        await rdbStore.executeSql(CREATE_TABLE_TEST, null);
        await rdbStore.executeSql("DELETE FROM test");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            const valueBucket = {
                "name": "lisi",
                "age": 28,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            const valueBucket = {
                "name": "lisi",
                "age": 38,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            let predicates = await new dataRdb.RdbPredicates("test")
            predicates.equalTo("name", "zhangsan")
            let deletePromise = rdbStore.delete(predicates)
            deletePromise.then(async (ret) => {
                await expect(1).assertEqual(ret)
                await console.log(TAG + "Delete done: " + ret)
            }).catch((err) => {
                expect(null).assertFail()
            })
            await deletePromise
        }
        await rdbStore.executeSql("DELETE FROM test");
        rdbStore = null
        await dataRdb.deleteRdbStore(context, "CreateDeleteWithFAContextTest.db");
        done()
        console.log(TAG + "************* testRdbStoreCreateDeleteWithFAContextTest0002 end *************");
    })

    /**
     * @tc.name rdb delete test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Delete_0030
     * @tc.desc rdb delete test
     */
    it('testRdbStoreCreateDeleteWithFAContextTest0003', 0, function (done) {
        console.log(TAG + "************* testRdbStoreCreateDeleteWithFAContextTest0003 start *************");
        let context = featureAbility.getContext()
        dataRdb.getRdbStore(context, STORE_CONFIG, 1, (err, rdbStore) => {
            if (err) {
                console.info("Get RdbStore failed, err: " + err)
                return
            }
            console.log("Get RdbStore successfully.")
            rdbStore.executeSql(CREATE_TABLE_TEST, null, (err) => {
                if (err) {
                    console.info("executeSql CREATE_TABLE_TEST failed, err: " + err)
                    return
                }
                console.log("executeSql CREATE_TABLE_TEST successfully.")
                const valueBucket = {
                    "name": "zhangsan",
                    "age": 18,
                    "salary": 100.5,
                    "blobType": new Uint8Array([1, 2, 3]),
                }
                rdbStore.insert("test", valueBucket, (err, rowId) => {
                    if (err) {
                        console.log("Insert is failed");
                        return;
                    }
                    console.log("Insert is successful, rowId = " + rowId)
                    let predicates = new dataRdb.RdbPredicates("test")
                    predicates.equalTo("name", "zhangsan")
                    rdbStore.delete(predicates, (err, rows) => {
                        if (err) {
                            console.info("Delete failed, err: " + err)
                            expect(null).assertFail()
                        }
                        console.log("Delete rows: " + rows)
                        expect(1).assertEqual(rows)
                        dataRdb.deleteRdbStore(context, "CreateDeleteWithFAContextTest.db", (err) => {
                            if (err) {
                                console.info("Delete RdbStore failed, err: " + err)
                                return
                            }
                            console.log("Delete RdbStore successfully.")
                            done()
                            console.log(TAG + "************* testRdbStoreCreateDeleteWithFAContextTest0003 end *************");
                        });
                    })
                })
            });
        })
    })

    /**
     * @tc.name rdb delete test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Delete_0040
     * @tc.desc rdb delete test
     */
    it('testRdbStoreCreateDeleteWithFAContextTest0004', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCreateDeleteWithFAContextTest0004 start *************");
        let context = featureAbility.getContext()
        dataRdb.getRdbStore(context, STORE_CONFIG, 1).then((rdbStore) => {
            console.log("Get RdbStore successfully.")
            rdbStore.executeSql(CREATE_TABLE_TEST, null).then(() => {
                console.log("executeSql CREATE_TABLE_TEST successfully.")
                const valueBucket = {
                    "name": "zhangsan",
                    "age": 18,
                    "salary": 100.5,
                    "blobType": new Uint8Array([1, 2, 3]),
                }
                rdbStore.insert("test", valueBucket).then((rowId) => {
                    console.log("Insert is successful, rowId = " + rowId)
                    let predicates = new dataRdb.RdbPredicates("test")
                    predicates.equalTo("name", "zhangsan")
                    rdbStore.delete(predicates).then((rows) => {
                        console.log("Delete rows: " + rows)
                        expect(1).assertEqual(rows)
                        dataRdb.deleteRdbStore(context, "CreateDeleteWithFAContextTest.db").then(() => {
                            console.log("Delete RdbStore successfully.")
                            done()
                            console.log(TAG + "************* testRdbStoreCreateDeleteWithFAContextTest0004 end *************");
                        }).catch((err) => {
                            console.info("Delete RdbStore failed, err: " + err)
                        })
                    }).catch((err) => {
                        console.info("Delete failed, err: " + err)
                        expect(null).assertFail()
                    })
                }).catch((err) => {
                    console.log("Insert is failed");
                })
            }).catch((err) => {
                console.info("executeSql CREATE_TABLE_TEST failed, err: " + err)
            })
        }).catch((err) => {
            console.info("Get RdbStore failed, err: " + err)
        })
    })

    console.log(TAG + "*************Unit Test End*************");
})