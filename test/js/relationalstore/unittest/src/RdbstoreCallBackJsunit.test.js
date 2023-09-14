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
import data_relationalStore from '@ohos.data.relationalStore';
import ability_featureAbility from '@ohos.ability.featureAbility';

const TAG = "[RELATIONAL_STORE_CALLBACK_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" +
                          "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                          "name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)";

const STORE_CONFIG = {
    name: "RDBCallbackTest.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
let context = ability_featureAbility.getContext()

describe('rdbStoreCallBackTest', async function () {
    beforeAll(function () {
        console.info(TAG, 'beforeAll')
    })

    beforeEach(async function () {
        console.info(TAG, 'beforeEach')
    })

    afterEach(async function () {
        console.info(TAG, 'afterEach')
    })

    afterAll(async function () {
        console.info(TAG, 'afterAll')
    })

    console.info(TAG, "*************Unit Test Begin*************");

    /**
     * @tc.number testRdbStoreCallBackTest0001
     * @tc.name Normal test case of using database
     * @tc.desc 1.Configure name and securityLevel
     *          2.Execute getRdbStore
     *          3.Create Table
     *          4.Insert data
     *          5.Query data
     *          6.Execute deleteRdbStore
     */
    it('testRdbStoreCallBackTest0001', 0, async function (done) {
        console.info(TAG,  "************* testRdbStoreCallBackTest0001 start *************");
        try {
            await data_relationalStore.getRdbStore(context, STORE_CONFIG, async (err, rdbStore) => {
                if (err) {
                    console.error(TAG, "Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
                    expect(false).assertTrue()
                }
                console.info(TAG, "Get RdbStore successfully.")
                await rdbStore.executeSql(CREATE_TABLE_TEST, null)
                const valueBucket = {
                    "name": "zhangsan",
                    "age": 18,
                    "salary": 100.5,
                    "blobType": new Uint8Array([1, 2, 3]),
                }
                let rowId = await rdbStore.insert("test", valueBucket)
                let predicates = new data_relationalStore.RdbPredicates("test")
                predicates.equalTo("name", "zhangsan")
                let resultSet = await rdbStore.query(predicates, [])
                expect(1).assertEqual(resultSet.rowCount)
                expect(true).assertEqual(resultSet.goToFirstRow())
                const id = resultSet.getLong(resultSet.getColumnIndex("id"))
                const name = resultSet.getString(resultSet.getColumnIndex("name"))
                const age = resultSet.getLong(resultSet.getColumnIndex("age"))
                const salary = resultSet.getDouble(resultSet.getColumnIndex("salary"))
                const blobType = resultSet.getBlob(resultSet.getColumnIndex("blobType"))
                expect(1).assertEqual(id);
                expect("zhangsan").assertEqual(name);
                expect(18).assertEqual(age);
                expect(100.5).assertEqual(salary);
                expect(1).assertEqual(blobType[0]);
                expect(2).assertEqual(blobType[1]);
                expect(3).assertEqual(blobType[2]);
                expect(false).assertEqual(resultSet.goToNextRow())
                let rows = await rdbStore.delete(predicates)
                expect(1).assertEqual(rows)
                data_relationalStore.deleteRdbStore(context, "RDBCallbackTest.db", (err) => {
                    if (err) {
                        console.error(TAG, "Delete RdbStore is failed, err: code=" + err.code + " message=" + err.message)
                        expect(false).assertTrue()
                    }
                    done()
                    console.info(TAG,  "************* testRdbStoreCallBackTest0001 end *************")
                });
                resultSet.close()
                rdbStore = null
            })
        } catch (err) {
            console.error(TAG, "catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect(false).assertTrue()
        }
    })

    /**
     * @tc.number testRdbStoreCallBackTest0002
     * @tc.name Abnormal test case of getRdbStore, configure wrong param dbname
     * @tc.desc 1.Configure wrong param dbname
     *          2.Execute getRdbStore
     */
    it('testRdbStoreCallBackTest0002', 0, function (done) {
        console.info(TAG,  "************* testRdbStoreCallBackTest0002 start *************")
        try {
            data_relationalStore.getRdbStore(context,
                {dbname: "RDBCallbackTest.db", securityLevel: data_relationalStore.SecurityLevel.S1,},
                (err, rdbStore) => {
                    if (err) {
                        console.error(TAG, "Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
                        expect(false).assertTrue()
                    }
                    console.info(TAG, "Get RdbStore successfully.")
                    expect(false).assertTrue()
                })
        } catch (err) {
            console.error(TAG, "catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect("401").assertEqual(err.code)
            done()
            console.info(TAG,  "************* testRdbStoreCallBackTest0002 end *************")
        }
    })

    /**
     * @tc.number testRdbStoreCallBackTest0003
     * @tc.name Abnormal test case of getRdbStore, if context is null
     * @tc.desc 1.Configure context as null
     *          2.Execute getRdbStore
     */
    it('testRdbStoreCallBackTest0003', 0, function (done) {
        console.info(TAG,  "************* testRdbStoreCallBackTest0003 start *************")
        try {
            data_relationalStore.getRdbStore(null, {
                name: "RDBCallbackTest.db",
                securityLevel: data_relationalStore.SecurityLevel.S1
            }, (err, rdbStore) => {
                if (err) {
                    console.error(TAG,  "Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
                    expect(false).assertTrue()
                }
                console.info(TAG,  "Get RdbStore successfully.")
                expect(false).assertTrue()
            })
        } catch (err) {
            console.error(TAG,  "catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect("401").assertEqual(err.code)
            done()
            console.info(TAG,  "************* testRdbStoreCallBackTest0003 end *************")
        }
    })

    /**
     * @tc.number testRdbStoreCallBackTest0004
     * @tc.name Normal test case of getRdbStore
     * @tc.desc 1.Configure database name and securityLevel
     *          2.Execute getRdbStore
     */
    it('testRdbStoreCallBackTest0004', 0, function (done) {
        console.info(TAG,  "************* testRdbStoreCallBackTest0004 start *************")
        try {
            data_relationalStore.getRdbStore(context, STORE_CONFIG, (err, rdbStore) => {
                if (err) {
                    console.error(TAG, "Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
                    expect(false).assertTrue()
                }
                rdbStore = null
                done()
                console.info(TAG,  "************* testRdbStoreCallBackTest0004 end *************")
            })
        } catch (err) {
            console.error("catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect(false).assertTrue()
        }
    })

    /**
     * @tc.number testRdbStoreCallBackTest0005
     * @tc.name Abnormal test case of deleteRdbStore, if database name is number
     * @tc.desc 1.Execute getRdbStore
     *          2.Configure database name as number
     *          3.Execute deleteRdbStore
     */
    it('testRdbStoreCallBackTest0005', 0, async function (done) {
        console.info(TAG,  "************* testRdbStoreCallBackTest0005 start *************");
        data_relationalStore.getRdbStore(context, STORE_CONFIG).then((rdbStore) => {
            try {
                rdbStore = null
                data_relationalStore.deleteRdbStore(context, 12345, (err) => {
                    if (err) {
                        console.error(TAG, "Delete RdbStore is failed, err: code=" + err.code + " message=" + err.message)
                        expect(false).assertTrue()
                    }
                    console.info(TAG, "Delete RdbStore successfully.")
                    expect(false).assertTrue()
                });
            } catch (err) {
                console.info(TAG, "catch err: Delete RdbStore failed, err: code=" + err.code + " message=" + err.message)
                expect("401").assertEqual(err.code)
                done()
                console.info(TAG,  "************* testRdbStoreCallBackTest0005 end *************");
            }
        }).catch((err) => {
            console.error(TAG, "Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect(false).assertTrue()
        })
    })

    /**
     * @tc.number testRdbStoreCallBackTest0006
     * @tc.name Normal test case of deleteRdbStore
     * @tc.desc 1.Execute getRdbStore
     *          2.Configure database name
     *          3.Execute deleteRdbStore
     */
    it('testRdbStoreCallBackTest0006', 0, async function (done) {
        console.info(TAG,  "************* testRdbStoreCallBackTest0006 start *************")
        data_relationalStore.getRdbStore(context, STORE_CONFIG).then((rdbStore) => {
            try {
                rdbStore = null
                data_relationalStore.deleteRdbStore(context, "RDBCallbackTest.db", (err) => {
                    if (err) {
                        console.error(TAG, "Delete RdbStore is failed, err: code=" + err.code + " message=" + err.message)
                        expect(false).assertTrue()
                    }
                    console.info(TAG, "Delete RdbStore successfully.")
                    done()
                    console.info(TAG,  "************* testRdbStoreCallBackTest0006 end *************")
                });
            } catch (err) {
                console.error(TAG, "Delete RdbStore is failed, err: code=" + err.code + " message=" + err.message)
                expect(false).assertTrue()
            }
        }).catch((err) => {
            console.error(TAG, "Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect(false).assertTrue()
        })
    })

    console.info(TAG,  "*************Unit Test End*************");
})