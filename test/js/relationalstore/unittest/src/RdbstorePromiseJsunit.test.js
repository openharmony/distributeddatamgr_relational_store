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

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" +
                          "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                          "name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)";

const STORE_CONFIG = {
    name: "RDBPromiseTest.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
let context = ability_featureAbility.getContext()

describe('rdbStorePromiseTest', function () {
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

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.number testRdbStorePromiseTest0001
     * @tc.name Normal test case of using database
     * @tc.desc 1.Configure name and securityLevel
     *          2.Execute getRdbStore
     *          3.Create Table
     *          4.Insert data
     *          5.Query data
     *          6.Execute deleteRdbStore
     */
    it('testRdbStorePromiseTest0001', 0, async function (done) {
        console.info(TAG, "************* testRdbStorePromiseTest0001 start *************");
        try {
            data_relationalStore.getRdbStore(context, STORE_CONFIG).then(async (rdbStore) => {
                console.info(TAG, "Get RdbStore successfully.")
                await rdbStore.executeSql(CREATE_TABLE_TEST, null)
                const valueBucket = {
                    "name": "zhangsan",
                    "age": 18,
                    "salary": 100.5,
                    "blobType": new Uint8Array([1, 2, 3]),
                }
                await rdbStore.insert("test", valueBucket)
                let predicates = new data_relationalStore.RdbPredicates("test")
                predicates.equalTo("name", "zhangsan")
                rdbStore.query(predicates, []).then((resultSet) => {
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
                    resultSet.close();
                    rdbStore.delete(predicates).then((rows) => {
                        console.info(TAG, "Delete rows: " + rows)
                        expect(1).assertEqual(rows)
                        data_relationalStore.deleteRdbStore(context, "RDBPromiseTest.db").then(() => {
                            console.info(TAG, "Delete RdbStore successfully.")
                            done()
                            console.info(TAG, "************* testRdbStorePromiseTest0001 end *************");
                        })
                    })
                })
            })
        } catch(err) {
            console.error(TAG, "catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect(null).assertFail()
            done()
            console.info(TAG, "************* testRdbStorePromiseTest0001 end *************");
        }
    })

    /**
     * @tc.number testRdbStorePromiseTest0002
     * @tc.name Abnormal test case of getRdbStore, just configure database name
     * @tc.desc 1.Configure database name
     *          2.Execute getRdbStore
     */
    it('testRdbStorePromiseTest0002', 0, async function (done) {
        console.info(TAG, "************* testRdbStorePromiseTest0002 start *************")
        try {
            data_relationalStore.getRdbStore(context, {dbname: "RDBCallbackTest.db"}).then((rdbStore) => {
                console.info(TAG, "Get RdbStore successfully.")
                expect(false).assertTrue()
            }).catch((err) => {
                console.error(TAG, "Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.error(TAG, "catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect("401").assertEqual(err.code)
            done()
        }
        done()
        console.info(TAG, "************* testRdbStorePromiseTest0002 end *************")
    })

    /**
     * @tc.number testRdbStorePromiseTest0003
     * @tc.name Normal test case of getRdbStore, Configure database name and securityLevel
     * @tc.desc 1.Configure database name and securityLevel
     *          2.Execute getRdbStore
     */
    it('testRdbStorePromiseTest0003', 0, async function (done) {
        console.info(TAG, "************* testRdbStorePromiseTest0003 start *************");
        try {
            data_relationalStore.getRdbStore(context, STORE_CONFIG).then((rdbStore) => {
                console.info(TAG, "Get RdbStore successfully.")
                rdbStore = null
                done()
            }).catch((err) => {
                console.error(TAG, "Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.error(TAG, "catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect(false).assertTrue()
        }
        done()
        console.info(TAG, "************* testRdbStorePromiseTest0003 end *************")
    })

    /**
     * @tc.number testRdbStorePromiseTest0004
     * @tc.name Abnormal test case of deleteRdbStore, if database name is number
     * @tc.desc 1.Execute getRdbStore
     *          2.Configure database name as number
     *          3.Execute deleteRdbStore
     */
    it('testRdbStorePromiseTest0004', 0, async function (done) {
        console.info(TAG, "************* testRdbStorePromiseTest0004 start *************")
        let rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG)
        try {
            data_relationalStore.deleteRdbStore(context, 123454345).then((rdbStore) => {
                console.info(TAG, "Delete RdbStore successfully.")
                rdbStore = null
                expect(false).assertTrue()
            }).catch((err) => {
                console.error(TAG, "Delete RdbStore failed, err: code=" + err.code + " message=" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.error(TAG, "catch err: Delete RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect("401").assertEqual(err.code)
            done()
        }
        done()
        console.info(TAG, "************* testRdbStorePromiseTest0004 end *************")
    })

    /**
     * @tc.number testRdbStorePromiseTest0005
     * @tc.name Normal test case of deleteRdbStore, if param is database name
     * @tc.desc 1.Execute getRdbStore
     *          2.Configure database name
     *          3.Execute deleteRdbStore
     */
    it('testRdbStorePromiseTest0005', 0, async function (done) {
        console.info(TAG, "************* testRdbStorePromiseTest0005 start *************");
        let rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG)
        try {
            data_relationalStore.deleteRdbStore(context, "RDBCallbackTest.db").then((err) => {
                console.info(TAG, "Delete RdbStore successfully.")
                done()
            }).catch((err) => {
                console.error(TAG, "Delete RdbStore failed, err: code=" + err.code + " message=" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.error(TAG, "catch err: Delete RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect(false).assertTrue()
        }
        done()
        console.info(TAG, "************* testRdbStorePromiseTest0005 end *************")
    })

    /**
     * @tc.number testRdbStorePromiseTest0006
     * @tc.name Abnormal test case of getRdbStore, if configure dataGroupId in FA mode
     * @tc.desc 1.Configure dataGroupId in FA mode
     *          2.Execute getRdbStore
     */
    it('testRdbStorePromiseTest0006', 0, async function (done) {
        console.info(TAG, "************* testRdbStorePromiseTest0006 start *************")
        try {
            const STORE_CONFIG = {
                name: "dataGroupId.db",
                encrypt: false,
                securityLevel: data_relationalStore.SecurityLevel.S1,
                dataGroupId: "12345678",
            }
            data_relationalStore.getRdbStore(context, STORE_CONFIG).then((rdbStore) => {
                console.info(TAG, "Get RdbStore successfully.")
                expect(false).assertTrue()
            }).catch((err) => {
                console.error(TAG, "Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
                expect(false).assertTrue()
            })
        } catch (err) {
            console.error(TAG, "catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect("14801001").assertEqual(err.code)
            done()
        }
        done()
        console.info(TAG, "************* testRdbStorePromiseTest0006 end *************")
    })

    /**
     * @tc.number testRdbStorePromiseTest0007
     * @tc.name Normal test case of deleteRdbStore, if param is STORE_CONFIG
     * @tc.desc 1.Execute getRdbStore
     *          2.Execute deleteRdbStore
     */
    it('testRdbStorePromiseTest0007', 0, async function (done) {
        console.info(TAG, "************* testRdbStorePromiseTest0007 start *************");
        const STORE_CONFIG = {
            name: "dataGroupId.db",
            securityLevel: data_relationalStore.SecurityLevel.S1,
        }
        await data_relationalStore.getRdbStore(context, STORE_CONFIG)
        try {
            data_relationalStore.deleteRdbStore(context, STORE_CONFIG).then((err) => {
                console.info(TAG, "Delete RdbStore successfully.")
                done()
            }).catch((err) => {
                console.error(TAG, "Delete RdbStore failed, err: code=" + err.code + " message=" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.error(TAG, "catch err: Delete RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect(false).assertTrue()
        }
        done()
        console.info(TAG, "************* testRdbStorePromiseTest0007 end *************")
    })

    console.info(TAG, "*************Unit Test End*************");
})
