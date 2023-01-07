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
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " + "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const STORE_CONFIG = {
    name: "RDBPromiseTest.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
var context = ability_featureAbility.getContext()

describe('rdbStorePromiseTest', function () {
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
     * @tc.name rdb  base use
     * @tc.number testRdbStorePromiseTest0001
     * @tc.desc rdb  base use
     */
    it('testRdbStorePromiseTest0001', 0, async function (done) {
        console.log(TAG + "************* testRdbStorePromiseTest0001 start *************");
        try {
            data_relationalStore.getRdbStore(context, STORE_CONFIG).then(async (rdbStore) => {
                console.log("Get RdbStore successfully.")
                await rdbStore.executeSql(CREATE_TABLE_TEST, null)
                const valueBucket = {
                    "name": "zhangsan",
                    "age": 18,
                    "salary": 100.5,
                    "blobType": new Uint8Array([1, 2, 3]),
                }             
                await rdbStore.insert("test", valueBucket)
                let predicates = new data_relationalStore.RdbPredicates("test")
                console.log("Create RdbPredicates OK")
                predicates.equalTo("name", "zhangsan")
                rdbStore.query(predicates, []).then((resultSet) => {
                    expect(1).assertEqual(resultSet.rowCount)
                    expect(true).assertEqual(resultSet.goToFirstRow())
                    const id = resultSet.getLong(resultSet.getColumnIndex("id"))
                    const name = resultSet.getString(resultSet.getColumnIndex("name"))
                    const age = resultSet.getLong(resultSet.getColumnIndex("age"))
                    const salary = resultSet.getDouble(resultSet.getColumnIndex("salary"))
                    const blobType = resultSet.getBlob(resultSet.getColumnIndex("blobType"))
                    console.log(TAG + "id=" + id + ", name=" + name + ", age=" + age + ", salary=" + salary + ", blobType=" + blobType);
                    expect(1).assertEqual(id);
                    expect("zhangsan").assertEqual(name);
                    expect(18).assertEqual(age);
                    expect(100.5).assertEqual(salary);
                    expect(1).assertEqual(blobType[0]);
                    expect(2).assertEqual(blobType[1]);
                    expect(3).assertEqual(blobType[2]);
                    expect(false).assertEqual(resultSet.goToNextRow())
                    rdbStore.delete(predicates).then((rows) => {
                        console.log("Delete rows: " + rows)
                        expect(1).assertEqual(rows)
                        data_relationalStore.deleteRdbStore(context, "RDBPromiseTest.db").then(() => {
                            console.log("Delete RdbStore successfully.")
                            done()
                            console.log(TAG + "************* testRdbStorePromiseTest0001 end *************");
                        })
                    })
                })
            })
        } catch(err) {
            console.info("catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect(null).assertFail()
            done()
            console.log(TAG + "************* testRdbStorePromiseTest0001 end *************");
        }
    })
    
    /**
     * @tc.name rdb getRdbStore err params
     * @tc.number testRdbStorePromiseTest0002
     * @tc.desc rdb getRdbStore err params
     */
    it('testRdbStorePromiseTest0002', 0, async function (done) {
        console.log(TAG + "************* testRdbStorePromiseTest0002 start *************")
        try {
            data_relationalStore.getRdbStore(context, {dbname: "RDBCallbackTest.db"}).then((rdbStore) => {
                console.log("Get RdbStore successfully.")
                expect(false).assertTrue()
            }).catch((err) => {
                console.info("Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.info("catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect("401").assertEqual(err.code)
            done()
        }
        done()
        console.log(TAG + "************* testRdbStorePromiseTest0002 end *************")
    })
    
    /**
     * @tc.name rdb getRdbStore ok params
     * @tc.number testRdbStorePromiseTest0003
     * @tc.desc rdb getRdbStore ok params
     */
    it('testRdbStorePromiseTest0003', 0, async function (done) {
        console.log(TAG + "************* testRdbStorePromiseTest0003 start *************");
        try {
            data_relationalStore.getRdbStore(context, STORE_CONFIG).then((rdbStore) => {
                console.log("Get RdbStore successfully.")
                done()
            }).catch((err) => {
                console.info("Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.info("catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect(false).assertTrue()
        }
        done()
        console.log(TAG + "************* testRdbStorePromiseTest0003 end *************")
    })

    /**
     * @tc.name rdb deleteRdbStore err params
     * @tc.number testRdbStorePromiseTest0004
     * @tc.desc rdb deleteRdbStore err params
     */
    it('testRdbStorePromiseTest0004', 0, async function (done) {
        console.log(TAG + "************* testRdbStorePromiseTest0004 start *************")
        let rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG)
        try {
            data_relationalStore.deleteRdbStore(context, 123454345).then((rdbStore) => {
                console.log("Delete RdbStore successfully.")
                expect(false).assertTrue()
            }).catch((err) => {
                console.info("Delete RdbStore failed, err: code=" + err.code + " message=" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.info("catch err: Delete RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect("401").assertEqual(err.code)
            done()
        }
        done()
        console.log(TAG + "************* testRdbStorePromiseTest0004 end *************")
    })
    
    /**
     * @tc.name rdb deleteRdbStore OK params
     * @tc.number testRdbStorePromiseTest0004
     * @tc.desc rdb deleteRdbStore OK params
     */
    it('testRdbStorePromiseTest0005', 0, async function (done) {
        console.log(TAG + "************* testRdbStorePromiseTest0005 start *************");
        let rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG)
        try {
            data_relationalStore.deleteRdbStore(context, "RDBCallbackTest.db").then((err) => {
                console.log("Delete RdbStore successfully.")
                done()
            }).catch((err) => {
                console.info("Delete RdbStore failed, err: code=" + err.code + " message=" + err.message)
                expect(false).assertTrue()
            })
        } catch(err) {
            console.info("catch err: Delete RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect(false).assertTrue()
        }
        done()
        console.log(TAG + "************* testRdbStorePromiseTest0005 end *************")
    })

    console.log(TAG + "*************Unit Test End*************");
})