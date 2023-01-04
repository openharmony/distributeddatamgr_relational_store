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
    name: "RDBCallbackTest.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
var context = ability_featureAbility.getContext()

describe('rdbStoreCallBackTest', async function () {
    beforeAll(function () {
        console.log(TAG + 'beforeAll')
    })

    beforeEach(async function () {
        console.log(TAG + 'beforeEach')
    })

    afterEach(async function () {
        console.log(TAG + 'afterEach')
    })

    afterAll(async function () {
        console.log(TAG + 'afterAll')
    })

    console.log(TAG + "*************Unit Test Begin*************");
    
    /**
     * @tc.name rdb callback test
     * @tc.number testRdbStoreCallBackTest0001
     * @tc.desc rdb callback test
     */
    it('testRdbStoreCallBackTest0001', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCallBackTest0001 start *************");
        try {
            await data_relationalStore.getRdbStore(context, STORE_CONFIG, async (err, rdbStore) => {
                if (err) {
                    console.log("Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
                    expect(false).assertTrue()
                }
                console.log("Get RdbStore successfully.")
                await rdbStore.executeSql(CREATE_TABLE_TEST, null)
                const valueBucket = {
                    "name": "zhangsan",
                    "age": 18,
                    "salary": 100.5,
                    "blobType": new Uint8Array([1, 2, 3]),
                }
                let rowId = await rdbStore.insert("test", valueBucket)
                console.log("Insert is successful, rowId = " + rowId)
                let predicates = new data_relationalStore.RdbPredicates("test")
                predicates.equalTo("name", "zhangsan")
                let resultSet = await rdbStore.query(predicates,[])
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
                let rows = await rdbStore.delete(predicates)
                expect(1).assertEqual(rows)
                data_relationalStore.deleteRdbStore(context, "RDBCallbackTest.db", (err) => {
                    if (err) {
                        console.log("Delete RdbStore is failed, err: code=" + err.code + " message=" + err.message)
                        expect(false).assertTrue()
                    }
                    console.log("Delete RdbStore successfully.")
                    done()
                    console.log(TAG + "************* testRdbStoreCallBackTest0001 end *************")
                });
            })
        } catch(e) {
            console.log("catch err: Get RdbStore failed, err: code=" + e.code + " message=" + e.message)
            expect(false).assertTrue()
            done()
            console.log(TAG + "************* testRdbStoreCallBackTest0001 end *************")
        }
    })

    /**
     * @tc.name rdb callback test getRdbStore err params
     * @tc.number testRdbStoreCallBackTest0002
     * @tc.desc rdb callback test getRdbStore err params
     */
    it('testRdbStoreCallBackTest0002', 0, function (done) {
        console.log(TAG + "************* testRdbStoreCallBackTest0002 start *************")
        try {
            data_relationalStore.getRdbStore(context, {dbname: "RDBCallbackTest.db", securityLevel: data_relationalStore.SecurityLevel.S1,}, (err, rdbStore) => {
                if (err) {
                    console.log("Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
                    expect(false).assertTrue()
                }
                console.log("Get RdbStore successfully.")
                expect(false).assertTrue()
                done()
                console.log(TAG + "************* testRdbStoreCallBackTest0002 end *************")
            })
        } catch(e) {
            console.log("catch err: Get RdbStore failed, err: code=" + e.code + " message=" + e.message)
            expect("401").assertEqual(e.code)
            done()
            console.log(TAG + "************* testRdbStoreCallBackTest0002 end *************")
        }
    })

    /**
     * @tc.name rdb callback test getRdbStore err params
     * @tc.number testRdbStoreCallBackTest0003
     * @tc.desc rdb callback test getRdbStore err params
     */
     it('testRdbStoreCallBackTest0003', 0, function (done) {
        console.log(TAG + "************* testRdbStoreCallBackTest0003 start *************")
        try {
            data_relationalStore.getRdbStore(null, {name: "RDBCallbackTest.db",securityLevel: data_relationalStore.SecurityLevel.S1}, (err, rdbStore) => {
                if (err) {
                    console.log("Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
                    expect(false).assertTrue()
                }
                console.log("Get RdbStore successfully.")
                expect(false).assertTrue()
                done()
                console.log(TAG + "************* testRdbStoreCallBackTest0003 end *************")
            })
        } catch(e) {
            console.log("catch err: Get RdbStore failed, err: code=" + e.code + " message=" + e.message)
            expect("401").assertEqual(e.code)
            done()
            console.log(TAG + "************* testRdbStoreCallBackTest0003 end *************")
        }
    })
    
    /**
     * @tc.name rdb callback test getRdbStore ok params
     * @tc.number testRdbStoreCallBackTest0004
     * @tc.desc rdb callback test getRdbStore ok params
     */
    it('testRdbStoreCallBackTest0004', 0, function (done) {
        console.log(TAG + "************* testRdbStoreCallBackTest0004 start *************")
        try {
            data_relationalStore.getRdbStore(context, STORE_CONFIG, (err, rdbStore) => {
                if (err) {
                    console.log("Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
                    expect(false).assertTrue()
                }
                console.log("Get RdbStore successfully.")
                done()
                console.log(TAG + "************* testRdbStoreCallBackTest0004 end *************")
            })
        } catch(e) {
            console.log("catch err: Get RdbStore failed, err: code=" + e.code + " message=" + e.message)
            expect(false).assertTrue()
            done()
            console.log(TAG + "************* testRdbStoreCallBackTest0004 end *************")
        }
    })

    /**
     * @tc.name rdb callback test deleteRdbStore err params
     * @tc.number testRdbStoreCallBackTest0005
     * @tc.desc rdb callback test deleteRdbStore err params
     */
    it('testRdbStoreCallBackTest0005', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCallBackTest0005 start *************");
        data_relationalStore.getRdbStore(context, STORE_CONFIG).then((rdbStore)=>{
            try {
                data_relationalStore.deleteRdbStore(context, 12345, (err) => {
                    if (err) {
                        console.log("Delete RdbStore is failed, err: code=" + err.code + " message=" + err.message)
                        expect(false).assertTrue()
                        done()
                        console.log(TAG + "************* testRdbStoreCallBackTest0005 end *************");
                    }
                    console.log("Delete RdbStore successfully.")
                    expect(false).assertTrue()
                    done()
                    console.log(TAG + "************* testRdbStoreCallBackTest0005 end *************");
                });
            } catch(e) {
                console.log("catch err: Delete RdbStore failed, err: code=" + e.code + " message=" + e.message)
                expect("401").assertEqual(e.code)
                done()
                console.log(TAG + "************* testRdbStoreCallBackTest0005 end *************");
            }
        }).catch((err2) => {
            console.info("Get RdbStore failed, err: code=" + err2.code + " message=" + err2.message)
            expect(false).assertTrue()
            done()
            console.log(TAG + "************* testRdbStoreCallBackTest0005 end *************");
        })
    })
    
    /**
     * @tc.name rdb callback test deleteRdbStore OK params
     * @tc.number testRdbStoreCallBackTest0006
     * @tc.desc rdb callback test deleteRdbStore OK params
     */
    it('testRdbStoreCallBackTest0006', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCallBackTest0006 start *************")
        data_relationalStore.getRdbStore(context, STORE_CONFIG).then((rdbStore)=>{
            try {
                data_relationalStore.deleteRdbStore(context, "RDBCallbackTest.db", (err) => {
                    if (err) {
                        console.log("Delete RdbStore is failed, err: code=" + err.code + " message=" + err.message)
                        expect(false).assertTrue()
                        done()
                        console.log(TAG + "************* testRdbStoreCallBackTest0006 end *************");
                    }
                    console.log("Delete RdbStore successfully.")
                    done()
                    console.log(TAG + "************* testRdbStoreCallBackTest0006 end *************")
                });
            } catch(err) {
                console.log("222catch err: Delete RdbStore failed, err: code=" + err.code + " message=" + err.message)
                expect(false).assertTrue()
                done()
                console.log(TAG + "************* testRdbStoreCallBackTest0006 end *************");
            }
        }).catch((err) => {
            console.info("Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect(false).assertTrue()
            done()
            console.log(TAG + "************* testRdbStoreCallBackTest0006 end *************");
        })
    })

    console.log(TAG + "*************Unit Test End*************");
})