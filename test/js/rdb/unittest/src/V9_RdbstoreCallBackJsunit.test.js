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
    name: "V9_RDBCallbackTest.db",
    securityLevel: dataRdb.SecurityLevel.S1,
}

describe('V9_rdbStoreCallBackTest', async function () {
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
     * @tc.number testV9RdbStoreCallBackTest0001
     * @tc.desc rdb callback test
     */
    it('testV9RdbStoreCallBackTest0001', 0, async function (done) {
        console.log(TAG + "************* testV9RdbStoreCallBackTest0001 start *************");
        let context = featureAbility.getContext()
        try{
            await dataRdb.getRdbStoreV9(context, STORE_CONFIG, 1, async (err, rdbStoreV9) => {
                if (err) {
                    console.log("Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
                    expect(false).assertTrue()
                }
                console.log("Get RdbStore successfully.")
                await rdbStoreV9.executeSql(CREATE_TABLE_TEST, null)
                const valueBucket = {
                    "name": "zhangsan",
                    "age": 18,
                    "salary": 100.5,
                    "blobType": new Uint8Array([1, 2, 3]),
                }
                let rowId = await rdbStoreV9.insert("test", valueBucket)
                console.log("Insert is successful, rowId = " + rowId)
                let predicates = new dataRdb.RdbPredicatesV9("test")
                predicates.equalTo("name", "zhangsan")
                let resultSetV9 = await rdbStoreV9.query(predicates,[])
                expect(1).assertEqual(resultSetV9.rowCount)
                expect(true).assertEqual(resultSetV9.goToFirstRow())
                const id = resultSetV9.getLong(resultSetV9.getColumnIndex("id"))
                const name = resultSetV9.getString(resultSetV9.getColumnIndex("name"))
                const age = resultSetV9.getLong(resultSetV9.getColumnIndex("age"))
                const salary = resultSetV9.getDouble(resultSetV9.getColumnIndex("salary"))
                const blobType = resultSetV9.getBlob(resultSetV9.getColumnIndex("blobType"))
                console.log(TAG + "id=" + id + ", name=" + name + ", age=" + age + ", salary=" + salary + ", blobType=" + blobType);
                expect(1).assertEqual(id);
                expect("zhangsan").assertEqual(name);
                expect(18).assertEqual(age);
                expect(100.5).assertEqual(salary);
                expect(1).assertEqual(blobType[0]);
                expect(2).assertEqual(blobType[1]);
                expect(3).assertEqual(blobType[2]);
                expect(false).assertEqual(resultSetV9.goToNextRow())
                let rows = await rdbStoreV9.delete(predicates)
                expect(1).assertEqual(rows)
                dataRdb.deleteRdbStoreV9(context, "V9_RDBCallbackTest.db", (err) => {
                    if (err) {
                        console.log("Delete RdbStore is failed, err: code=" + err.code + " message=" + err.message)
                        expect(false).assertTrue()
                    }
                    console.log("Delete RdbStore successfully.")
                    done()
                });
            })
        } catch(err) {
            console.log("catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect(false).assertTrue()
        }
        done()
        console.log(TAG + "************* testV9RdbStoreCallBackTest0001 end *************")
    })

    /**
     * @tc.name rdb callback test getRdbStoreV9 err params
     * @tc.number testV9RdbStoreCallBackTest0002
     * @tc.desc rdb callback test getRdbStoreV9 err params
     */
    it('testV9RdbStoreCallBackTest0002', 0, function (done) {
        console.log(TAG + "************* testV9RdbStoreCallBackTest0002 start *************")
        let context = featureAbility.getContext()
        try{
            dataRdb.getRdbStoreV9(context, {dbname: "V9_RDBCallbackTest.db"}, 1, (err, rdbStoreV9) => {
                if (err) {
                    console.log("Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
                    expect(false).assertTrue()
                }
                console.log("Get RdbStore successfully.")
                expect(false).assertTrue()
            })
        } catch(err) {
            console.log("catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect("401").assertEqual(err.code)
        }
        
        done()
        console.log(TAG + "************* testV9RdbStoreCallBackTest0002 end *************")
    })

    /**
     * @tc.name rdb callback test getRdbStoreV9 err params
     * @tc.number testV9RdbStoreCallBackTest0003
     * @tc.desc rdb callback test getRdbStoreV9 err params
     */
     it('testV9RdbStoreCallBackTest0003', 0, function (done) {
        console.log(TAG + "************* testV9RdbStoreCallBackTest0003 start *************")
        let context = featureAbility.getContext()
        try{
            dataRdb.getRdbStoreV9(null, {name: "V9_RDBCallbackTest.db"}, 1, (err, rdbStoreV9) => {
                if (err) {
                    console.log("Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
                    expect(false).assertTrue()
                }
                console.log("Get RdbStore successfully.")
                expect(false).assertTrue()
            })
        } catch(err) {
            console.log("catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect("401").assertEqual(err.code)
        }
        
        done()
        console.log(TAG + "************* testV9RdbStoreCallBackTest0003 end *************")
    })
    
    /**
     * @tc.name rdb callback test getRdbStoreV9 ok params
     * @tc.number testV9RdbStoreCallBackTest0004
     * @tc.desc rdb callback test getRdbStoreV9 ok params
     */
    it('testV9RdbStoreCallBackTest0004', 0, function (done) {
        console.log(TAG + "************* testV9RdbStoreCallBackTest0004 start *************")
        let context = featureAbility.getContext()
        try{
            dataRdb.getRdbStoreV9(context, STORE_CONFIG, 1, (err, rdbStoreV9) => {
                if (err) {
                    console.log("Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
                    expect(false).assertTrue()
                }
                console.log("Get RdbStore successfully.")
                done()
            })
        } catch(err) {
            console.log("catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect(false).assertTrue()
        }
        done()
        console.log(TAG + "************* testV9RdbStoreCallBackTest0004 end *************")
    })

    /**
     * @tc.name rdb callback test deleteRdbStoreV9 err params
     * @tc.number testV9RdbStoreCallBackTest0005
     * @tc.desc rdb callback test deleteRdbStoreV9 err params
     */
    it('testV9RdbStoreCallBackTest0005', 0, async function (done) {
        console.log(TAG + "************* testV9RdbStoreCallBackTest0005 start *************");
        let context = featureAbility.getContext()
        let rdbStoreV9;
        try{
            rdbStoreV9 = await dataRdb.getRdbStoreV9(context, STORE_CONFIG, 1)
        } catch(err) {
            console.log("catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect(false).assertTrue()
        }
        try{
            dataRdb.deleteRdbStoreV9(context, 12345, (err) => {
                if (err) {
                    console.log("Delete RdbStore is failed, err: code=" + err.code + " message=" + err.message)
                    expect(false).assertTrue()
                }
                console.log("Delete RdbStore successfully.")
                expect(false).assertTrue()
            });
        } catch(err) {
            console.log("catch err: Delete RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect("401").assertEqual(err.code)
            done()
        }
        done()
        console.log(TAG + "************* testV9RdbStoreCallBackTest0005 end *************");
    })
    
    /**
     * @tc.name rdb callback test deleteRdbStoreV9 OK params
     * @tc.number testV9RdbStoreCallBackTest0006
     * @tc.desc rdb callback test deleteRdbStoreV9 OK params
     */
    it('testV9RdbStoreCallBackTest0006', 0, async function (done) {
        console.log(TAG + "************* testV9RdbStoreCallBackTest0006 start *************")
        let context = featureAbility.getContext()
        dataRdb.getRdbStoreV9(context, STORE_CONFIG, 1).then((rdbStoreV9)=>{
            try{
                dataRdb.deleteRdbStoreV9(context, "V9_RDBCallbackTest.db", (err) => {
                    if (err) {
                        console.log("Delete RdbStore is failed, err: code=" + err.code + " message=" + err.message)
                        expect(false).assertTrue()
                    }
                    console.log("Delete RdbStore successfully.")
                    done()
                    console.log(TAG + "************* testV9RdbStoreCallBackTest0006 end *************")
                });
            } catch(err) {
                console.log("222catch err: Delete RdbStore failed, err: code=" + err.code + " message=" + err.message)
                expect(false).assertTrue()
            }
        }).catch((err) => {
            console.info("Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect(false).assertTrue()
        })
    })

    console.log(TAG + "*************Unit Test End*************");
})