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
    name: "V9_RDBPromiseTest.db",
}

describe('V9_rdbStorePromiseTest', function () {
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
     * @tc.name rdb V9 base use
     * @tc.number testV9RdbStorePromiseTest0001
     * @tc.desc rdb V9 base use
     */
    it('testV9RdbStorePromiseTest0001', 0, async function (done) {
        console.log(TAG + "************* testV9RdbStorePromiseTest0001 start *************");
        let context = featureAbility.getContext()
        try{
            dataRdb.getRdbStoreV9(context, STORE_CONFIG, 1).then(async (rdbStoreV9) => {
                console.log("Get RdbStore successfully.")
                await rdbStoreV9.executeSql(CREATE_TABLE_TEST, null)
                const valueBucket = {
                    "name": "zhangsan",
                    "age": 18,
                    "salary": 100.5,
                    "blobType": new Uint8Array([1, 2, 3]),
                }             
                await rdbStoreV9.insert("test", valueBucket)
                let predicates = new dataRdb.RdbPredicatesV9("test")
                console.log("Create RdbPredicates OK")
                predicates.equalTo("name", "zhangsan")
                rdbStoreV9.query(predicates, []).then((resultSetV9) => {
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
                    rdbStoreV9.delete(predicates).then((rows) => {
                        console.log("Delete rows: " + rows)
                        expect(1).assertEqual(rows)
                        dataRdb.deleteRdbStoreV9(context, "V9_RDBPromiseTest.db").then(() => {
                            console.log("Delete RdbStore successfully.")
                            done()
                            console.log(TAG + "************* testV9RdbStorePromiseTest0001 end *************");
                        })
                    })
                })
            })
        } catch(err) {
            console.info("catch err: Get RdbStore failed, err: code=" + err.code + " message=" + err.message)
            expect(null).assertFail()
        }
        done()
    })
    
    /**
     * @tc.name rdb getRdbStoreV9 err params
     * @tc.number testV9RdbStorePromiseTest0002
     * @tc.desc rdb getRdbStoreV9 err params
     */
    it('testV9RdbStorePromiseTest0002', 0, async function (done) {
        console.log(TAG + "************* testV9RdbStorePromiseTest0002 start *************")
        let context = featureAbility.getContext()
        try{
            dataRdb.getRdbStoreV9(context, {dbname: "V9_RDBCallbackTest.db"}, 1).then((rdbStoreV9) => {
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
        console.log(TAG + "************* testV9RdbStorePromiseTest0002 end *************")
    })
    
    /**
     * @tc.name rdb getRdbStoreV9 ok params
     * @tc.number testV9RdbStorePromiseTest0003
     * @tc.desc rdb getRdbStoreV9 ok params
     */
    it('testV9RdbStorePromiseTest0003', 0, async function (done) {
        console.log(TAG + "************* testV9RdbStorePromiseTest0003 start *************");
        let context = featureAbility.getContext()
        try{
            dataRdb.getRdbStoreV9(context, STORE_CONFIG, 1).then((rdbStoreV9) => {
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
        console.log(TAG + "************* testV9RdbStorePromiseTest0003 end *************")
    })

    /**
     * @tc.name rdb deleteRdbStoreV9 err params
     * @tc.number testV9RdbStorePromiseTest0004
     * @tc.desc rdb deleteRdbStoreV9 err params
     */
    it('testV9RdbStorePromiseTest0004', 0, async function (done) {
        console.log(TAG + "************* testV9RdbStorePromiseTest0004 start *************")
        let context = featureAbility.getContext()        
        let rdbStoreV9 = await dataRdb.getRdbStoreV9(context, STORE_CONFIG, 1)
        try{
            dataRdb.deleteRdbStoreV9(context, 123454345).then((rdbStoreV9) => {
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
        console.log(TAG + "************* testV9RdbStorePromiseTest0004 end *************")
    })
    
    /**
     * @tc.name rdb deleteRdbStoreV9 OK params
     * @tc.number testV9RdbStorePromiseTest0004
     * @tc.desc rdb deleteRdbStoreV9 OK params
     */
    it('testV9RdbStorePromiseTest0005', 0, async function (done) {
        console.log(TAG + "************* testV9RdbStorePromiseTest0005 start *************");
        let context = featureAbility.getContext()
        let rdbStoreV9 = await dataRdb.getRdbStoreV9(context, STORE_CONFIG, 1)
        try{
            dataRdb.deleteRdbStoreV9(context, "V9_RDBCallbackTest.db").then((err) => {
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
        console.log(TAG + "************* testV9RdbStorePromiseTest0005 end *************")
    })

    console.log(TAG + "*************Unit Test End*************");
})