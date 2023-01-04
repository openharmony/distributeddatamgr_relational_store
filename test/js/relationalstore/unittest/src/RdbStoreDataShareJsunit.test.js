/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")
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
import data_relationalStore from '@ohos.data.relationalStore'
import ability_featureAbility from '@ohos.ability.featureAbility'
import data_dataSharePredicates from '@ohos.data.dataSharePredicates'

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    + "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)"
const DROP_TABLE_TEST = "drop table test"

const STORE_CONFIG = {
    name: "DataShareTest.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
var rdbStore = undefined
var context = ability_featureAbility.getContext()

describe('rdbStoreDataSharePredicatesTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG)
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
        await rdbStore.executeSql(CREATE_TABLE_TEST, null)
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
        await rdbStore.executeSql(DROP_TABLE_TEST, null)
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        rdbStore = null
        await data_relationalStore.deleteRdbStore(context, "DataShareTest.db")
    })

    console.log(TAG + "*************Unit Test Begin*************")


    /**
     * @tc.name rdb DataShare insert test
     * @tc.number testRdbStoreDataShareFunc0010
     * @tc.desc rdb DataShare Func insert test
     */
    it('testRdbStoreDataShareFunc0001', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDataShareFunc0001 start *************")
        let u8 = new Uint8Array([1, 2, 3])
        const valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        let insertPromise = rdbStore.insert("test", valueBucket)
        insertPromise.then(async (ret) => {
            expect(1).assertEqual(ret)
            console.log(TAG + "Insert done: " + ret)
        }).catch((err) => {
            console.log(TAG + "Insert err: " + err)
            expect(false).assertTrue()
        })
        await insertPromise
        console.log("insert end")

        let predicates = new data_relationalStore.RdbPredicates("test")
        predicates.equalTo("name", "zhangsan")
        let resultSet = await rdbStore.query(predicates)
        try {
            console.log(TAG + "resultSet query done")
            expect(true).assertEqual(resultSet.goToFirstRow())
            const name = resultSet.getString(resultSet.getColumnIndex("name"))
            const age = resultSet.getLong(resultSet.getColumnIndex("age"))
            const salary = resultSet.getDouble(resultSet.getColumnIndex("salary"))
            const blobType = resultSet.getBlob(resultSet.getColumnIndex("blobType"))
            expect("zhangsan").assertEqual(name)
            expect(18).assertEqual(age)
            expect(100.5).assertEqual(salary)
            expect(1).assertEqual(blobType[0])
            expect(2).assertEqual(blobType[1])
            expect(3).assertEqual(blobType[2])
        } catch (err) {
            expect(false).assertTrue()
        }
        resultSet = null

        done()
        console.log(TAG + "************* testRdbStoreDataShareFunc0001 end *************")
    })


    /**
     * @tc.name rdb DataShare update test
     * @tc.number testRdbStoreDataShareFunc0020
     * @tc.desc rdb DataShare update promise Func test
     */
    it('testRdbStoreDataShareFunc0002', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDataShareFunc0002 start *************")
        let u8 = new Uint8Array([1, 2, 3])
        let valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket)

        u8 = new Uint8Array([4, 5, 6])
        valueBucket = {
            "name": "lisi",
            "age": 28,
            "salary": 200.5,
            "blobType": u8,
        }

        let predicates = new data_dataSharePredicates.DataSharePredicates()
        predicates.equalTo("name", "zhangsan")
        try {
            let promiseUpdate = rdbStore.update("test", valueBucket, predicates)
            promiseUpdate.then(async (ret) => {
                expect(1).assertEqual(ret)
                console.log(TAG + "Update done: " + ret)
            }).catch((err) => {
                console.log(TAG + "Update err: " + err)
                expect(false).assertTrue()
            })
            await promiseUpdate

            let rdbPredicates = await new data_relationalStore.RdbPredicates("test")
            rdbPredicates.equalTo("name", "lisi")
            let resultSet = await rdbStore.query(rdbPredicates)
            expect(true).assertEqual(resultSet.goToFirstRow())
            const id = resultSet.getLong(resultSet.getColumnIndex("id"))
            const name = resultSet.getString(resultSet.getColumnIndex("name"))
            const age = resultSet.getLong(resultSet.getColumnIndex("age"))
            const salary = resultSet.getDouble(resultSet.getColumnIndex("salary"))
            const blobType = resultSet.getBlob(resultSet.getColumnIndex("blobType"))

            expect("lisi").assertEqual(name)
            expect(28).assertEqual(age)
            expect(200.5).assertEqual(salary)
            expect(4).assertEqual(blobType[0])
            expect(5).assertEqual(blobType[1])
            expect(6).assertEqual(blobType[2])

            console.log(TAG + "dataShare update: {id=" + id + ", name=" + name + ", " +
                "age=" + age + ", salary=" + salary + ", blobType=" + blobType)
            resultSet = null
        } catch(e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)
            expect("202").assertEqual(e.code)
        }
        done()
        console.log(TAG + "************* testRdbStoreDelete0002 end *************")
    })

    /**
     * @tc.name rdb DataShare update test
     * @tc.number testRdbStoreDataShareFunc0030
     * @tc.desc rdb DataShare update callback Func test
     */
    it('testRdbStoreDataShareFunc0003', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDataShareFunc0003 start *************")
        let u8 = new Uint8Array([1, 2, 3])
        let valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket)

        u8 = new Uint8Array([4, 5, 6])
        valueBucket = {
            "name": "lisi",
            "age": 28,
            "salary": 200.5,
            "blobType": u8,
        }

        let predicates = new data_dataSharePredicates.DataSharePredicates()
        predicates.equalTo("name", "zhangsan")
        try {
            await rdbStore.update("test", valueBucket, predicates, async function (err, ret) {
                if (err) {
                    console.info("Update err: " + err)
                    expect(false).assertTrue()
                }
                expect(1).assertEqual(ret)
                console.log("Update done: " + ret)
                let rdbPredicates = await new data_relationalStore.RdbPredicates("test")
                rdbPredicates.equalTo("name", "lisi")
                let resultSet = await rdbStore.query(rdbPredicates)
                expect(1).assertEqual(resultSet.rowCount)
                expect(true).assertEqual(resultSet.goToFirstRow())
                const id = resultSet.getLong(resultSet.getColumnIndex("id"))
                const name = resultSet.getString(resultSet.getColumnIndex("name"))
                const age = resultSet.getLong(resultSet.getColumnIndex("age"))
                const salary = resultSet.getDouble(resultSet.getColumnIndex("salary"))
                const blobType = resultSet.getBlob(resultSet.getColumnIndex("blobType"))

                expect("lisi").assertEqual(name)
                expect(28).assertEqual(age)
                expect(200.5).assertEqual(salary)
                expect(4).assertEqual(blobType[0])
                expect(5).assertEqual(blobType[1])
                expect(6).assertEqual(blobType[2])
                console.log(TAG + "dataShare update: {id=" + id + ", name=" + name + ", " +
                    "age=" + age + ", salary=" + salary + ", blobType=" + blobType)
                resultSet = null
            })
        } catch(e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)
            expect("202").assertEqual(e.code)
        }

        done()
        console.log(TAG + "************* testRdbStoreDelete0003 end *************")
    })

    /**
     * @tc.name rdb DataShare query test
     * @tc.number testRdbStoreDataShareFunc0040
     * @tc.desc rdb DataShare query promise Func test
     */
    it('testRdbStoreDataShareFunc0004', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDataShareFunc0004 start *************")
        let u8 = new Uint8Array([4, 5, 6])
        let valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket)

        let predicates = new data_dataSharePredicates.DataSharePredicates()
        predicates.equalTo("name", "zhangsan")
        try {
            let queryPromise = rdbStore.query("test", predicates)
            queryPromise.then((resultSet) => {
                console.log(TAG + "DataShare Query done: ")
                expect(true).assertEqual(resultSet.goToFirstRow())
                const name = resultSet.getString(resultSet.getColumnIndex("name"))
                const age = resultSet.getLong(resultSet.getColumnIndex("age"))
                const salary = resultSet.getDouble(resultSet.getColumnIndex("salary"))
                const blobType = resultSet.getBlob(resultSet.getColumnIndex("blobType"))

                expect("zhangsan").assertEqual(name)
                expect(18).assertEqual(age)
                expect(100.5).assertEqual(salary)
                expect(4).assertEqual(blobType[0])
                expect(5).assertEqual(blobType[1])
                expect(6).assertEqual(blobType[2])

            }).catch((err) => {
                console.log(TAG + "Query err: " + err)
                expect(false).assertTrue()
            })
            await queryPromise
        } catch(e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)
            expect("202").assertEqual(e.code)
        }
        done()
        console.log(TAG + "************* testRdbStoreDataShareFunc0004 end *************")
    })

    /**
     * @tc.name rdb DataShare query test
     * @tc.number testRdbStoreDataShareFunc0050
     * @tc.desc rdb DataShare query callback Func test
     */
    it('testRdbStoreDataShareFunc0005', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDataShareFunc0005 start *************")
        let u8 = new Uint8Array([4, 5, 6])
        let valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket)

        let predicates = new data_dataSharePredicates.DataSharePredicates()
        predicates.equalTo("name", "zhangsan")
        try {
            await rdbStore.query("test", predicates, ["ID", "NAME", "AGE", "SALARY", "blobType"],
                function (err, resultSet) {
                    if (err) {
                        console.info("Query err: " + err)
                        expect(false).assertTrue()
                    }
                    expect(true).assertEqual(resultSet.goToFirstRow())
                    const name = resultSet.getString(resultSet.getColumnIndex("name"))
                    const age = resultSet.getLong(resultSet.getColumnIndex("age"))
                    const salary = resultSet.getDouble(resultSet.getColumnIndex("salary"))
                    const blobType = resultSet.getBlob(resultSet.getColumnIndex("blobType"))

                    expect("zhangsan").assertEqual(name)
                    expect(18).assertEqual(age)
                    expect(100.5).assertEqual(salary)
                    expect(4).assertEqual(blobType[0])
                    expect(5).assertEqual(blobType[1])
                    expect(6).assertEqual(blobType[2])
                })
        } catch(e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)
            expect("202").assertEqual(e.code)
        }
        done()
        console.log(TAG + "************* testRdbStoreDataShareFunc0005 end *************")
    })

    /**
     * @tc.name rdb DataShare delete test
     * @tc.number testRdbStoreDataShareFunc0060
     * @tc.desc rdb DataShare delete Func test
     */
    it('testRdbStoreDataShareFunc0006', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDataShareFunc0006 start *************")
        let u8 = new Uint8Array([1, 2, 3])
        let valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }

        await rdbStore.insert("test", valueBucket)
        let predicates = new data_dataSharePredicates.DataSharePredicates()
        predicates.equalTo("name", "zhangsan")
        try {
            let deletePromise = rdbStore.delete("test", predicates)
            deletePromise.then(async (ret) => {
                expect(1).assertEqual(ret)
                console.log(TAG + "Delete done: " + ret)
            }).catch((err) => {
                console.log(TAG + "Delete err: " + err)
                expect(false).assertTrue()
            })
            await deletePromise

            let rdbPredicates = await new data_relationalStore.RdbPredicates("test")
            rdbPredicates.equalTo("name", "zhangsan")
            let resultSet = await rdbStore.query(rdbPredicates)
            expect(false).assertEqual(resultSet.goToFirstRow())
            resultSet = null
        } catch(e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)
            expect("202").assertEqual(e.code)
        }
        done()
        console.log(TAG + "************* testRdbStoreDataShareFunc0006 end *************")
    })

    /**
     * @tc.name rdb DataShare delete test
     * @tc.number testRdbStoreDataShareFunc0070
     * @tc.desc rdb DataShare delete Func test
     */
    it('testRdbStoreDataShareFunc0007', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDataShareFunc0007 start *************")
        let u8 = new Uint8Array([1, 2, 3])
        let valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket)

        let predicates = new data_dataSharePredicates.DataSharePredicates()
        predicates.equalTo("name", "zhangsan")
        try {
            await rdbStore.delete("test", predicates, async function (err, ret) {
                if (err) {
                    console.info("Delete err: " + err)
                    expect(false).assertTrue()
                }
                expect(1).assertEqual(ret)
                console.log("Delete done: " + ret)
                let rdbPredicates = await new data_relationalStore.RdbPredicates("test")
                rdbPredicates.equalTo("name", "zhangsan")
                let resultSet = await rdbStore.query(rdbPredicates)
                expect(false).assertEqual(resultSet.goToFirstRow())
                resultSet = null
            })
        } catch(e) {
            console.log("catch err: failed, err: code=" + e.code + " message=" + e.message)
            expect("202").assertEqual(e.code)
        }
        done()
        console.log(TAG + "************* testRdbStoreDataShareFunc0007 end *************")
    })
    console.log(TAG + "*************Unit Test End*************")
})