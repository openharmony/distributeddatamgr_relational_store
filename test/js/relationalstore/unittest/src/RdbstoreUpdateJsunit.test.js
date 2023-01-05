/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
import data_relationalStore from '@ohos.data.relationalStore'
import ability_featureAbility from '@ohos.ability.featureAbility'
import dataSharePredicates from '@ohos.data.dataSharePredicates';
var context = ability_featureAbility.getContext()

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " + "name TEXT UNIQUE, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";
const STORE_CONFIG = {
    name: "UpdataTest.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
var rdbStore = undefined;

describe('rdbStoreUpdateTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await rdbStore.executeSql(CREATE_TABLE_TEST, null);
    })

    beforeEach(async function () {
        await rdbStore.executeSql("DELETE FROM test");
        console.info(TAG + 'beforeEach')
    })

    afterEach(function () {
        console.info(TAG + 'afterEach')
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        rdbStore = null
        await data_relationalStore.deleteRdbStore(context, "UpdataTest.db");
    })

    /**
     * @tc.name resultSet Update test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Update_0001
     * @tc.desc resultSet Update test
     */
    it('testRdbStoreUpdate0001', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreUpdate0001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let insertPromise = rdbStore.insert("test", valueBucket)
            insertPromise.then(async (ret) => {
                expect(1).assertEqual(ret);
                await console.log(TAG + "update done: " + ret);
            }).catch((err) => {
                expect(null).assertFail();
            })
            await insertPromise
        }
        {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "name": "lisi",
                "age": 20,
                "salary": 200.5,
                "blobType": u8,
            }
            let predicates = await new data_relationalStore.RdbPredicates("test")
            await predicates.equalTo("id", "1")
            let updatePromise = rdbStore.update(valueBucket, predicates)
            updatePromise.then(async (ret) => {
                await expect(1).assertEqual(ret);
                await console.log(TAG + "update done: " + ret);
                {
                    let predicates = await new data_relationalStore.RdbPredicates("test")
                    let resultSet = await rdbStore.query(predicates)

                    expect(true).assertEqual(resultSet.goToFirstRow())
                    const id = await resultSet.getLong(resultSet.getColumnIndex("id"))
                    const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                    const age = await resultSet.getLong(resultSet.getColumnIndex("age"))
                    const salary = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                    const blobType = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))

                    await expect(1).assertEqual(id);
                    await expect("lisi").assertEqual(name);
                    await expect(20).assertEqual(age);
                    await expect(200.5).assertEqual(salary);
                    await expect(4).assertEqual(blobType[0]);
                    await expect(5).assertEqual(blobType[1]);
                    await expect(6).assertEqual(blobType[2]);
                    console.log(TAG + "{id=" + id + ", name=" + name + ", age=" + age + ", salary=" + salary + ", blobType=" + blobType);
                    await expect(false).assertEqual(resultSet.goToNextRow())
                    resultSet = null
                }

            }).catch((err) => {
                console.log(TAG + "update error");
                expect(null).assertFail();
            })
            // await updatePromise
        }

        done();
        console.log(TAG + "************* testRdbStoreUpdate0001 end   *************");
    })

    /**
     * @tc.name resultSet Update test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Update_0002
     * @tc.desc resultSet Update test
     */
    it('testRdbStoreUpdate0002', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreUpdate0002 start *************");
        {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            try {
                let predicates = new data_relationalStore.RdbPredicates("")
                let updatePromise = rdbStore.update(valueBucket, predicates)
                updatePromise.then(async (ret) => {
                    await console.log(TAG + "update done: " + ret);
                    expect(null).assertFail();
                }).catch((err) => {
                    console.log(TAG + "update with null table name");
                })
            } catch (err) {
                console.log(
                    "catch err: update with null table name failed, err: code=" + err.code + " message=" + err.message)
                expect("401").assertEqual(err.code)
            }
            try {
                const emptyBucket = {};
                let predicates = await new data_relationalStore.RdbPredicates("test")
                let updatePromise = rdbStore.update(emptyBucket, predicates)
                updatePromise.then(async (ret) => {
                    await console.log(TAG + "update done: " + ret);
                    expect(null).assertFail();
                }).catch((err) => {
                    console.log(TAG + "update with wrong valueBucket");
                })
            } catch (err) {
                console.log("catch err: update with wrong valueBucket failed, err: code=" + err.code
                            + " message=" + err.message)
                expect("401").assertEqual(err.code)
            }
            try {
                let predicates = await new data_relationalStore.RdbPredicates("test")
                await predicates.equalTo("aaa", "null")
                let updatePromise = rdbStore.update(valueBucket, predicates)
                updatePromise.then(async (ret) => {
                    await console.log(TAG + "update done: " + ret);
                    expect(null).assertFail();
                }).catch((err) => {
                    console.log(TAG + "update with wrong condition");
                })
            } catch (err) {
                console.log("catch err: update with wrong condition failed, err: code=" + err.code
                            + " message=" + err.message)
            }
        }
        done();
        console.log(TAG + "************* testRdbStoreUpdate0002 end   *************");
    })

    /**
     * @tc.name resultSet Update test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Update_0003
     * @tc.desc resultSet Update test
     */
    it('testRdbStoreUpdate0003', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreUpdate0003 start *************");
        {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
                "wrongColumn": 100.5,
            }
            {
                let predicates = new data_relationalStore.RdbPredicates("wrongTable")
                let updatePromise = rdbStore.update(valueBucket, predicates)
                updatePromise.then(async (ret) => {
                    await console.log(TAG + "update done: " + ret);
                    expect(null).assertFail();
                }).catch((err) => {
                    console.log(TAG + "update with wrong table name");
                })
                // await updatePromise
            }
            {
                let predicates = await new data_relationalStore.RdbPredicates("test")
                let updatePromise = rdbStore.update(valueBucket, predicates)
                updatePromise.then(async (ret) => {
                    await console.log(TAG + "update done: " + ret);
                    expect(null).assertFail();
                }).catch((err) => {
                    console.log(TAG + "update with wrong column name");
                })
                // await updatePromise
            }
        }
        done();
        console.log(TAG + "************* testRdbStoreUpdate0003 end   *************");
    })

    /**
     * @tc.name resultSet Update test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Update_0004
     * @tc.desc resultSet Update test
     */
    it('testRdbStoreUpdate0004', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreUpdate0004 start *************");
        {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            {
                let predicates = await new data_relationalStore.RdbPredicates("test")
                await predicates.equalTo("aaa", "null")
                let updatePromise = rdbStore.update(valueBucket, predicates)
                updatePromise.then(async (ret) => {
                    await console.log(TAG + "update done: " + ret);
                    expect(null).assertFail();
                }).catch((err) => {
                    console.log(TAG + "update with wrong condition");
                })
                // await updatePromise
            }
            {
                const emptyBucket = {};
                let predicates = await new data_relationalStore.RdbPredicates("test")
                await predicates.equalTo("name", "zhangsan")
                await predicates.equalTo("age", 18)
                await predicates.equalTo("null", 100.5)
                let updatePromise = rdbStore.update(valueBucket, predicates)
                updatePromise.then(async (ret) => {
                    await console.log(TAG + "update done: " + ret);
                    expect(null).assertFail();
                }).catch((err) => {
                    console.log(TAG + "update with wrong condition");
                })
            }
        }
        done();
        console.log(TAG + "************* testRdbStoreUpdate0004 end   *************");
    })

    /**
     * @tc.name resultSet Update Extra long character test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Update_0005
     * @tc.desc resultSet Update Extra long character test
     */
    it('testRdbStoreUpdate0005', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreUpdate0005 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "xiaoming",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            var u8 = new Uint8Array([4, 5, 6])
            var nameStr = "abcd" + "e".repeat(2000) + "./&*$!@()"
            const valueBucket = {
                "name": nameStr,
                "age": 20,
                "salary": 200.5,
                "blobType": u8,
            }
            let predicates = await new data_relationalStore.RdbPredicates("test")
            await predicates.equalTo("name", "xiaoming")
            let updatePromise = rdbStore.update(valueBucket, predicates)
            updatePromise.then(async (ret) => {
                await expect(1).assertEqual(ret);
                await console.log(TAG + "update done: " + ret);
                {
                    let predicates = await new data_relationalStore.RdbPredicates("test")
                    predicates.equalTo("age", 20)
                    let resultSet = await rdbStore.query(predicates)
                    expect(true).assertEqual(resultSet.goToFirstRow())
                    const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                    await expect(nameStr).assertEqual(name);
                    console.log(TAG + "{id=" + id + ", name=" + name + ", age=" + age + ", salary=" + salary + ", blobType=" + blobType);
                    resultSet = null
                }

            }).catch((err) => {
                console.log(TAG + "update error");
                expect(null).assertFail();
            })
        }

        done();
        console.log(TAG + "************* testRdbStoreUpdate0005 end   *************");
    })

    /**
     * @tc.name resultSet Update Extra long character test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Update_0006
     * @tc.desc resultSet Update Extra long character test
     */
    it('testRdbStoreUpdate0006', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreUpdate0006 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "xiaohua",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            var u8 = new Uint8Array([4, 5, 6])
            var nameStr = "橘子是水果" + "e".repeat(2000)
            const valueBucket = {
                "name": nameStr,
                "age": 19,
                "salary": 200.5,
                "blobType": u8,
            }
            let predicates = await new data_relationalStore.RdbPredicates("test")
            await predicates.equalTo("name", "xiaohua")
            let updatePromise = rdbStore.update(valueBucket, predicates)
            updatePromise.then(async (ret) => {
                await expect(1).assertEqual(ret);
                await console.log(TAG + "update done: " + ret);
                {
                    let predicates = await new data_relationalStore.RdbPredicates("test")
                    predicates.equalTo("age", 19)
                    let resultSet = await rdbStore.query(predicates)
                    expect(true).assertEqual(resultSet.goToFirstRow())
                    const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                    await expect(nameStr).assertEqual(name);
                    console.log(TAG + "{id=" + id + ", name=" + name + ", age=" + age + ", salary=" + salary + ", blobType=" + blobType);
                    resultSet = null
                }

            }).catch((err) => {
                console.log(TAG + "update error");
                expect(null).assertFail();
            })
        }

        done();
        console.log(TAG + "************* testRdbStoreUpdate0006 end   *************");
    })

    /**
     * @tc.name resultSet Update Extra long character test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Update_0007
     * @tc.desc resultSet Update Extra long character test
     */
    it('testRdbStoreUpdate0007', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreUpdate0007 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "xiaocan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            var u8 = new Uint8Array([4, 5, 6])
            var nameStr = "菠萝是水果" + "e".repeat(2000) + "好吃又不贵"
            const valueBucket = {
                "name": nameStr,
                "age": 21,
                "salary": 200.5,
                "blobType": u8,
            }
            let predicates = await new data_relationalStore.RdbPredicates("test")
            await predicates.equalTo("name", "xiaocan")
            let updatePromise = rdbStore.update(valueBucket, predicates)
            updatePromise.then(async (ret) => {
                await expect(1).assertEqual(ret);
                await console.log(TAG + "update done: " + ret);
                {
                    let predicates = await new data_relationalStore.RdbPredicates("test")
                    predicates.equalTo("age", 21)
                    let resultSet = await rdbStore.query(predicates)
                    expect(true).assertEqual(resultSet.goToFirstRow())
                    const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                    await expect(nameStr).assertEqual(name);
                    console.log(TAG + "{id=" + id + ", name=" + name + ", age=" + age + ", salary=" + salary + ", blobType=" + blobType);
                    resultSet = null
                }

            }).catch((err) => {
                console.log(TAG + "update error");
                expect(null).assertFail();
            })
        }

        done();
        console.log(TAG + "************* testRdbStoreUpdate0007 end   *************");
    })

    /**
     * @tc.name rdb update test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Update_0008
     * @tc.desc rdb update test
     */
    it('testRdbStoreUpdate0008', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreUpdate0008 start *************");
        try {
            const valueBucket = {
                "name": "name",
                "age": 21,
                "salary": 200.5,
                "blobType": new Uint8Array([1, 2, 3]),
            }
            var predicate = new dataSharePredicates.DataSharePredicates();
            await rdbStore.update("test", valueBucket, predicate);
            expect(null).assertFail();
        } catch (err) {
            console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("202").assertEqual(err.code)
            done()
        }
        console.log(TAG + "************* testRdbStoreUpdate0008 end *************");
    })

    /**
     * @tc.name resultSet Update test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_UpdateWithConflictResolution_0001
     * @tc.desc resultSet Update test
     */
    it('testRdbStoreUpdateWithConflictResolution0001', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0001 start *************");
        {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "id": 2,
                "name": "lisi",
                "age": 19,
                "salary": 200.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }

        {
            var u8 = new Uint8Array([7, 8, 9])
            const valueBucket = {
                "id": 3,
                "name": "wangjing",
                "age": 20,
                "salary": 300.5,
                "blobType": u8,
            }
            let predicates = await new data_relationalStore.RdbPredicates("test")
            await predicates.equalTo("age", "19")
            let updatePromise = rdbStore.update(valueBucket, predicates)
            updatePromise.then(async (ret) => {
                await expect(1).assertEqual(ret);
                await console.log(TAG + "update done: " + ret);
                {
                    let predicates = await new data_relationalStore.RdbPredicates("test")
                    let resultSet = await rdbStore.query(predicates)

                    expect(true).assertEqual(resultSet.goToFirstRow())
                    const id = await resultSet.getLong(resultSet.getColumnIndex("id"))
                    const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                    const age = await resultSet.getLong(resultSet.getColumnIndex("age"))
                    const salary = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                    const blobType = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))

                    await expect(1).assertEqual(id);
                    await expect("zhangsan").assertEqual(name);
                    await expect(18).assertEqual(age);
                    await expect(100.5).assertEqual(salary);
                    await expect(1).assertEqual(blobType[0]);
                    await expect(2).assertEqual(blobType[1]);
                    await expect(3).assertEqual(blobType[2]);
                    console.log(TAG + "{id=" + id + ", name=" + name + ", age=" + age + ", salary="
                        + salary + ", blobType=" + blobType);

                    await expect(true).assertEqual(resultSet.goToNextRow())
                    const id_1 = await resultSet.getLong(resultSet.getColumnIndex("id"))
                    const name_1 = await resultSet.getString(resultSet.getColumnIndex("name"))
                    const age_1 = await resultSet.getLong(resultSet.getColumnIndex("age"))
                    const salary_1 = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                    const blobType_1 = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))

                    await expect(3).assertEqual(id_1);
                    await expect("wangjing").assertEqual(name_1);
                    await expect(20).assertEqual(age_1);
                    await expect(300.5).assertEqual(salary_1);
                    await expect(7).assertEqual(blobType_1[0]);
                    await expect(8).assertEqual(blobType_1[1]);
                    await expect(9).assertEqual(blobType_1[2]);
                    console.log(TAG + "{id=" + id_1 + ", name=" + name_1 + ", age=" + age_1 + ", salary="
                        + salary_1 + ", blobType=" + blobType_1);
                    await expect(false).assertEqual(resultSet.goToNextRow())

                    resultSet = null
                    done();
                    console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0001 end   *************");
                }
            }).catch((err) => {
                console.log(TAG + "update error");
                expect(null).assertFail();
                console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0001 end   *************");
            })
        }
    })

    /**
     * @tc.name resultSet Update test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_UpdateWithConflictResolution_0002
     * @tc.desc resultSet Update test
     */
    it('testRdbStoreUpdateWithConflictResolution0002', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0002 start *************");
        {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "id": 2,
                "name": "lisi",
                "age": 19,
                "salary": 200.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            var u8 = new Uint8Array([7, 8, 9])
            const valueBucket = {
                "id": 3,
                "name": "zhangsan",
                "age": 20,
                "salary": 300.5,
                "blobType": u8,
            }
            let predicates = await new data_relationalStore.RdbPredicates("test")
            await predicates.equalTo("age", "19")
            let updatePromise = rdbStore.update(valueBucket, predicates, data_relationalStore.ConflictResolution.ON_CONFLICT_NONE);
            updatePromise.then(async (ret) => {
                await console.log(TAG + "update done: " + ret);
                expect(null).assertFail();
            }).catch((err) => {
                console.log(TAG + "update error");
                expect(null).assertFail();
            })
            done()
        }

        {
            let predicates = await new data_relationalStore.RdbPredicates("test")
            let resultSet = await rdbStore.query(predicates)

            expect(true).assertEqual(resultSet.goToFirstRow())
            const id = await resultSet.getLong(resultSet.getColumnIndex("id"))
            const name = await resultSet.getString(resultSet.getColumnIndex("name"))
            const age = await resultSet.getLong(resultSet.getColumnIndex("age"))
            const salary = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
            const blobType = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))

            await expect(1).assertEqual(id);
            await expect("zhangsan").assertEqual(name);
            await expect(18).assertEqual(age);
            await expect(100.5).assertEqual(salary);
            await expect(1).assertEqual(blobType[0]);
            await expect(2).assertEqual(blobType[1]);
            await expect(3).assertEqual(blobType[2]);
            console.log(TAG + "{id=" + id + ", name=" + name + ", age=" + age + ", salary="
                + salary + ", blobType=" + blobType);

            await expect(true).assertEqual(resultSet.goToNextRow())
            const id_1 = await resultSet.getLong(resultSet.getColumnIndex("id"))
            const name_1 = await resultSet.getString(resultSet.getColumnIndex("name"))
            const age_1 = await resultSet.getLong(resultSet.getColumnIndex("age"))
            const salary_1 = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
            const blobType_1 = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))

            await expect(2).assertEqual(id_1);
            await expect("lisi").assertEqual(name_1);
            await expect(19).assertEqual(age_1);
            await expect(200.5).assertEqual(salary_1);
            await expect(4).assertEqual(blobType_1[0]);
            await expect(5).assertEqual(blobType_1[1]);
            await expect(6).assertEqual(blobType_1[2]);
            console.log(TAG + "{id=" + id_1 + ", name=" + name_1 + ", age=" + age_1 + ", salary="
                + salary_1 + ", blobType=" + blobType_1);
            await expect(false).assertEqual(resultSet.goToNextRow())

            resultSet = null
            done()
            console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0002 end   *************");
        }
    })

    /**
     * @tc.name resultSet Update test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_UpdateWithConflictResolution_0003
     * @tc.desc resultSet Update test
     */
    it('testRdbStoreUpdateWithConflictResolution0003', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0003 start *************");
        {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "id": 2,
                "name": "lisi",
                "age": 19,
                "salary": 200.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            var u8 = new Uint8Array([7, 8, 9])
            const valueBucket = {
                "id": 3,
                "name": "wangjing",
                "age": 20,
                "salary": 300.5,
                "blobType": u8,
            }
            let predicates = await new data_relationalStore.RdbPredicates("test")
            await predicates.equalTo("age", "19")
            let updatePromise = rdbStore.update(valueBucket, predicates, data_relationalStore.ConflictResolution.ON_CONFLICT_ROLLBACK);
            updatePromise.then(async (ret) => {
                await expect(1).assertEqual(ret);
                await console.log(TAG + "update done: " + ret);
                {
                    let predicates = await new data_relationalStore.RdbPredicates("test")
                    let resultSet = await rdbStore.query(predicates)

                    expect(true).assertEqual(resultSet.goToFirstRow())
                    const id = await resultSet.getLong(resultSet.getColumnIndex("id"))
                    const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                    const age = await resultSet.getLong(resultSet.getColumnIndex("age"))
                    const salary = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                    const blobType = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))

                    await expect(1).assertEqual(id);
                    await expect("zhangsan").assertEqual(name);
                    await expect(18).assertEqual(age);
                    await expect(100.5).assertEqual(salary);
                    await expect(1).assertEqual(blobType[0]);
                    await expect(2).assertEqual(blobType[1]);
                    await expect(3).assertEqual(blobType[2]);
                    console.log(TAG + "{id=" + id + ", name=" + name + ", age=" + age + ", salary="
                        + salary + ", blobType=" + blobType);

                    await expect(true).assertEqual(resultSet.goToNextRow())
                    const id_1 = await resultSet.getLong(resultSet.getColumnIndex("id"))
                    const name_1 = await resultSet.getString(resultSet.getColumnIndex("name"))
                    const age_1 = await resultSet.getLong(resultSet.getColumnIndex("age"))
                    const salary_1 = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                    const blobType_1 = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))

                    await expect(3).assertEqual(id_1);
                    await expect("wangjing").assertEqual(name_1);
                    await expect(20).assertEqual(age_1);
                    await expect(300.5).assertEqual(salary_1);
                    await expect(7).assertEqual(blobType_1[0]);
                    await expect(8).assertEqual(blobType_1[1]);
                    await expect(9).assertEqual(blobType_1[2]);
                    console.log(TAG + "{id=" + id_1 + ", name=" + name_1 + ", age=" + age_1 + ", salary="
                        + salary_1 + ", blobType=" + blobType_1);
                    await expect(false).assertEqual(resultSet.goToNextRow())

                    resultSet = null
                    done();
                    console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0003 end   *************");
                }

            }).catch((err) => {
                console.log(TAG + "update error");
                expect(null).assertFail();
                console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0003 end   *************");
            })
        }
    })

    /**
     * @tc.name resultSet Update test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_UpdateWithConflictResolution_0004
     * @tc.desc resultSet Update test
     */
    it('testRdbStoreUpdateWithConflictResolution0004', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0004 start *************");
        {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "id": 2,
                "name": "lisi",
                "age": 19,
                "salary": 200.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            var u8 = new Uint8Array([7, 8, 9])
            const valueBucket = {
                "id": 3,
                "name": "zhangsan",
                "age": 20,
                "salary": 300.5,
                "blobType": u8,
            }
            let predicates = await new data_relationalStore.RdbPredicates("test")
            await predicates.equalTo("age", "19")
            let updatePromise = rdbStore.update(valueBucket, predicates, data_relationalStore.ConflictResolution.ON_CONFLICT_ROLLBACK);
            updatePromise.then(async (ret) => {
                aexpect(null).assertFail();
                await console.log(TAG + "update done: " + ret);
            }).catch((err) => {
                expect(null).assertFail();
                console.log(TAG + "update error");
            })
            done()
        }

        {
            let predicates = await new data_relationalStore.RdbPredicates("test")
            let resultSet = await rdbStore.query(predicates)

            expect(true).assertEqual(resultSet.goToFirstRow())
            const id = await resultSet.getLong(resultSet.getColumnIndex("id"))
            const name = await resultSet.getString(resultSet.getColumnIndex("name"))
            const age = await resultSet.getLong(resultSet.getColumnIndex("age"))
            const salary = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
            const blobType = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))

            await expect(1).assertEqual(id);
            await expect("zhangsan").assertEqual(name);
            await expect(18).assertEqual(age);
            await expect(100.5).assertEqual(salary);
            await expect(1).assertEqual(blobType[0]);
            await expect(2).assertEqual(blobType[1]);
            await expect(3).assertEqual(blobType[2]);
            console.log(TAG + "{id=" + id + ", name=" + name + ", age=" + age + ", salary="
                + salary + ", blobType=" + blobType);

            await expect(true).assertEqual(resultSet.goToNextRow())
            const id_1 = await resultSet.getLong(resultSet.getColumnIndex("id"))
            const name_1 = await resultSet.getString(resultSet.getColumnIndex("name"))
            const age_1 = await resultSet.getLong(resultSet.getColumnIndex("age"))
            const salary_1 = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
            const blobType_1 = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))

            await expect(2).assertEqual(id_1);
            await expect("lisi").assertEqual(name_1);
            await expect(19).assertEqual(age_1);
            await expect(200.5).assertEqual(salary_1);
            await expect(4).assertEqual(blobType_1[0]);
            await expect(5).assertEqual(blobType_1[1]);
            await expect(6).assertEqual(blobType_1[2]);
            console.log(TAG + "{id=" + id_1 + ", name=" + name_1 + ", age=" + age_1 + ", salary="
                + salary_1 + ", blobType=" + blobType_1);
            await expect(false).assertEqual(resultSet.goToNextRow())

            resultSet = null
            done()
            console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0004 end   *************");
        }
    })

    /**
     * @tc.name resultSet Update test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_UpdateWithConflictResolution_0005
     * @tc.desc resultSet Update test
     */
    it('testRdbStoreUpdateWithConflictResolution0005', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0005 start *************");
        {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "id": 2,
                "name": "lisi",
                "age": 19,
                "salary": 200.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            var u8 = new Uint8Array([7, 8, 9])
            const valueBucket = {
                "id": 3,
                "name": "wangjing",
                "age": 20,
                "salary": 300.5,
                "blobType": u8,
            }
            let predicates = await new data_relationalStore.RdbPredicates("test")
            await predicates.equalTo("age", "19")
            let updatePromise = rdbStore.update(valueBucket, predicates, data_relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
            updatePromise.then(async (ret) => {
                await expect(1).assertEqual(ret);
                await console.log(TAG + "update done: " + ret);
                {
                    let predicates = await new data_relationalStore.RdbPredicates("test")
                    let resultSet = await rdbStore.query(predicates)

                    expect(true).assertEqual(resultSet.goToFirstRow())
                    const id = await resultSet.getLong(resultSet.getColumnIndex("id"))
                    const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                    const age = await resultSet.getLong(resultSet.getColumnIndex("age"))
                    const salary = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                    const blobType = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))

                    await expect(1).assertEqual(id);
                    await expect("zhangsan").assertEqual(name);
                    await expect(18).assertEqual(age);
                    await expect(100.5).assertEqual(salary);
                    await expect(1).assertEqual(blobType[0]);
                    await expect(2).assertEqual(blobType[1]);
                    await expect(3).assertEqual(blobType[2]);
                    console.log(TAG + "{id=" + id + ", name=" + name + ", age=" + age + ", salary="
                        + salary + ", blobType=" + blobType);

                    await expect(true).assertEqual(resultSet.goToNextRow())
                    const id_1 = await resultSet.getLong(resultSet.getColumnIndex("id"))
                    const name_1 = await resultSet.getString(resultSet.getColumnIndex("name"))
                    const age_1 = await resultSet.getLong(resultSet.getColumnIndex("age"))
                    const salary_1 = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                    const blobType_1 = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))

                    await expect(3).assertEqual(id_1);
                    await expect("wangjing").assertEqual(name_1);
                    await expect(20).assertEqual(age_1);
                    await expect(300.5).assertEqual(salary_1);
                    await expect(7).assertEqual(blobType_1[0]);
                    await expect(8).assertEqual(blobType_1[1]);
                    await expect(9).assertEqual(blobType_1[2]);
                    console.log(TAG + "{id=" + id_1 + ", name=" + name_1 + ", age=" + age_1 + ", salary="
                        + salary_1 + ", blobType=" + blobType_1);
                    await expect(false).assertEqual(resultSet.goToNextRow())

                    resultSet = null
                    done()
                    console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0005 end   *************");
                }

            }).catch((err) => {
                console.log(TAG + "update error");
                expect(null).assertFail();
                console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0005 end   *************");
            })
        }
    })

    it('testRdbStoreUpdateWithConflictResolution0006', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0006 start *************");
        {
            var u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "id": 1,
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }

        {
            var u8 = new Uint8Array([4, 5, 6])
            const valueBucket = {
                "id": 2,
                "name": "lisi",
                "age": 19,
                "salary": 200.5,
                "blobType": u8,
            }
            await rdbStore.insert("test", valueBucket)
        }
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 20,
                "salary": 300.5,
            }
            let predicates = await new data_relationalStore.RdbPredicates("test")
            await predicates.equalTo("age", "19")
            let updatePromise = rdbStore.update(valueBucket, predicates, data_relationalStore.ConflictResolution.ON_CONFLICT_REPLACE);
            updatePromise.then(async (ret) => {
                await expect(1).assertEqual(ret);
                await console.log(TAG + "update done: " + ret);
                {
                    let predicates = await new data_relationalStore.RdbPredicates("test")
                    let resultSet = await rdbStore.query(predicates)

                    expect(true).assertEqual(resultSet.goToFirstRow())
                    const id = await resultSet.getLong(resultSet.getColumnIndex("id"))
                    const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                    const age = await resultSet.getLong(resultSet.getColumnIndex("age"))
                    const salary = await resultSet.getDouble(resultSet.getColumnIndex("salary"))
                    const blobType = await resultSet.getBlob(resultSet.getColumnIndex("blobType"))

                    await expect(2).assertEqual(id);
                    await expect("zhangsan").assertEqual(name);
                    await expect(20).assertEqual(age);
                    await expect(300.5).assertEqual(salary);
                    await expect(4).assertEqual(blobType[0]);
                    await expect(5).assertEqual(blobType[1]);
                    await expect(6).assertEqual(blobType[2]);
                    console.log(TAG + "{id=" + id + ", name=" + name + ", age=" + age + ", salary="
                        + salary + ", blobType=" + blobType);

                    await expect(false).assertEqual(resultSet.goToNextRow())
                    resultSet = null
                    done()
                    console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0006 end   *************");
                }

            }).catch((err) => {
                console.log(TAG + "update error");
                expect(null).assertFail();
                console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0006 end   *************");
            })
        }
    })

    /**
     * @tc.name resultSet Update test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_UpdateWithConflictResolution_0007
     * @tc.desc resultSet Update test
     */
    it('testRdbStoreUpdateWithConflictResolution0007', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0007 start *************");
        try {
            const valueBucket = {
                "name": "zhangsan",
                "age": 20,
                "salary": 300.5,
            }
            let predicates = await new data_relationalStore.RdbPredicates("test")
            await predicates.equalTo("age", "19")
            rdbStore.update(valueBucket, predicates, 6);
            expect(null).assertFail();
        } catch (err) {
            console.log("catch err: failed, err: code=" + err.code + " message=" + err.message)
            expect("401").assertEqual(err.code)
            console.log(TAG + "************* testRdbStoreUpdateWithConflictResolution0007 end   *************");
            done()
        }
    })

    console.log(TAG + "*************Unit Test End*************");
})
