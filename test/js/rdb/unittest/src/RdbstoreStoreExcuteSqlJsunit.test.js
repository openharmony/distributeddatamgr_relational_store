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
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index'
import dataRdb from '@ohos.data.rdb';

const TAG = "[RDB_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const STORE_CONFIG = {
    name: "ExcuteSqlTest.db",
}
var rdbStore = undefined;

describe('rdbStoreExcuteSqlTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        rdbStore = await dataRdb.getRdbStore(STORE_CONFIG, 1);
    })

    beforeEach(async function () {
        await rdbStore.executeSql(CREATE_TABLE_TEST, null);
        console.info(TAG + 'beforeEach')
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
        await rdbStore.executeSql("DROP TABLE IF EXISTS test")
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        rdbStore = null
        await dataRdb.deleteRdbStore("ExcuteSqlTest.db");
    })

    /**
     * @tc.name resultSet ExcuteSql normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ExcuteSql_0010
     * @tc.desc resultSet ExcuteSql normal test
     */
    it('ExcuteSqlTest0001', 0, async function (done) {
        console.log(TAG + "************* ExcuteSqlTest0001 start *************");
        var u8 = new Uint8Array([1, 2, 3])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = await rdbStore.insert("test", valueBucket)
            expect(1).assertEqual(ret);
        }
        {
            const valueBucket = {
                "name": "lisi",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = await rdbStore.insert("test", valueBucket)
            expect(2).assertEqual(ret);
        }
        {
            const valueBucket = {
                "name": "lisi",
                "age": 20,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = await rdbStore.insert("test", valueBucket)
            expect(3).assertEqual(ret);
        }
        await rdbStore.executeSql("DELETE FROM test WHERE age = ? OR age = ?", ["18", "20"])

        let querySqlPromise = rdbStore.querySql("SELECT * FROM test")
        querySqlPromise.then(async (resultSet) => {
            expect(0).assertEqual(resultSet.rowCount)
            resultSet.close()
            done();
        }).catch((err) => {
            expect(null).assertFail();
        })
        await querySqlPromise
        console.log(TAG + "************* ExcuteSqlTest0001 end   *************");
    })

    /**
     * @tc.name resultSet ExcuteSql normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ExcuteSql_0020
     * @tc.desc resultSet ExcuteSql normal test
     */
    it('ExcuteSqlTest0002', 0, async function (done) {
        console.log(TAG + "************* ExcuteSqlTest0002 start *************");
        var u8 = new Uint8Array([2, 3, 4])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = await rdbStore.insert("test", valueBucket)
            expect(1).assertEqual(ret);
        }
        {
            const valueBucket = {
                "name": "lisi",
                "age": 19,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = await rdbStore.insert("test", valueBucket)
            expect(2).assertEqual(ret);
        }
        {
            const valueBucket = {
                "name": "lisi",
                "age": 20,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = await rdbStore.insert("test", valueBucket)
            expect(3).assertEqual(ret);
        }
        await rdbStore.executeSql("DELETE FROM test WHERE name = 'lisi'")
        let querySqlPromise = rdbStore.querySql("SELECT * FROM test")
        querySqlPromise.then(async (resultSet) => {
            expect(1).assertEqual(resultSet.rowCount)
            resultSet.close()
            done();
        }).catch((err) => {
            expect(null).assertFail();
        })
        await querySqlPromise
        console.log(TAG + "************* ExcuteSqlTest0002 end   *************");
    })

    /**
     * @tc.name resultSet ExcuteSql normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ExcuteSql_0030
     * @tc.desc resultSet ExcuteSql normal test
     */
    it('ExcuteSqlTest0003', 0, async function (done) {
        console.log(TAG + "************* ExcuteSqlTest0003 start *************");
        var u8 = new Uint8Array([3, 4, 5])
        var nameStr = "lisi" + "e".repeat(2000) + "zhangsan"
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = await rdbStore.insert("test", valueBucket)
            expect(1).assertEqual(ret);
        }
        {
            const valueBucket = {
                "name": nameStr,
                "age": 19,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = await rdbStore.insert("test", valueBucket)
            expect(2).assertEqual(ret);
        }
        {
            const valueBucket = {
                "name": nameStr,
                "age": 28,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = await rdbStore.insert("test", valueBucket)
            expect(3).assertEqual(ret);
        }
        {
            let predicates = await new dataRdb.RdbPredicates("test")
            predicates.equalTo("name", nameStr)
            let querySqlPromise = rdbStore.query(predicates)
            querySqlPromise.then(async (resultSet) => {
                expect(2).assertEqual(resultSet.rowCount)
                resultSet.close()
            }).catch((err) => {
                expect(null).assertFail();
            })
            await querySqlPromise
        }
        {
            let executeSqlPromise = rdbStore.executeSql("DELETE FROM test WHERE age = 19 AND name ='" + nameStr + "'")
            executeSqlPromise.then(async () => {
                console.log(TAG + "executeSql done.");
            }).catch((err) => {
                expect(null).assertFail();
            })
            await executeSqlPromise
        }
        {
            let querySqlPromise = rdbStore.querySql("SELECT * FROM test WHERE name ='" + nameStr + "'")
            querySqlPromise.then(async (resultSet) => {
                expect(1).assertEqual(resultSet.rowCount)
                expect(true).assertEqual(resultSet.goToFirstRow())
                const name = resultSet.getString(resultSet.getColumnIndex("name"))
                const age = resultSet.getLong(resultSet.getColumnIndex("age"))
                const salary = resultSet.getDouble(resultSet.getColumnIndex("salary"))
                const blobType = resultSet.getBlob(resultSet.getColumnIndex("blobType"))
                expect(nameStr).assertEqual(name)
                expect(2012).assertEqual(name.length)
                expect(28).assertEqual(age)
                expect(100.5).assertEqual(salary)
                expect(3).assertEqual(blobType[0])
                resultSet.close();
                done();
            }).catch((err) => {
                expect(null).assertFail();
            })
            await querySqlPromise
        }
        console.log(TAG + "************* ExcuteSqlTest0003 end   *************");
    })

    /**
     * @tc.name resultSet ExcuteSql normal test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ExcuteSql_0040
     * @tc.desc resultSet ExcuteSql normal test
     */
    it('ExcuteSqlTest0004', 0, async function (done) {
        console.log(TAG + "************* ExcuteSqlTest0004 start *************");
        var u8 = new Uint8Array([3, 4, 5])
        {
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = await rdbStore.insert("test", valueBucket)
            expect(1).assertEqual(ret);
        }
        {
            const valueBucket = {
                "name": "lisi",
                "age": 19,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = await rdbStore.insert("test", valueBucket)
            expect(2).assertEqual(ret);
        }
        {
            const valueBucket = {
                "name": "lisi",
                "age": 28,
                "salary": 100.5,
                "blobType": u8,
            }
            let ret = await rdbStore.insert("test", valueBucket)
            expect(3).assertEqual(ret);
        }
        await rdbStore.executeSql("DROP TABLE IF EXISTS test")
        done();
        console.log(TAG + "************* ExcuteSqlTest0004 end   *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})