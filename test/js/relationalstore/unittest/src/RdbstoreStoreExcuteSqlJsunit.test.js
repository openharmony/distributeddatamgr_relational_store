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
import data_relationalStore from '@ohos.data.relationalStore'
import ability_featureAbility from '@ohos.ability.featureAbility'
var context = ability_featureAbility.getContext()

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const STORE_CONFIG = {
    name: "ExecuteSqlTest.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
var rdbStore = undefined;

describe('rdbStoreExecuteSqlTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
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
        await data_relationalStore.deleteRdbStore(context, "ExecuteSqlTest.db");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ExecuteSql_0010
     * @tc.name Normal test case of ExecuteSql
     * @tc.desc 1.Insert data
     *          2.ExecuteSql(delete age = "18" OR "20")
     *          3.QuerySql
     */
    it('ExecuteSqlTest0001', 0, async function (done) {
        console.log(TAG + "************* ExecuteSqlTest0001 start *************");
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
        console.log(TAG + "************* ExecuteSqlTest0001 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ExecuteSql_0020
     * @tc.name Normal test case of ExecuteSql
     * @tc.desc 1.Insert data
     *          2.ExecuteSql(delete name = "lisi")
     *          3.QuerySql
     */
    it('ExecuteSqlTest0002', 0, async function (done) {
        console.log(TAG + "************* ExecuteSqlTest0002 start *************");
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
        console.log(TAG + "************* ExecuteSqlTest0002 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ExecuteSql_0030
     * @tc.name Normal test case of ExecuteSql
     * @tc.desc 1.Insert data (param is long string)
     *          2.Query data
     *          3.ExecuteSql (delete age = 19 AND name = nameStr)
     *          4.Query data
     */
    it('ExecuteSqlTest0003', 0, async function (done) {
        console.log(TAG + "************* ExecuteSqlTest0003 start *************");
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
            let predicates = await new data_relationalStore.RdbPredicates("test")
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
        console.log(TAG + "************* ExecuteSqlTest0003 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ExecuteSql_0040
     * @tc.name Normal test case of ExecuteSql, drop table
     * @tc.desc 1.Insert data
     *          2.ExecuteSql (drop table)
     */
    it('ExecuteSqlTest0004', 0, async function (done) {
        console.log(TAG + "************* ExecuteSqlTest0004 start *************");
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
        console.log(TAG + "************* ExecuteSqlTest0004 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ExecuteSql_0050
     * @tc.name Normal test case of executeSql and querySql, PRAGMA user_version
     * @tc.desc 1.Set user_version
     *          2.Get user_version
     */
    it('ExecuteSqlTest0005', 0, async function () {
        console.log(TAG + "************* ExecuteSqlTest0005 start *************");
        // 2 is used to set the store version
        await rdbStore.executeSql("PRAGMA user_version = 2")
        let resultSet = await rdbStore.querySql("PRAGMA user_version");
        resultSet.goToFirstRow();
        expect(2).assertEqual(resultSet.getLong(0))
        resultSet.close();
        console.log(TAG + "************* ExecuteSqlTest0005 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ExecuteSql_0060
     * @tc.name Normal test case of executeSql and querySql, PRAGMA table_info
     * @tc.desc 1.Get table_info
     *          2.Check table_info
     */
    it('ExecuteSqlTest0006', 0, async function () {
        console.log(TAG + "************* ExecuteSqlTest0006 start *************");
        let resultSet = await rdbStore.querySql("PRAGMA table_info(test)");
        resultSet.goToFirstRow();
        expect(0).assertEqual(resultSet.getLong(0))
        expect("id").assertEqual(resultSet.getString(1))
        expect("INTEGER").assertEqual(resultSet.getString(2))
        resultSet.goToNextRow();
        expect(1).assertEqual(resultSet.getLong(0))
        expect("name").assertEqual(resultSet.getString(1))
        expect("TEXT").assertEqual(resultSet.getString(2))
        expect(1).assertEqual(resultSet.getLong(3))
        resultSet.goToNextRow();
        expect(2).assertEqual(resultSet.getLong(0))
        expect("age").assertEqual(resultSet.getString(1))
        expect("INTEGER").assertEqual(resultSet.getString(2))
        resultSet.goToNextRow();
        expect(3).assertEqual(resultSet.getLong(0))
        expect("salary").assertEqual(resultSet.getString(1))
        expect("REAL").assertEqual(resultSet.getString(2))
        resultSet.goToNextRow();
        expect(4).assertEqual(resultSet.getLong(0))
        expect("blobType").assertEqual(resultSet.getString(1))
        expect("BLOB").assertEqual(resultSet.getString(2))
        resultSet.close();
        console.log(TAG + "************* ExecuteSqlTest0006 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_ExecuteSql_0070
     * @tc.name Normal test case of executeSql, if spaces before the sql
     * @tc.desc 1.Set user_version
     *          2.Get user_version
     */
    it('ExecuteSqlTest0007', 0, async function () {
        console.log(TAG + "************* ExecuteSqlTest0007 start *************");
        // 2 is used to set the store version
        await rdbStore.executeSql("   PRAGMA user_version = 2")
        let resultSet = await rdbStore.querySql("PRAGMA user_version");
        resultSet.goToFirstRow();
        expect(2).assertEqual(resultSet.getLong(0))

        await rdbStore.executeSql("\r\nPRAGMA user_version = 3")
        resultSet = await rdbStore.querySql("PRAGMA user_version");
        resultSet.goToFirstRow();
        expect(3).assertEqual(resultSet.getLong(0))
        resultSet.close();
        console.log(TAG + "************* ExecuteSqlTest0007 end   *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})