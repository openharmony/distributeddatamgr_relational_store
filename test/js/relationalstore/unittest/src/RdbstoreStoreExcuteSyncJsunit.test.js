/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
import relationalStore from '@ohos.data.relationalStore'
import ability_featureAbility from '@ohos.ability.featureAbility'

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"

let context = ability_featureAbility.getContext()
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)";
const CREATE_TABLE_TEST2 = "CREATE TABLE IF NOT EXISTS test2 (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)";
const TEST_TABLE_IS_EXIST = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='test2'";

const STORE_CONFIG = {
    name: "executeTest.db",
    securityLevel: relationalStore.SecurityLevel.S1,
}

let rdbStore = undefined;

describe('rdbStoreExcuteTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
    })

    beforeEach(async function () {
        await rdbStore.executeSql(CREATE_TABLE_TEST);
        console.info(TAG + 'beforeEach')
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
        await rdbStore.executeSql("DROP TABLE IF EXISTS test")
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        await relationalStore.deleteRdbStore(context, STORE_CONFIG);
        rdbStore = null
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Execute_0001
     * @tc.name Normal test case of Execute, check integrity for store
     * @tc.desc 1. Execute sql: PRAGMA integrity_check
     *          2. Check returned value
     */
    it('testSyncExecute0001', 0, async function (done) {
        console.info(TAG + "************* testSyncExecute0001 start *************");
        try {
            let ret = rdbStore.executeSync("PRAGMA integrity_check");
            expect("ok").assertEqual(ret);
        } catch (err) {
            expect(null).assertFail();
            console.error(`integrity_check failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testSyncExecute0001 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Execute_0002
     * @tc.name Normal test case of Execute, check integrity for store
     * @tc.desc 1. Execute sql: PRAGMA quick_check
     *          2. Check returned value
     */
    it('testSyncExecute0002', 0, async function (done) {
        console.info(TAG + "************* testSyncExecute0002 start *************");
        try {
            let ret = rdbStore.executeSync("PRAGMA quick_check");
            expect("ok").assertEqual(ret);
        } catch (err) {
            expect(null).assertFail();
            console.error(`integrity_check failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testSyncExecute0002 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Execute_0003
     * @tc.name Normal test case of Execute, get user_version of store
     * @tc.desc 1. Execute sql: PRAGMA user_version
     *          2. Check returned value
     */
    it('testSyncExecute0003', 0, async function (done) {
        console.info(TAG + "************* testSyncExecute0003 start *************");
        try {
            // set user_version as 5
            rdbStore.version = 5;
            let ret = rdbStore.executeSync("PRAGMA user_version");
            // get user_version 5
            expect(5).assertEqual(ret);
        } catch (err) {
            expect(null).assertFail();
            console.error(`get user_version failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testSyncExecute0003 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Execute_0004
     * @tc.name AbNormal test case of Execute, execute select sql
     * @tc.desc 1. Execute select sql
     *          2. Check returned value
     */
    it('testSyncExecute0004', 0, async function (done) {
        console.info(TAG + "************* testSyncExecute0004 start *************");
        try {
            rdbStore.executeSync("SELECT * FROM test");
            expect(null).assertFail();
        } catch (err) {
            // 14800000: inner error
            expect(14800000).assertEqual(err.code);
            console.error(`execute select sql failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testSyncExecute0004 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Execute_0005
     * @tc.name Normal test case of Execute, execute sql for inserting data
     * @tc.desc 1. Execute insert sql
     *          2. Check returned value
     */
    it('testSyncExecute0005', 0, async function (done) {
        console.info(TAG + "************* testSyncExecute0005 start *************");
        try {
            let ret = rdbStore.executeSync("INSERT INTO test(name, age, salary) VALUES ('tt', 28, 50000)");
            // 1 represent that the last data is inserted in the first row
            expect(1).assertEqual(ret);
        } catch (err) {
            expect(null).assertFail();
            console.error(`execute select sql failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testSyncExecute0005 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Execute_0006
     * @tc.name Normal test case of Execute, execute sql for inserting data
     * @tc.desc 1. Execute insert sql
     *          2. Check returned value
     */
    it('testSyncExecute0006', 0, async function (done) {
        console.info(TAG + "************* testSyncExecute0006 start *************");
        try {
            let ret = rdbStore.executeSync("INSERT INTO test(name, age, salary) VALUES (?, ?, ?)", ['tt', 28, 50000]);
            // 1 represent that the last data is inserted in the first row
            expect(1).assertEqual(ret);
        } catch (err) {
            expect(null).assertFail();
            console.error(`execute insert sql failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testSyncExecute0006 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Execute_0007
     * @tc.name Normal test case of Execute, execute sql for batch insert data
     * @tc.desc 1. Execute batch insert sql
     *          2. Check returned value
     */
    it('testSyncExecute0007', 0, async function (done) {
        console.info(TAG + "************* testSyncExecute0007 start *************");
        try {
            let ret = rdbStore.executeSync("INSERT INTO test(name, age, salary) VALUES (?, ?, ?), (?, ? ,?)",
                ['tt', 28, 50000, 'ttt', 278, 500800]);
            // 2 represent that the last data is inserted in the second row
            expect(2).assertEqual(ret);
        } catch (err) {
            expect(null).assertFail();
            console.error(`execute insert sql failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testSyncExecute0007 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Execute_0008
     * @tc.name Normal test case of Execute, execute sql for updating data
     * @tc.desc 1. Execute update sql
     *          2. Check returned value
     */
    it('testSyncExecute0008', 0, async function (done) {
        console.info(TAG + "************* testSyncExecute0008 start *************");
        try {
            let ret = rdbStore.executeSync("INSERT INTO test(name, age, salary) VALUES (?, ?, ?), (?, ? ,?)",
                ['tt', 28, 50000, 'ttt', 278, 500800]);
            // 2 represent that the last data is inserted in the second row
            expect(2).assertEqual(ret);

            ret = rdbStore.executeSync("UPDATE test SET name='dd' WHERE id = 1");
            // 1 represent that effected row id
            expect(1).assertEqual(ret);
        } catch (err) {
            expect(null).assertFail();
            console.error(`execute update sql failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testSyncExecute0008 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Execute_0009
     * @tc.name Normal test case of Execute, execute sql for deleting data
     * @tc.desc 1. Execute delete sql
     *          2. Check returned value
     */
    it('testSyncExecute0009', 0, async function (done) {
        console.info(TAG + "************* testSyncExecute0009 start *************");
        try {
            let ret = rdbStore.executeSync("INSERT INTO test(name, age, salary) VALUES (?, ?, ?), (?, ? ,?)",
                ['tt', 28, 50000, 'ttt', 278, 500800]);
            // 2 represent that the last data is inserted in the second row
            expect(2).assertEqual(ret);

            ret = rdbStore.executeSync("DELETE FROM test");
            // 2 represent that effected row id
            expect(2).assertEqual(ret);
        } catch (err) {
            expect(null).assertFail();
            console.error(`execute delete sql failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testSyncExecute0009 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Execute_0010
     * @tc.name AbNormal test case of Execute, execute sql for attaching database and transaction
     * @tc.desc 1. Execute attach sql
     *          2. Execute detach sql
     *          3. Execute transaction sql
     *          4. Check returned value
     */
    it('testSyncExecute0010', 0, async function (done) {
        console.info(TAG + "************* testSyncExecute0010 start *************");
        try {
            rdbStore.executeSync("ATTACH DATABASE 'execute_attach_test.db' AS 'attach.db'");
            expect(null).assertFail();
        } catch (err) {
            // 14800000: inner error
            expect(14800000).assertEqual(err.code);
            console.error(`execute attach sql failed, code:${err.code}, message: ${err.message}`);
        }

        try {
            rdbStore.executeSync("DETACH DATABASE 'attach.db'");
            expect(null).assertFail();
        } catch (err) {
            // 14800000: inner error
            expect(14800000).assertEqual(err.code);
            console.error(`execute detach sql failed, code:${err.code}, message: ${err.message}`);
        }

        try {
            rdbStore.executeSync("BEGIN TRANSACTION");
            expect(null).assertFail();
        } catch (err) {
            // 14800000: inner error
            expect(14800000).assertEqual(err.code);
            console.error(`execute begin transaction sql failed, code:${err.code}, message: ${err.message}`);
        }

        try {
            rdbStore.executeSync("COMMIT");
            expect(null).assertFail();
        } catch (err) {
            // 14800000: inner error
            expect(14800000).assertEqual(err.code);
            console.error(`execute commit sql failed, code:${err.code}, message: ${err.message}`);
        }

        try {
            rdbStore.executeSync("ROLLBACK");
            expect(null).assertFail();
        } catch (err) {
            // 14800000: inner error
            expect(14800000).assertEqual(err.code);
            console.error(`execute rollback sql failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testSyncExecute0010 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Execute_0011
     * @tc.name Normal test case of Execute, execute DDL sql for creating and dropping table
     * @tc.desc 1. Create table
     *          2. Drop table
     */
    it('testSyncExecute0011', 0, async function (done) {
        console.info(TAG + "************* testSyncExecute0011 start *************");
        try {
            let ret = rdbStore.executeSync(CREATE_TABLE_TEST2);
            expect(null).assertEqual(ret);
            let resultSet = await rdbStore.querySql(TEST_TABLE_IS_EXIST);
            resultSet.goToFirstRow();
            // 0 represent that get count of table test2 in the first row, 1 represent that the table exists
            expect(1).assertEqual(resultSet.getLong(0))
            resultSet.close();

            rdbStore.executeSync("DROP TABLE test2");
            resultSet = await rdbStore.querySql(TEST_TABLE_IS_EXIST);
            resultSet.goToFirstRow();
            // 0 represent that get count of table test2 in the first row, and the table test2 does not exist
            expect(0).assertEqual(resultSet.getLong(0))
            resultSet.close();
        } catch (err) {
            expect(null).assertFail();
            console.error(`execute ddl sql failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testSyncExecute0011 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Execute_0012
     * @tc.name Normal test case of Execute, execute sql for creating table and insert, query data
     * @tc.desc 1. Create table
     *          2. Insert data
     *          3. Query data
     *          4. Drop table
     */
    it('testSyncExecute0012', 0, async function (done) {
        console.info(TAG + "************* testSyncExecute0012 start *************");
        try {
            rdbStore.executeSync(CREATE_TABLE_TEST2);

            let ret = rdbStore.executeSync(
                "INSERT INTO test2(name, age, salary) VALUES (?, ?, ?)", ['tt', 28, 50000]);
            // 1 represent that the last data is inserted in the first row
            expect(1).assertEqual(ret);

            let resultSet = await rdbStore.querySql("SELECT * FROM test2");
            // 1 represent that the row count of resultSet
            expect(1).assertEqual(resultSet.rowCount)
            resultSet.close();
        } catch (err) {
            expect(null).assertFail();
            console.error(`execute sql failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testSyncExecute0012 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Execute_0013
     * @tc.name AbNormal test case of Execute, if sql is ""
     * @tc.desc 1. Execute sql: ""
     *          2. Check returned value
     */
    it('testSyncExecute0013', 0, async function (done) {
        console.info(TAG + "************* testSyncExecute0013 start *************");
        try {
            rdbStore.executeSync("");
            expect(null).assertFail();
        } catch (err) {
            expect("401").assertEqual(err.code);
            console.error(`execute attach sql failed, code:${err.code}, message: ${err.message}`);
        }

        done();
        console.info(TAG + "************* testSyncExecute0013 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Execute_0014
     * @tc.name AbNormal test case of Execute, execute sql insert data and if args is []
     * @tc.desc 1. Insert data
     *          2. Check returned value
     */
    it('testSyncExecute0014', 0, async function (done) {
        console.info(TAG + "************* testSyncExecute0014 start *************");
        try {
            rdbStore.executeSync("INSERT INTO test (name, age, salary) VALUES (?, ?, ?)");
            expect(null).assertFail();
        } catch (err) {
            expect(14800000).assertEqual(err.code);
            console.error(`insert data failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testSyncExecute0014 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Execute_0015
     * @tc.name AbNormal test case of Execute, if sql is null or undefined
     * @tc.desc 1. Insert data and set sql as null or undefined
     *          2. Check returned value
     */
    it('testSyncExecute0015', 0, async function (done) {
        console.info(TAG + "************* testSyncExecute0015 start *************");
        try {
            rdbStore.executeSync(null);
            expect(null).assertFail();
        } catch (err) {
            expect('401').assertEqual(err.code);
            console.error(`insert data failed, code:${err.code}, message: ${err.message}`);
        }

        try {
            rdbStore.executeSync(undefined);
            expect(null).assertFail();
        } catch (err) {
            expect('401').assertEqual(err.code);
            console.error(`insert data failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testSyncExecute0015 end   *************");
    })

    /**
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Execute_0016
     * @tc.name AbNormal test case of Execute, if args is null or undefined
     * @tc.desc 1. Insert data and set args as null or undefined
     *          2. Check returned value
     */
    it('testSyncExecute0016', 0, async function (done) {
        console.info(TAG + "************* testSyncExecute0016 start *************");
        try {
            rdbStore.executeSync("INSERT INTO test (name, age, salary) VALUES (?, ?, ?)", null);
            expect(null).assertFail();
        } catch (err) {
            expect(14800000).assertEqual(err.code);
            console.error(`insert data failed, code:${err.code}, message: ${err.message}`);
        }

        try {
            rdbStore.executeSync("INSERT INTO test (name, age, salary) VALUES (?, ?, ?)", undefined);
            expect(null).assertFail();
        } catch (err) {
            expect(14800000).assertEqual(err.code);
            console.error(`insert data failed, code:${err.code}, message: ${err.message}`);
        }
        done();
        console.info(TAG + "************* testSyncExecute0016 end   *************");
    })

    console.info(TAG + "*************Unit Test End*************");
})