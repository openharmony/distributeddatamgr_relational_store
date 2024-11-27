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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from "deccjsunit/index"
import relationalStore from '@ohos.data.relationalStore';
import ability_featureAbility from '@ohos.ability.featureAbility'

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const STORE_NAME = "statistics.db"
let rdbStore = undefined;
let context = ability_featureAbility.getContext()
describe('RdbStoreStatisticsTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        const config = {
            'name': STORE_NAME,
            securityLevel: relationalStore.SecurityLevel.S1,
        }
        try {
            rdbStore = await relationalStore.getRdbStore(context, config);
        } catch (err) {
            console.error(TAG + `failed, code:${err.code}, message: ${err.message}`)
            expect().assertFail()
        }
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
        try {
            const CREATE_TABLE_SQL = "CREATE TABLE IF NOT EXISTS test (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";
            await rdbStore.executeSql(CREATE_TABLE_SQL);

            const valueBucket1 = {
                'name': 'zhangsan',
                'age': 18,
                'salary': 25000,
                'blobType': new Uint8Array([1, 2, 3]),
            };
            let rowId = await rdbStore.insert('test', valueBucket1);
            expect(1).assertEqual(rowId);
        } catch (err) {
            console.error(TAG + `failed2, code:${err.code}, message: ${err.message}`)
            expect().assertFail()
        }
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
        try {
            rdbStore.off('statistics')
        } catch (err) {
            console.error(TAG + `unRegister fail3, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
        }
        await rdbStore.executeSql("drop table test");
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        rdbStore = null
        await relationalStore.deleteRdbStore(context, STORE_NAME);
    })

    console.info(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name Normal case for Statistics insert data execution time
     * @tc.number testRdbStoreStatistics0001
     * @tc.desc 1. Register callback for statistics
     *          2. Insert data
     *          3. UnRegister callback
     */
    it('testRdbStoreStatistics0001', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreStatistics0001 start *************");
        try {
            rdbStore.on('statistics', (SqlExeInfo) => {
                expect('INSERT INTO test(age,blobType,name,salary) VALUES (?,?,?,?)').assertEqual(SqlExeInfo.sql[0]);
                done()
            })
        } catch (err) {
            console.error(TAG + `on statistics fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done()
        }

        try {
            const valueBucket1 = {
                'name': 'zhangsan',
                'age': 18,
                'salary': 25000,
                'blobType': new Uint8Array([1, 2, 3]),
            };
            let rowId = await rdbStore.insert('test', valueBucket1);
            expect(2).assertEqual(rowId);
        } catch (error) {
            console.error(TAG + `insert2 fail, code:${error.code}, message: ${error.message}`);
            expect().assertFail();
            done();
        }
        console.info(TAG + "************* testRdbStoreStatistics0001 end *************");
    })

    /**
     * @tc.name Normal case for Statistics update data execution time
     * @tc.number testRdbStoreStatistics0002
     * @tc.desc 1. Register callback for statistics
     *          2. Update data
     *          3. UnRegister callback
     */
    it('testRdbStoreStatistics0002', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreStatistics0002 start *************");
        try {
            rdbStore.on('statistics', (SqlExeInfo) => {
                expect('UPDATE test SET age=?,blobType=?,name=?,salary=? WHERE id = ? ').assertEqual(SqlExeInfo.sql[0]);
                done()
            })
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done()
        }

        try {
            const valueBucket = {
                'name': 'lisi',
                'age': 18,
                'salary': 30000,
                'blobType': new Uint8Array([1, 2, 3]),
            };
            let predicates = new relationalStore.RdbPredicates('test');
            predicates.equalTo('id', 1);
            let rowId = await rdbStore.update(valueBucket, predicates);
            expect(1).assertEqual(rowId);
        } catch (error) {
            console.error(TAG + `update fail, code:${error.code}, message: ${error.message}`);
            expect().assertFail();
            done()
        }
        console.info(TAG + "************* testRdbStoreStatistics0002 end *************");
    })

    /**
     * @tc.name Normal case for Statistics delete data execution time
     * @tc.number testRdbStoreStatistics0003
     * @tc.desc 1. Register callback for statistics
     *          2. Delete data
     *          3. UnRegister callback
     */
    it('testRdbStoreStatistics0003', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreStatistics0003 start *************");
        try {
            rdbStore.on('statistics', (SqlExeInfo) => {
                expect('DELETE FROM test').assertEqual(SqlExeInfo.sql[0]);
                done()
            })
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done()
        }

        try {
            let predicates = new relationalStore.RdbPredicates('test');
            let rowId = await rdbStore.delete(predicates);
            expect(1).assertEqual(rowId);
        } catch (error) {
            console.error(TAG + `delete fail, code:${error.code}, message: ${error.message}`);
            expect().assertFail();
            done()
        }
        console.info(TAG + "************* testRdbStoreStatistics0003 end *************");
    })

    /**
     * @tc.name Normal case for Statistics batchInsert data execution time
     * @tc.number testRdbStoreStatistics0004
     * @tc.desc 1. Register callback for statistics
     *          2. batchInsert data
     *          3. UnRegister callback
     */
    it('testRdbStoreStatistics0004', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreStatistics0004 start *************");
        try {
            rdbStore.on('statistics', (SqlExeInfo) => {
                expect(SqlExeInfo.sql.length).assertEqual(1);
                done()
            })
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done()
        }

        try {
            let u8 = new Uint8Array([1, 2, 3])
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": u8,
            }
            let valueBucketArray = new Array();
            for (let i = 0; i < 1000; i++) {
                valueBucketArray.push(valueBucket);
            }
            let rowId = await rdbStore.batchInsert("test", valueBucketArray);
            expect(1000).assertEqual(rowId);
        } catch (error) {
            console.error(TAG + `insert fail, code:${error.code}, message: ${error.message}`);
            expect().assertFail();
            done();
        }
        console.info(TAG + "************* testRdbStoreStatistics0004 end *************");
    })

    /**
     * @tc.name Normal case for Statistics insert data execution time to new table
     * @tc.number testRdbStoreStatistics0005
     * @tc.desc 1. Register callback for statistics
     *          2. Create table test1
     *          3. Insert data into table test1
     *          4. UnRegister callback
     */
    it('testRdbStoreStatistics0005', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreStatistics0005 start *************");
        const CREATE_TABLE_SQL = "CREATE TABLE IF NOT EXISTS test1 (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";
        try {
            rdbStore.on('statistics', (SqlExeInfo) => {
                expect(CREATE_TABLE_SQL).assertEqual(SqlExeInfo.sql[0]);
                done()
            })
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done();
        }
        try {
            await rdbStore.executeSql(CREATE_TABLE_SQL);
            const valueBucket = {
                "name": "zhangsan",
                "age": 18,
                "salary": 100.5,
                "blobType": new Uint8Array([1, 2, 3]),
            }
            let rowId = await rdbStore.insert("test1", valueBucket);
            expect(1).assertEqual(rowId);
            await rdbStore.executeSql("drop table test1");
        } catch (error) {
            console.error(TAG + `insert fail, code:${error.code}, message: ${error.message}`);
            expect().assertFail();
            done();
        }
        console.info(TAG + "************* testRdbStoreStatistics0005 end *************");
    })

    /**
     * @tc.name AbNormal case for failed to insert
     * @tc.number testRdbStoreStatistics0006
     * @tc.desc 1. Register callback for statistics
     *          2. Failed to insert data into table test
     *          3. UnRegister callback
     */
    it('testRdbStoreStatistics0006', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreStatistics0006 start *************");
        try {
            rdbStore.on('statistics', (SqlExeInfo) => {
                expect().assertFail();
                done();
            })
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done();
        }

        try {
            const valueBucket = {
                "age": 18,
                "salary": 100.5,
                "blobType": new Uint8Array([1, 2, 3]),
            }
            await rdbStore.insert("test", valueBucket);
            expect().assertFail();
        } catch (error) {
            expect(14800032).assertEqual(error.code);
            console.error(TAG + `insert fail, code:${error.code}, message: ${error.message}`);
            done();
        }
        console.info(TAG + "************* testRdbStoreStatistics0006 end *************");
    })

    /**
     * @tc.name AbNormal case for function on, if args is invalid
     * @tc.number testRdbStoreStatistics0007
     * @tc.desc 1.Register callback for statistics, event is invalid
     */
    it('testRdbStoreStatistics0007', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreStatistics0007 start *************");
        try {
            rdbStore.on('', (SqlExeInfo) => {
            })
            expect().assertFail();
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect('401').assertEqual(err.code);
            done();
        }
        console.info(TAG + "************* testRdbStoreStatistics0007 end *************");
    })

    /**
     * @tc.name AbNormal case for function off, if args is invalid
     * @tc.number testRdbStoreStatistics0008
     * @tc.desc 1.Register callback statistics, event is invalid
     */
    it('testRdbStoreStatistics0008', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreStatistics0008 start *************");
        try {
            rdbStore.off('', (SqlExeInfo) => {
            })
            expect().assertFail();
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect('401').assertEqual(err.code);
            done();
        }
        console.info(TAG + "************* testRdbStoreStatistics0008 end *************");
    })

    /**
     * @tc.name Normal case for multi observer
     * @tc.number testRdbStoreStatistics0009
     * @tc.desc 1. Register observer1 and observer2 for local database
     *          2. Insert data into table test
     *          3. UnRegister observer1 and observer2
     */
    it('testRdbStoreStatistics0009', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreStatistics0009 start *************");
        function observer1(SqlExeInfo) {
            console.info(TAG + "observer1");
            expect().assertFail();
        };
        function observer2(SqlExeInfo) {
            console.info(TAG + "observer2");
            expect('INSERT INTO test(age,blobType,name,salary) VALUES (?,?,?,?)').assertEqual(SqlExeInfo.sql[SqlExeInfo.sql.length - 1]);
            done();
        };
        try {
            rdbStore.on('statistics', observer1);
            rdbStore.on('statistics', observer2);
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done();
        }
        try {
            rdbStore.off('statistics', observer1);
        } catch (err) {
            expect().assertFail();
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            done();
        }
        try {
            const valueBucket = {
                'name': 'liSi',
                "age": 18,
                "salary": 100.5,
                "blobType": new Uint8Array([1, 2, 3]),
            }
            let rowId = await rdbStore.insert("test", valueBucket);
            expect(2).assertEqual(rowId);
        } catch (error) {
            expect().assertFail();
            console.error(TAG + `insert fail, code:${error.code}, message: ${error.message}`);
            done();
        }
        console.info(TAG + "************* testRdbStoreStatistics0009 end *************");
    })

    /**
     * @tc.name Normal case for multi observer
     * @tc.number testRdbStoreStatistics0010
     * @tc.desc 1. Register observer1 and observer2 for local database
     *          2. Insert data into table test
     *          3. UnRegister observer1 and observer2
     */
    it('testRdbStoreStatistics0010', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreStatistics0010 start *************");
        function observer1(SqlExeInfo) {
            console.info(TAG + "observer1");
            expect('INSERT INTO test(age,blobType,name,salary) VALUES (?,?,?,?)').assertEqual(SqlExeInfo.sql[SqlExeInfo.sql.length - 1]);
        };
        function observer2(SqlExeInfo) {
            console.info(TAG + "observer2");
            expect('INSERT INTO test(age,blobType,name,salary) VALUES (?,?,?,?)').assertEqual(SqlExeInfo.sql[SqlExeInfo.sql.length - 1]);
            done();
        };
        try {
            rdbStore.on('statistics', observer1);
            rdbStore.on('statistics', observer2);
        } catch (err) {
            console.error(TAG + `register fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done();
        }
        try {
            const valueBucket = {
                'name': 'liSi',
                "age": 18,
                "salary": 100.5,
                "blobType": new Uint8Array([1, 2, 3]),
            }
            let rowId = await rdbStore.insert("test", valueBucket);
            expect(2).assertEqual(rowId);
        } catch (error) {
            expect().assertFail();
            console.error(TAG + `insert fail, code:${error.code}, message: ${error.message}`);
            done();
        }
        console.info(TAG + "************* testRdbStoreStatistics0010 end *************");
    })

    /**
     * @tc.name Normal case for multi observer
     * @tc.number testRdbStoreStatistics0012
     * @tc.desc 1. Register observer1  local database
     *          2. query data into table test
     *
     */
    it('testRdbStoreStatistics0011', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreStatistics0011 start *************");
        try {
            rdbStore.on('statistics', (SqlExeInfo) => {
                expect('select * from test').assertEqual(SqlExeInfo.sql[0]);
                done();
            })
        } catch (err) {
            console.error(TAG + `on statistics fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done();
        }
        await rdbStore.queryByStep("select * from test");
        console.info(TAG + "************* testRdbStoreStatistics0011 end *************");
    })

    /**
     * @tc.name Normal case for multi observer
     * @tc.number testRdbStoreStatistics0012
     * @tc.desc 1. Register observer1  local database
     *          2. query data into table test
     *
     */
    it('testRdbStoreStatistics0012', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreStatistics0012 start *************");
        try {
            rdbStore.on('statistics', (SqlExeInfo) => {
                expect('SELECT * FROM test').assertEqual(SqlExeInfo.sql[0]);
                done();
            })
        } catch (err) {
            console.error(TAG + `on statistics fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done();
        }
        let predicates = new relationalStore.RdbPredicates('test');
        await rdbStore.query(predicates);
        console.info(TAG + "************* testRdbStoreStatistics0012 end *************");
    })

    /**
     * @tc.name Normal case for multi observer
     * @tc.number testRdbStoreStatistics0012
     * @tc.desc 1. Register observer1  local database
     *          2. query data into table test
     *
     */
    it('testRdbStoreStatistics0013', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreStatistics0013 start *************");
        try {
            rdbStore.on('statistics', (SqlExeInfo) => {
                expect('select * from test').assertEqual(SqlExeInfo.sql[0]);
                done();
            })
        } catch (err) {
            console.error(TAG + `on statistics fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done();
        }

        await rdbStore.querySql("select * from test");
        console.info(TAG + "************* testRdbStoreStatistics0013 end *************");
    })

    /**
     * @tc.name Normal case for multi observer
     * @tc.number testRdbStoreStatistics0012
     * @tc.desc 1. Register observer1  local database
     *          2. query data into table test
     *
     */
    it('testRdbStoreStatistics0014', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreStatistics0014 start *************");
        try {
            rdbStore.on('statistics', (SqlExeInfo) => {
                expect('PRAGMA quick_check').assertEqual(SqlExeInfo.sql[0]);
                done();
            })
        } catch (err) {
            console.error(TAG + `on statistics fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done();
        }
        let ret = await rdbStore.execute("PRAGMA quick_check");
        console.info(TAG + "************* testRdbStoreStatistics0014 end *************");
    })

    /**
     * @tc.name Normal case for Statistics query data execution time
     * @tc.number testRdbStoreStatistics0016
     * @tc.desc 1. Register callback for statistics
     *          2. query data into table test
     *
     */
    it('testRdbStoreStatistics0015', 0, async function (done) {
        console.info(TAG + "************* testRdbStoreStatistics0016 start *************");
        try {
            rdbStore.on('statistics', (SqlExeInfo) => {
                expect('with test1 as (select * from test) select * from test').assertEqual(SqlExeInfo.sql[0]);
                done();
            })
        } catch (err) {
            console.error(TAG + `on statistics fail, code:${err.code}, message: ${err.message}`);
            expect().assertFail();
            done();
        }
        let ret = await rdbStore.executeSql("with test1 as (select * from test) select * from test");
        console.info(TAG + "************* testRdbStoreStatistics0015 end *************");
    })

    /**
     * @tc.name AbNormal case for Statistics when store is closed
     * @tc.number testRdbStoreStatistics0016
     * @tc.desc 1. close store
     *          2. Register callback for statistics
     *
     */
    it('testRdbStoreStatistics0016', 0, async function () {
        console.info(TAG + "************* testRdbStoreStatistics0016 start *************");
        await rdbStore.close().then(() => {
            console.info(`close succeeded`);
        }).catch((err) => {
            console.error(`close failed, code is ${err.code},message is ${err.message}`);
        })

        try {
            rdbStore.on('statistics', (SqlExeInfo) => {
            })
        } catch (err) {
            console.error(TAG + `on statistics fail, code:${err.code}, message: ${err.message}`);
            expect('14800014').assertEqual(err.code);
        }
        console.info(TAG + "************* testRdbStoreStatistics0016 end *************");
    })
    console.info(TAG + "*************Unit Test End*************");
})