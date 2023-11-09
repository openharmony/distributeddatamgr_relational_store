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
import ability_featureAbility from '@ohos.ability.featureAbility'

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const STORE_NAME = "distributed_rdb.db"
const E_NOT_SUPPORTED = 801;
var rdbStore = undefined;
var context = ability_featureAbility.getContext()

describe('rdbStoreDistributedTest', function () {
    beforeAll(async function (done) {
        console.info(TAG + 'beforeAll')
        const config = {
            "name": STORE_NAME,
            securityLevel: data_relationalStore.SecurityLevel.S1,
        }
        try {
            rdbStore = await data_relationalStore.getRdbStore(context, config);
            console.log(TAG + "create rdb store success")
            expect(rdbStore).assertEqual(rdbStore)
            let sqlStatement = "CREATE TABLE IF NOT EXISTS employee (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "name TEXT NOT NULL," +
                "age INTEGER)"
            try {
                await rdbStore.executeSql(sqlStatement, null)
                console.log(TAG + "create table employee success")
            } catch (err) {
                console.log(TAG + "create table employee failed")
                expect(null).assertFail()
            }

            sqlStatement = "CREATE TABLE IF NOT EXISTS product (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "name TEXT NOT NULL," +
                "price REAL," +
                "vendor INTEGER," +
                "describe TEXT)"
            try {
                await rdbStore.executeSql(sqlStatement, null)
                console.log(TAG + "create table product success")
                done()
            } catch (err) {
                console.log(TAG + "create table product failed")
                expect(null).assertFail()
            }
        } catch (err) {
            console.log(TAG + "create rdb store failed")
            expect(null).assertFail()
        }
        done()
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        rdbStore = null
        await data_relationalStore.deleteRdbStore(context, STORE_NAME);
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name set_distributed_table_none_table
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_002
     * @tc.desc rdb set distributed table using none table as argment
     */
    it('testRdbStoreDistributed0002', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed002 start *************");
        try {
            await rdbStore.setDistributedTables([])
            console.log(TAG + "set none to be distributed table success");
            expect(rdbStore).assertEqual(rdbStore)
        } catch (err) {
            console.log(TAG + `set none to be distributed table failed, err is ${err.code}.`);
            expect(E_NOT_SUPPORTED).assertEqual(err.code);
        }
        done()
        console.log(TAG + "************* testRdbStoreDistributed002 end *************");
    })

    /**
     * @tc.name set distributed table using one table name
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_003
     * @tc.desc set distributed table using one table name
     */
    it('testRdbStoreDistributed0003', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed003 start *************");
        try {
            await rdbStore.setDistributedTables(['employee'])
            console.log(TAG + "set employee to be distributed table success");
            expect(rdbStore).assertEqual(rdbStore)
        } catch (err) {
            console.log(TAG + `set employee to be distributed table failed, err is ${err.code}.`);
            expect(E_NOT_SUPPORTED).assertEqual(err.code);
        }
        done()
        console.log(TAG + "************* testRdbStoreDistributed003 end *************");
    })

    /**
     * @tc.name set distributed table using two table name
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_004
     * @tc.desc set distributed table using two table name
     */
    it('testRdbStoreDistributed0004', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed004 start *************");
        try {
            await rdbStore.setDistributedTables(['employee', 'product'])
            console.log(TAG + "set employee and product to be distributed table success");
            expect(rdbStore).assertEqual(rdbStore)
        } catch (err) {
            console.log(TAG + `set employee and product to be distributed table failed, err is ${err.code}.`);
            expect(E_NOT_SUPPORTED).assertEqual(err.code);
        }
        done()
        console.log(TAG + "************* testRdbStoreDistributed004 end *************");
    })

    /**
     * @tc.name insert record after setting distributed table
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_005
     * @tc.desc insert record after setting distributed table
     */
    it('testRdbStoreDistributed0005', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed005 start *************");
        const record = {
            "name": "Jim",
            "age": 20,
        }
        try {
            let rowId = await rdbStore.insert("employee", record)
            console.log(TAG + "insert one record success " + rowId)
            expect(1).assertEqual(rowId)
        } catch (err) {
            console.log(TAG + "insert one record failed");
            expect(null).assertFail();
        }
        done()
        console.log(TAG + "************* testRdbStoreDistributed005 end *************");
    })

    /**
     * @tc.name update record after setting distributed table
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_006
     * @tc.desc update record after setting distributed table
     */
    it('testRdbStoreDistributed0006', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed006 start *************");
        const record = {
            "name": "Jim",
            "age": 30,
        }
        try {
            let predicate = new data_relationalStore.RdbPredicates("employee");
            predicate.equalTo("id", 1);
            try {
                let rowId = await rdbStore.update(record, predicate);
                console.log(TAG + "update one record success " + rowId)
                expect(1).assertEqual(rowId)
            } catch (err) {
                console.log(TAG + "update one record failed");
                expect(null).assertFail();
            }
        } catch (err) {
            console.log(TAG + "construct predicate failed");
            expect(null).assertFail();
        }
        done()
        console.log(TAG + "************* testRdbStoreDistributed006 end *************");
    })

    /**
     * @tc.name query record after setting distributed table
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_007
     * @tc.desc query record after setting distributed table
     */
    it('testRdbStoreDistributed0007', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0007 start *************");
        try {
            let predicates = new data_relationalStore.RdbPredicates("employee")
            let resultSet = await rdbStore.query(predicates)
            try {
                console.log(TAG + "product resultSet query done");
                expect(true).assertEqual(resultSet.goToFirstRow())
                const id = await resultSet.getLong(resultSet.getColumnIndex("id"))
                const name = await resultSet.getString(resultSet.getColumnIndex("name"))
                const age = await resultSet.getLong(resultSet.getColumnIndex("age"))

                await expect(1).assertEqual(id);
                await expect("Jim").assertEqual(name);
                await expect(30).assertEqual(age);
                resultSet.close();
                expect(true).assertEqual(resultSet.isClosed)
            } catch (e) {
                console.log(TAG + "result get value failed")
                expect(null).assertFail();
            }
        } catch (err) {
            console.log("query failed");
            expect(null).assertFail();
        }
        done();
        console.log(TAG + "************* testRdbStoreDistributed0007 end *************");
    })

    /**
     * @tc.name delete record after setting distributed table
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_008
     * @tc.desc delete record after setting distributed table
     */
    it('testRdbStoreDistributed0008', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0008 start *************");
        let predicates = new data_relationalStore.RdbPredicates("employee")
        try {
            let number = await rdbStore.delete(predicates)
            console.log(TAG + "employee Delete done: " + number)
            expect(1).assertEqual(number)
        } catch (err) {
            console.log(TAG + "delete record failed");
            expect(null).assertFail()
        }
        done();
        console.log(TAG + "************* testRdbStoreDistributed0008 end *************");
    })

    /**
     * @tc.name predicates inDevice
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_009
     * @tc.desc predicates inDevice
     */
    it('testRdbStoreDistributed0009', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0009 start *************");
        let predicates = new data_relationalStore.RdbPredicates("employee")
        try {
            predicates = predicates.inDevices(["1234567890"]);
            console.log(TAG + "inDevices success");
            expect(predicates).assertEqual(predicates);
        } catch (err) {
            console.log(TAG + "inDevices failed");
            expect(null).assertFail();
        }
        done();
        console.log(TAG + "************* testRdbStoreDistributed0009 end *************");
    })

    /**
     * @tc.name predicates inAllDevices
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_010
     * @tc.desc predicates inAllDevices
     */
    it('testRdbStoreDistributed0010', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0010 start *************");
        let predicates = new data_relationalStore.RdbPredicates("employee")
        try {
            predicates = predicates.inAllDevices();
            console.log(TAG + "inAllDevices success");
            expect(predicates).assertEqual(predicates);
        } catch (err) {
            console.log(TAG + "inAllDevices failed");
            expect(null).assertFail();
        }
        done();
        console.log(TAG + "************* testRdbStoreDistributed0010 end *************");
    })

    /**
     * @tc.name sync test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_011
     * @tc.desc sync test
     */
    it('testRdbStoreDistributed0011', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0011 start *************");
        let predicates = new data_relationalStore.RdbPredicates("employee")
        predicates = predicates.inDevices(["12345678abcd"]);
        rdbStore.sync(data_relationalStore.SyncMode.SYNC_MODE_PUSH, predicates);
        console.log(TAG + "sync push success");
        expect(rdbStore).assertEqual(rdbStore);
        rdbStore.sync(data_relationalStore.SyncMode.SYNC_MODE_PULL, predicates);
        console.log(TAG + "sync pull success");
        expect(rdbStore).assertEqual(rdbStore);
        done();
        console.log(TAG + "************* testRdbStoreDistributed0011 end *************");
    })

    /**
     * @tc.name subscribe test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_012
     * @tc.desc subscribe test
     */
    it('testRdbStoreDistributed0012', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0012 start *************");
        rdbStore.on("dataChange", data_relationalStore.SubscribeType.SUBSCRIBE_TYPE_REMOTE, (device) => {
            console.log(TAG + device + " dataChange");
        });
        console.log(TAG + "on dataChange success");
        expect(rdbStore).assertEqual(rdbStore);
        done()
        console.log(TAG + "************* testRdbStoreDistributed0012 end *************");
    })

    /**
     * @tc.name subscribe test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_013
     * @tc.desc subscribe test
     */
    it('testRdbStoreDistributed0013', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0013 start *************");
        rdbStore.off("dataChange", data_relationalStore.SubscribeType.SUBSCRIBE_TYPE_REMOTE, (device) => {
            console.log(TAG + device + " dataChange");
        });
        console.log(TAG + "off dataChange success");
        expect(rdbStore).assertEqual(rdbStore);
        done()
        console.log(TAG + "************* testRdbStoreDistributed0013 end *************");
    })
    console.log(TAG + "*************Unit Test End*************");

    /**
     * @tc.name subscribe test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_014
     * @tc.desc subscribe test
     */
    it('testRdbStoreDistributed0014', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0014 start *************");
        rdbStore.on("dataChange", data_relationalStore.SubscribeType.SUBSCRIBE_TYPE_CLOUD, (device) => {
            console.log(TAG + device + " dataChange");
        });
        console.log(TAG + "on dataChange success");
        expect(rdbStore).assertEqual(rdbStore);
        console.log(TAG + "************* testRdbStoreDistributed0014 end *************");
        done()
    })

    /**
     * @tc.name unsubscribe test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_015
     * @tc.desc subscribe test
     */
    it('testRdbStoreDistributed0015', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0015 start *************");
        rdbStore.off("dataChange", data_relationalStore.SubscribeType.SUBSCRIBE_TYPE_CLOUD, (device) => {
            console.log(TAG + device + " dataChange");
        });
        console.log(TAG + "off dataChange success");
        expect(rdbStore).assertEqual(rdbStore);
        console.log(TAG + "************* testRdbStoreDistributed0015 end *************");
        done()
    })

    /**
     * @tc.name subscribe test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_016
     * @tc.desc subscribe test
     */
    it('testRdbStoreDistributed0016', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0016 start *************");
        rdbStore.on("dataChange", data_relationalStore.SubscribeType.SUBSCRIBE_TYPE_CLOUD_DETAILS, (device) => {
            console.log(TAG + device + " dataChange");
        });
        console.log(TAG + "on dataChange success");
        expect(rdbStore).assertEqual(rdbStore);
        console.log(TAG + "************* testRdbStoreDistributed0016 end *************");
        done()
    })

    /**
     * @tc.name unsubscribe test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_017
     * @tc.desc subscribe test
     */
    it('testRdbStoreDistributed0017', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0017 start *************");
        rdbStore.off("dataChange", data_relationalStore.SubscribeType.SUBSCRIBE_TYPE_CLOUD_DETAILS, (device) => {
            console.log(TAG + device + " dataChange");
        });
        console.log(TAG + "off dataChange success");
        expect(rdbStore).assertEqual(rdbStore);
        console.log(TAG + "************* testRdbStoreDistributed0017 end *************");
        done()
    })

    /**
     * @tc.name unsubscribe test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_018
     * @tc.desc unsubscribe when no observer
     */
    it('testRdbStoreDistributed0018', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0018 start *************");
        rdbStore.off("dataChange", data_relationalStore.SubscribeType.SUBSCRIBE_TYPE_REMOTE);
        console.log(TAG + "off dataChange success");
        expect(rdbStore).assertEqual(rdbStore);
        console.log(TAG + "************* testRdbStoreDistributed0018 end *************");
        done()
    })

    /**
     * @tc.name unsubscribe test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_019
     * @tc.desc unsubscribe when observer is null
     */
    it('testRdbStoreDistributed0019', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0019 start *************");
        rdbStore.off("dataChange", data_relationalStore.SubscribeType.SUBSCRIBE_TYPE_CLOUD, null);
        console.log(TAG + "off dataChange success");
        expect(rdbStore).assertEqual(rdbStore);
        console.log(TAG + "************* testRdbStoreDistributed0019 end *************");
        done()
    })

    /**
     * @tc.name unsubscribe test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_020
     * @tc.desc unsubscribe when observer is undefined
     */
    it('testRdbStoreDistributed0020', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0020 start *************");
        rdbStore.off("dataChange", data_relationalStore.SubscribeType.SUBSCRIBE_TYPE_CLOUD_DETAILS, undefined);
        console.log(TAG + "off dataChange success");
        expect(rdbStore).assertEqual(rdbStore);
        console.log(TAG + "************* testRdbStoreDistributed0020 end *************");
        done()
    })

    /**
     * @tc.name subscribe test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_021
     * @tc.desc normal testcase for autoSyncProgress of interface 'on'
     */
    it('testRdbStoreDistributed0021', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0021 start *************");
        try {
            rdbStore.on("autoSyncProgress", function (detail) {
                console.log(TAG + `Progress:` + JSON.stringify(detail));
            });
            done();
            expect(rdbStore).assertEqual(rdbStore);
            console.log(TAG + "on autoSyncProgress success");
        } catch (err) {
            console.log(TAG + "on autoSyncProgress" + err);
            done();
            expect().assertFail();
        }
        console.log(TAG + "************* testRdbStoreDistributed0021 end *************");
    })

    /**
     * @tc.name subscribe test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_022
     * @tc.desc normal testcase for autoSyncProgress of interface 'off'
     */
    it('testRdbStoreDistributed0022', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0022 start *************");
        try {
            rdbStore.off("autoSyncProgress", function (detail) {
                console.log(TAG + `Progress:` + JSON.stringify(detail));
            });
            done();
            expect(rdbStore).assertEqual(rdbStore);
            console.log(TAG + "off autoSyncProgress success");
        } catch (err) {
            console.log(TAG + "off autoSyncProgress" + err);
            done();
            expect().assertFail();
        }
        console.log(TAG + "************* testRdbStoreDistributed0022 end *************");
    })

    /**
     * @tc.name subscribe test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_023
     * @tc.desc normal testcase for autoSyncProgress of interface 'off'
     */
    it('testRdbStoreDistributed0023', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0023 start *************");
        try {
            rdbStore.off("autoSyncProgress", null);
            done();
            expect(rdbStore).assertEqual(rdbStore);
            console.log(TAG + "off autoSyncProgress success");
        } catch (err) {
            console.log(TAG + "off autoSyncProgress" + err);
            done();
            expect().assertFail();
        }
        console.log(TAG + "************* testRdbStoreDistributed0023 end *************");
    })

    /**
     * @tc.name subscribe test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_024
     * @tc.desc normal testcase for autoSyncProgress of interface 'off'
     */
    it('testRdbStoreDistributed0024', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0024 start *************");
        try {
            rdbStore.off("autoSyncProgress", undefined);
            done();
            expect(rdbStore).assertEqual(rdbStore);
            console.log(TAG + "off autoSyncProgress success");
        } catch (err) {
            console.log(TAG + "off autoSyncProgress" + err);
            done();
            expect().assertFail();
        }
        console.log(TAG + "************* testRdbStoreDistributed0024 end *************");
    })

    /**
     * @tc.name subscribe test
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_Distributed_025
     * @tc.desc normal testcase for autoSyncProgress of interface 'off'
     */
    it('testRdbStoreDistributed0025', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreDistributed0025 start *************");
        try {
            rdbStore.off("autoSyncProgress");
            done();
            expect(rdbStore).assertEqual(rdbStore);
            console.log(TAG + "off autoSyncProgress success");
        } catch (err) {
            console.log(TAG + "off autoSyncProgress" + err);
            done();
            expect().assertFail();
        }
        console.log(TAG + "************* testRdbStoreDistributed0025 end *************");
    })
    console.log(TAG + "*************Unit Test End*************");
})
