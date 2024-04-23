/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
import relationalStore from '@ohos.data.relationalStore';
import ability_featureAbility from '@ohos.ability.featureAbility'

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const STORE_NAME = "cloud_sync_rdb.db"
var rdbStore = undefined;
var context = ability_featureAbility.getContext()

describe('rdbStoreCloudSyncTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        const config = {
            "name": STORE_NAME,
            securityLevel: relationalStore.SecurityLevel.S1,
        }
        try {
            rdbStore = await relationalStore.getRdbStore(context, config);
            console.log(TAG + "create rdb store success")
            let sql_text = "CREATE TABLE IF NOT EXISTS cloud_text (" +
                "data TEXT, " +
                "recycled BOOLEAN, " +
                "recycledTime INTEGER, " +
                "uuid TEXT PRIMARY KEY)";
            let sql_int = "CREATE TABLE IF NOT EXISTS cloud_int (" +
                "data TEXT, " +
                "recycled BOOLEAN, " +
                "recycledTime INTEGER, " +
                "uuid INTEGER PRIMARY KEY)";
            let sql_integer = "CREATE TABLE IF NOT EXISTS cloud_integer (" +
                "data TEXT, " +
                "recycled BOOLEAN, " +
                "recycledTime INTEGER, " +
                "uuid INTEGER PRIMARY KEY)";
            await rdbStore.executeSql(sql_text, null);
            await rdbStore.executeSql(sql_int, null);
            await rdbStore.executeSql(sql_integer, null);
            console.log(TAG + "create table cloud_text cloud_int cloud_integer success");

            let tableArray = ["cloud_text", "cloud_integer"];
            const setConfig = {
                autoSync: false,
            }
            await rdbStore.setDistributedTables(
                tableArray, relationalStore.DistributedType.DISTRIBUTED_CLOUD, setConfig);
            let vBucketArray1 = new Array();
            for (let i = 0; i < 5; i++) {
                let valueBucket = {
                    "data": "cloud_sync_insert",
                    "recycled": true,
                    "recycledTime": 12345,
                    "uuid": "test_key" + i.toString(),
                }
                vBucketArray1.push(valueBucket);
            }
            await rdbStore.batchInsert("cloud_text", vBucketArray1);
            let vBucketArray2 = new Array();
            for (let i = 0; i < 5; i++) {
                let valueBucket = {
                    "data": "cloud_sync_insert",
                    "recycled": true,
                    "recycledTime": 12345,
                    "uuid": i,
                }
                vBucketArray2.push(valueBucket);
            }
            await rdbStore.batchInsert("cloud_integer", vBucketArray2);
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }
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
        await rdbStore.deleteRdbStore(context, STORE_NAME);
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name get modify time using wrong primary key type
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_SYNC_0001
     * @tc.desc rdb get modify time using wrong primary key type
     */
    it('testRdbStoreCloudSync0001', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloudSync0001 start *************");
        try {
            let key = new Array();
            let PRIKey = [key, "test_key1", "test_key2"];
            await rdbStore.getModifyTime("cloud_text", "uuid", PRIKey);
            expect().assertFail();
        } catch (err) {
            console.log(TAG + `get modify time, errcode:${JSON.stringify(err)}.`);
            expect(err.code).assertEqual('401');
        }
        done();
        console.log(TAG + "************* testRdbStoreCloudSync0001 end *************");
    })

    /**
     * @tc.name get modify time using string primary key type and callback method
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_SYNC_0002
     * @tc.desc get modify time using string primary key type and callback method
     */
    it('testRdbStoreCloudSync0002', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloudSync0002 start *************");
        try {
            let PRIKey = ["test_key1", "test_key2"];
            rdbStore.getModifyTime("cloud_text", "uuid", PRIKey, function (err, data) {
                console.log(TAG + `modifyTime:` + JSON.stringify(data));
                done();
                console.log(TAG + "************* testRdbStoreCloudSync0002 end *************");
            });
        } catch (err) {
            console.log(TAG + `get modify time fail, errcode:${JSON.stringify(err)}.`);
            done()
            expect().assertFail();
        }
    })

    /**
     * @tc.name get modify time using string primary key type and promise method
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_SYNC_0003
     * @tc.desc get modify time using string primary key type and promise method
     */
    it('testRdbStoreCloudSync0003', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloudSync0003 start *************");
        let PRIKey = ["test_key1", "test_key2"];
        try {
            await rdbStore.getModifyTime("cloud_text", "uuid", PRIKey);
            done();
        } catch (err) {
            console.log(TAG + `get modify time fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        }
        console.log(TAG + "************* testRdbStoreCloudSync0003 end *************");
    })

    /**
     * @tc.name get modify time using rowid and callback method
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_SYNC_0004
     * @tc.desc get modify time using rowid and callback method
     */
    it('testRdbStoreCloudSync0004', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloudSync0004 start *************");
        try {
            let PRIKey = [1, 3, 4];
            rdbStore.getModifyTime("cloud_text", "rowid", PRIKey, function (err, data) {
                console.log(TAG + `modifyTime:` + JSON.stringify(data));
                done();
                console.log(TAG + "************* testRdbStoreCloudSync0004 end *************");
            });
        } catch (err) {
            console.log(TAG + `get modify time fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        }
    })

    /**
     * @tc.name get modify time using rowid and promise method
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_SYNC_0005
     * @tc.desc get modify time using rowid and promise method
     */
    it('testRdbStoreCloudSync0005', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloudSync0005 start *************");
        let PRIKey = [2, 4];
        try {
            await rdbStore.getModifyTime("cloud_text", "roWId", PRIKey);
            done();
        } catch (err) {
            console.log(TAG + `get modify time fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        }
        console.log(TAG + "************* testRdbStoreCloudSync0005 end *************");
    })

    /**
     * @tc.name get modify time, but not set distributed table
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_SYNC_0006
     * @tc.desc get modify time, but not set distributed table
     */
    it('testRdbStoreCloudSync0006', 0, async function () {
        console.log(TAG + "************* testRdbStoreCloudSync0006 start *************");
        let valueBucket = {
            "data": "cloud_sync_insert",
            "recycled": true,
            "recycledTime": 12345,
            "uuid": undefined,
        }
        await rdbStore.insert("cloud_int", valueBucket);
        let PRIKey = [0, 1, 2];
        try {
            await rdbStore.getModifyTime("cloud_int", "uuid", PRIKey)
            expect().assertFail();
        } catch (err) {
            console.log(TAG + `get modify time fail, errcode:${JSON.stringify(err)}.`);
            expect(err.code).assertEqual(14800000);
        }
        console.log(TAG + "************* testRdbStoreCloudSync0006 end *************");
    })

    /**
     * @tc.name get modify time using int primary key type and callback method
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_SYNC_0007
     * @tc.desc get modify time using int primary key type and callback method
     */
    it('testRdbStoreCloudSync0007', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloudSync0007 start *************");
        try {
            let PRIKey = [1, 2, 4];
            rdbStore.getModifyTime("cloud_integer", "uuid", PRIKey, function (err, data) {
                console.log(TAG + `modifyTime:` + JSON.stringify(data));
                done();
                console.log(TAG + "************* testRdbStoreCloudSync0007 end *************");
            });
        } catch (err) {
            console.log(TAG + `get modify time fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        }
    })

    /**
     * @tc.name get modify time using int primary key type and promise method
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_SYNC_0008
     * @tc.desc get modify time using int primary key type and promise method
     */
    it('testRdbStoreCloudSync0008', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloudSync0008 start *************");
        let PRIKey = [2, 4];
        await rdbStore.getModifyTime("cloud_integer", "uuid", PRIKey).then((err, data) => {
            console.log(TAG + `modifyTime:` + JSON.stringify(err));
            done();
        }).catch((err) => {
            console.log(TAG + `get modify time fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        });
        console.log(TAG + "************* testRdbStoreCloudSync0008 end *************");
    })

    /**
     * @tc.name cloud sync with no table, SyncMode is SYNC_MODE_TIME_FIRST and callback method
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_SYNC_0009
     * @tc.desc cloud sync with no table, SyncMode is SYNC_MODE_TIME_FIRST and callback method
     */
    it('testRdbStoreCloudSync0009', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloudSync0009 start *************");
        try {
            rdbStore.cloudSync(relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, function (detail) {
                console.log(TAG + `Progress:` + JSON.stringify(detail));
                done();
                expect(JSON.stringify(detail)).assertEqual('{"schedule":2,"code":3,"details":{}}');
                console.log(TAG + "************* testRdbStoreCloudSync0009 end *************");
            }, () => {
            });
        } catch (err) {
            console.log(TAG + `cloud sync fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        }
    })

    /**
     * @tc.name cloud sync with no table, SyncMode is SYNC_MODE_TIME_FIRST and promise method
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_SYNC_0010
     * @tc.desc cloud sync with no table, SyncMode is SYNC_MODE_TIME_FIRST and promise method
     */
    it('testRdbStoreCloudSync0010', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloudSync0010 start *************");

        function Progress(detail) {
            console.log(TAG + `Progress:` + JSON.stringify(detail));
            done();
            expect(JSON.stringify(detail)).assertEqual('{"schedule":2,"code":3,"details":{}}');
            console.log(TAG + "************* testRdbStoreCloudSync0010 end *************");
        }

        try {
            await rdbStore.cloudSync(relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress)
        } catch (err) {
            console.log(TAG + `cloud sync fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        }
    })

    /**
     * @tc.name cloud sync with table, SyncMode is SYNC_MODE_TIME_FIRST and callback method
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_SYNC_0011
     * @tc.desc cloud sync with table, SyncMode is SYNC_MODE_TIME_FIRST and callback method
     */
    it('testRdbStoreCloudSync0011', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloudSync0011 start *************");
        try {

            function Progress(detail) {
                console.log(TAG + `Progress:` + JSON.stringify(detail));
                done();
                expect(JSON.stringify(detail)).assertEqual('{"schedule":2,"code":3,"details":{}}');
                console.log(TAG + "************* testRdbStoreCloudSync0011 end *************");
            }

            let tableArray = ["cloud_text"];
            rdbStore.cloudSync(relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, tableArray, Progress, () => {
            });
        } catch (err) {
            console.log(TAG + `cloud sync fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        }
    })

    /**
     * @tc.name cloud sync with table, SyncMode is SYNC_MODE_TIME_FIRST and promise method
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_SYNC_0012
     * @tc.desc cloud sync with table, SyncMode is SYNC_MODE_TIME_FIRST and promise method
     */
    it('testRdbStoreCloudSync0012', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloudSync0012 start *************");

        function Progress(detail) {
            console.log(TAG + `Progress:` + JSON.stringify(detail));
            done();
            expect(JSON.stringify(detail)).assertEqual('{"schedule":2,"code":3,"details":{}}');
            console.log(TAG + "************* testRdbStoreCloudSync0012 end *************");
        }

        let tableArray = ["cloud_text"];
        try {
            await rdbStore.cloudSync(relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, tableArray, Progress)
        } catch (err) {
            console.log(TAG + `cloud sync fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        }
    })

    /**
     * @tc.name cloud sync with table, SyncMode is SYNC_MODE_NATIVE_FIRST and promise method
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_SYNC_0013
     * @tc.desc cloud sync with table, SyncMode is SYNC_MODE_NATIVE_FIRST and promise method
     */
    it('testRdbStoreCloudSync0013', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloudSync0013 start *************");

        function Progress(detail) {
            console.log(TAG + `Progress:` + JSON.stringify(detail));
            done();
            expect(JSON.stringify(detail)).assertEqual('{"schedule":2,"code":3,"details":{}}');
            console.log(TAG + "************* testRdbStoreCloudSync0013 end *************");
        }

        let tableArray = ["cloud_text"];
        try {
            await rdbStore.cloudSync(relationalStore.SyncMode.SYNC_MODE_NATIVE_FIRST, tableArray, Progress)
        } catch (err) {
            console.log(TAG + `cloud sync fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        }
    })

    /**
     * @tc.name cloud sync with table, SyncMode is SYNC_MODE_CLOUD_FIRST and promise method
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_SYNC_0014
     * @tc.desc cloud sync with table, SyncMode is SYNC_MODE_CLOUD_FIRST and promise method
     */
    it('testRdbStoreCloudSync0014', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloudSync0014 start *************");

        function Progress(detail) {
            console.log(TAG + `Progress:` + JSON.stringify(detail));
            done();
            expect(JSON.stringify(detail)).assertEqual('{"schedule":2,"code":3,"details":{}}');
            console.log(TAG + "************* testRdbStoreCloudSync0014 end *************");
        }

        let tableArray = ["cloud_text"];
        try {
            await rdbStore.cloudSync(relationalStore.SyncMode.SYNC_MODE_CLOUD_FIRST, tableArray, Progress)
        } catch (err) {
            console.log(TAG + `cloud sync fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        }
    })

    /**
     * @tc.name cloud sync with RdbPredicates, SyncMode is SYNC_MODE_CLOUD_FIRST and promise method
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_SYNC_0015
     * @tc.desc cloud sync with RdbPredicates, SyncMode is SYNC_MODE_CLOUD_FIRST and promise method
     */
    it('testRdbStoreCloudSync0015', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloudSync0015 start *************");

        function Progress(detail) {
            console.log(TAG + `Progress:` + JSON.stringify(detail));
            done();
        }
        let predicates = new relationalStore.RdbPredicates("test")
        predicates.in("id", ["id1","id2"]);
        try {
            await rdbStore.cloudSync(relationalStore.SyncMode.SYNC_MODE_CLOUD_FIRST, predicates, Progress)
        } catch (err) {
            console.log(TAG + `cloud sync fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect("202").assertEqual(err.code)
        }
        console.log(TAG + "************* testRdbStoreCloudSync0015 end *************");
    })

    /**
     * @tc.name cloud sync with RdbPredicates, SyncMode is SYNC_MODE_CLOUD_FIRST and callback method
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_SYNC_0016
     * @tc.desc cloud sync with RdbPredicates, SyncMode is SYNC_MODE_CLOUD_FIRST and callback method
     */
    it('testRdbStoreCloudSync0016', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloudSync0016 start *************");
        try {

            function Progress(detail) {
                console.log(TAG + `Progress:` + JSON.stringify(detail));
            }
            let predicates = new relationalStore.RdbPredicates("test")
            predicates.in("id", ["id1","id2"]);
            rdbStore.cloudSync(relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, predicates, Progress, () => {
                done();
                expect(false).assertTrue()
            });
        } catch (err) {
            console.log(TAG + `cloud sync fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect("202").assertEqual(err.code)
        }
        console.log(TAG + "************* testRdbStoreCloudSync0016 end *************");
    })

    /**
     * @tc.name cloud sync with exception parameter, SyncMode is SYNC_MODE_CLOUD_FIRST and callback method
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_SYNC_0017
     * @tc.desc cloud sync with exception parameter, SyncMode is SYNC_MODE_CLOUD_FIRST and callback method
     */
    it('testRdbStoreCloudSync0017', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloudSync0017 start *************");
        try {

            function Progress(detail) {
                console.log(TAG + `Progress:` + JSON.stringify(detail));
            }
            rdbStore.cloudSync(relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, 1410, Progress, () => {
                done();
                expect(false).assertTrue()
            });
        } catch (err) {
            console.log(TAG + `cloud sync fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect(err.code).assertEqual('401');
        }
        console.log(TAG + "************* testRdbStoreCloudSync0017 end *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})
