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
const STORE_NAME = "query_cursor_rdb.db"
var rdbStore = undefined;
var context = ability_featureAbility.getContext()

describe('rdbStoreQueryByCursorTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        const config = {
            "name": STORE_NAME,
            securityLevel: relationalStore.SecurityLevel.S1,
        }
        try {
            rdbStore = await relationalStore.getRdbStore(context, config);
            console.log(TAG + "create rdb store success")
            let sql = "CREATE TABLE IF NOT EXISTS query_tb (" +
                "data TEXT, " +
                "recycled BOOLEAN, " +
                "recycledTime INTEGER, " +
                "uuid TEXT PRIMARY KEY)";
            await rdbStore.executeSql(sql, null);
            console.log(TAG + "create table query_tb success");
            const setConfig = {
                autoSync: false,
            }
            await rdbStore.setDistributedTables(
                ["query_tb"], relationalStore.DistributedType.DISTRIBUTED_CLOUD, setConfig);
            console.log(TAG + "set distributed tables success");
        } catch (err) {
            console.log(TAG + `failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach');
        try {
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
            await rdbStore.batchInsert("query_tb", vBucketArray1);
        } catch (err) {
            console.log(TAG + `insert failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach');
        try {
            let predicates = new relationalStore.RdbPredicates("query_tb");
            predicates.equalTo("data", "cloud_sync_insert");
            await rdbStore.delete(predicates);
        } catch (err) {
            console.log(TAG + `delete failed, err: ${JSON.stringify(err)}`)
            expect().assertFail()
        }
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll');
        rdbStore = null;
        await rdbStore.deleteRdbStore(context, STORE_NAME);
    })

    console.log(TAG + "*************Unit Test Begin*************");
    /**
     * @tc.name query with cursor
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_QUERY_WITH_CURSOR_0001
     * @tc.desc query with cursor, and get all columns.
     */
    it('testRdbStoreQueryAllColumnsWithCursor', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreQueryAllColumnsWithCursor start *************");

        let predicates = new relationalStore.RdbPredicates("query_tb");
        predicates.greaterThan(relationalStore.Field.CURSOR_FIELD, 0);
        if (rdbStore == undefined) {
            return;
        }
        let promise = rdbStore.query(predicates);
        await promise.then((resultSet) => {
            expect(6).assertEqual(resultSet.columnCount);
            let deletedIndex = resultSet.getColumnIndex(relationalStore.Field.DELETED_FLAG_FIELD);
            expect(5).assertEqual(deletedIndex);
            let cursorIndex = resultSet.getColumnIndex(relationalStore.Field.CURSOR_FIELD);
            expect(4).assertEqual(cursorIndex);
            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed);
        }).catch((err) => {
            console.log(TAG + `query cursor fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        });
        done();
    })
0.
    /**
     * @tc.name query with cursor
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_QUERY_WITH_CURSOR_0002
     * @tc.desc query with cursor, and specific columns.
     */
    it('testRdbStoreQuerySpecificColumnsWithCursor', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreQuerySpecificColumnsWithCursor start *************");

        let predicates = new relationalStore.RdbPredicates("query_tb");
        predicates.greaterThan(relationalStore.Field.CURSOR_FIELD, 0);
        predicates.orderByAsc(relationalStore.Field.CURSOR_FIELD);
        predicates.orderByAsc("data");
        if (rdbStore == undefined) {
            return;
        }
        let promise = rdbStore.query(predicates, ["data", "uuid"]);
        await promise.then((resultSet) => {
            expect(4).assertEqual(resultSet.columnCount);
            expect(true).assertEqual(resultSet.goToFirstRow());
            expect(true).assertEqual(resultSet.goToNextRow());
            let cursor = resultSet.getLong(resultSet.getColumnIndex(relationalStore.Field.CURSOR_FIELD));
            expect(12).assertEqual(cursor);
            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed);
        }).catch((err) => {
            console.log(TAG + `query cursor fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        });
        done();
    })

    /**
     * @tc.name query with cursor
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_QUERY_WITH_CURSOR_0003
     * @tc.desc update data, and query with cursor.
     */
    it('testRdbStoreQueryCursorAfterUpdate', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreQueryCursorAfterUpdate start *************");
        if (rdbStore == undefined) {
            return;
        }
        const valueBucket = {
            "recycledTime": "1234567890",
        }
        let updatePredicates = new relationalStore.RdbPredicates("query_tb");
        updatePredicates.equalTo("uuid", "test_key1");
        updatePredicates.or();
        updatePredicates.equalTo("uuid", "test_key2");
        await rdbStore.update(valueBucket, updatePredicates);
        console.log(TAG + `update end.`);
        let predicates = new relationalStore.RdbPredicates("query_tb");
        predicates.greaterThanOrEqualTo(relationalStore.Field.CURSOR_FIELD, 26);
        predicates.equalTo(relationalStore.Field.ORIGIN_FIELD, relationalStore.Origin.LOCAL);
        predicates.orderByDesc(relationalStore.Field.CURSOR_FIELD);
        let promise = rdbStore.query(predicates);
        await promise.then((resultSet) => {
            expect(true).assertEqual(resultSet.goToFirstRow());
            let value1 = resultSet.getString(resultSet.getColumnIndex("recycledTime"));
            expect("1234567890").assertEqual(value1);
            expect(true).assertEqual(resultSet.goToNextRow());
            let value2 = resultSet.getString(resultSet.getColumnIndex("recycledTime"));
            expect("1234567890").assertEqual(value2);
            resultSet.close();
            expect(true).assertEqual(resultSet.isClosed);
        }).catch((err) => {
            console.log(TAG + `query cursor fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        });
        done();
    })

    /**
     * @tc.name query with cursor
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_QUERY_WITH_CURSOR_0004
     * @tc.desc delete data, and query with cursor.
     */
    it('testRdbStoreQueryCursorAfterDelete', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreQueryCursorAfterDelete start *************");
        if (rdbStore == undefined) {
            return;
        }
        let deletedPred = new relationalStore.RdbPredicates("query_tb");
        deletedPred.equalTo("uuid", "test_key3");
        await rdbStore.delete(deletedPred);
        console.log(TAG + `delete end.`);
        let predicates = new relationalStore.RdbPredicates("query_tb");
        predicates.greaterThan(relationalStore.Field.CURSOR_FIELD, 37);
        predicates.orderByAsc(relationalStore.Field.CURSOR_FIELD);
        try {
            rdbStore.query(predicates, (err, resultSet) => {
                expect(0).assertEqual(resultSet.rowCount);
                resultSet.close();
                expect(true).assertEqual(resultSet.isClosed);
            })
        } catch(err) {
            console.log(TAG + `query cursor fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        }
        done();
    })

    /**
     * @tc.name query with cursor
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_QUERY_WITH_CURSOR_0005
     * @tc.desc query with cursor and origin.
     */
    it('testRdbStoreQueryCursorAndOrigin', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreQueryCursorAndOrigin start *************");
        if (rdbStore == undefined) {
            return;
        }
        let predicates = new relationalStore.RdbPredicates("query_tb");
        predicates.greaterThan(relationalStore.Field.CURSOR_FIELD, 0);
        predicates.and();
        predicates.beginWrap();
        predicates.equalTo(relationalStore.Field.ORIGIN_FIELD, relationalStore.Origin.CLOUD);
        predicates.or();
        predicates.equalTo(relationalStore.Field.ORIGIN_FIELD, relationalStore.Origin.REMOTE);
        predicates.endWrap();
        predicates.orderByAsc(relationalStore.Field.CURSOR_FIELD);
        try {
            rdbStore.query(predicates, (err, resultSet) => {
                expect(0).assertEqual(resultSet.rowCount);
                resultSet.close();
                expect(true).assertEqual(resultSet.isClosed);
            })
        } catch(err) {
            console.log(TAG + `query cursor fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        }
        done();
    })

    /**
     * @tc.name clean dirty data
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLEAN_DIRTY_DATA_0001
     * @tc.desc clean dirty data.
     */
    it('testRdbStoreCleanDirtyData', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCleanDirtyData start *************");
        if (rdbStore == undefined) {
            return;
        }
        let promise = rdbStore.cleanDirtyData("query_tb");
        await promise.then((err) => {
            expect(true).assertTrue();
        }).catch((err) => {
            console.log(TAG + `clean dirty data fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        });
        done();
    })

    /**
     * @tc.name clean dirty data with specified cursor.
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLEAN_DIRTY_DATA_0002
     * @tc.desc clean dirty data with specified cursor.
     */
    it('testRdbStoreCleanDirtyDataWithSpecifiedCursor', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCleanDirtyDataWithSpecifiedCursor start *************");
        if (rdbStore == undefined) {
            return;
        }
        let cursor = 3;
        let promise = rdbStore.cleanDirtyData("query_tb", cursor);
        await promise.then((err) => {
            expect(true).assertTrue();
        }).catch((err) => {
            console.log(TAG + `clean dirty data fail, errcode:${JSON.stringify(err)}.`);
            done();
            expect().assertFail();
        });
        done();
    })

    /**
     * @tc.name clean dirty data with error param.
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLEAN_DIRTY_DATA_0003
     * @tc.desc clean dirty data with specified cursor.
     */
    it('testRdbStoreCleanDirtyDataWithErrorParam', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCleanDirtyDataWithErrorParam start *************");
        if (rdbStore == undefined) {
            return;
        }
        try {
            let cursor = 3;
            let promise = rdbStore.cleanDirtyData();
            await promise.then((err) => {
                expect().assertFail();
            }).catch((err) => {
                console.log(TAG + `clean dirty data fail, errcode:${JSON.stringify(err)}.`);
                expect(true).assertTrue();
                done();
            });
        } catch (err) {
            console.error("clean dirty data, err: code=" + err.code + " message=" + err.message)
            expect(true).assertTrue()
        }
        done();
    })

    /**
     * @tc.name clean dirty data with specified cursor by callback method.
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLEAN_DIRTY_DATA_0004
     * @tc.desc clean dirty data with specified cursor.
     */
    it('testRdbStoreCleanDirtyDataWithSpecifiedCursorCallback', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCleanDirtyDataWithSpecifiedCursorCallback start *************");
        if (rdbStore == undefined) {
            return;
        }
        try {
            let cursor = 100;
            rdbStore.cleanDirtyData("query_tb", cursor, (err) => {
                if (err) {
                    console.error(TAG, "clean dirty data failed, err: code=" + err.code + " message=" + err.message);
                    expect(false).assertTrue() ;
                }
                done();
            })
        } catch (err) {
            console.error("clean dirty data, err: code=" + err.code + " message=" + err.message)
            expect(false).assertTrue()
        }
        done();
    })
    console.log(TAG + "*************Unit Test End*************");
})
