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
import {DistributedType} from "../../../../../interfaces/inner_api/js/@ohos.data.relationalStore";

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const STORE_NAME = "cloud_rdb.db"
const E_NOT_SUPPORTED = 801;
var rdbStore = undefined;
var context = ability_featureAbility.getContext()

describe('rdbStoreDistributedCloudTest', function () {
    beforeAll(async function (done) {
        console.info(TAG + 'beforeAll')
        const config = {
            "name": STORE_NAME,
            securityLevel: data_relationalStore.SecurityLevel.S1,
        }
        try {
            rdbStore = await data_relationalStore.getRdbStore(context, config);
            console.log(TAG + "create rdb store success")
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
            console.log(TAG + "create rdb store failed" + `, error code is ${err.code}, message is ${err.message}`)
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
     * @tc.name set distributed table cloud none table
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_0001
     * @tc.desc rdb set distributed table cloud using none table as argment
     */
    it('testRdbStoreCloud0001', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloud0001 start *************");
        try {
            let config = {
                autoSync:false
            }
            await rdbStore.setDistributedTables([],rdbStore.DistributedType.DISTRIBUTED_CLOUD,config)
            console.log(TAG + "set none to be distributed table cloud success");
            expect(false).assertTrue();
        } catch (err) {
            console.log(TAG + `set none to be distributed table cloud failed, err code is ${err.code}, message is ${err.message}.`);
            expect(E_NOT_SUPPORTED).assertEqual(err.code);
        }
        done()
        console.log(TAG + "************* testRdbStoreCloud0001 end *************");
    })

    /**
     * @tc.name set distributed table cloud using one table name
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_0002
     * @tc.desc set distributed table cloud using one table name
     */
    it('testRdbStoreCloud0002', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloud0002 start *************");
        try {
            let config = {
                autoSync:true
            }
            await rdbStore.setDistributedTables(['employee'],rdbStore.DistributedType.DISTRIBUTED_CLOUD,config)
            console.log(TAG + "set employee to be distributed table cloud success");
            expect(true).assertTrue();
        } catch (err) {
            console.log(TAG + `set employee to be distributed table cloud failed, err code is ${err.code}, message is ${err.message}.`);
            expect(false).assertTrue();
        }
        done()
        console.log(TAG + "************* testRdbStoreCloud0002 end *************");
    })

    /**
     * @tc.name set distributed table cloud using two table name
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_0003
     * @tc.desc set distributed table cloud using two table name
     */
    it('testRdbStoreCloud0003', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloud0003 start *************");
        try {
            let config = {
                autoSync:false
            }
            await rdbStore.setDistributedTables(['employee', 'product'], rdbStore.DistributedType.DISTRIBUTED_CLOUD,
                config)
            console.log(TAG + "set employee and product to be distributed cloud table success");
            expect(true).assertTrue();
        } catch (err) {
            console.log(TAG + `set employee and product to be distributed table failed, err code is ${err.code}, message is ${err.message}.`);
            expect(false).assertTrue();
        }
        done()
        console.log(TAG + "************* testRdbStoreCloud0003 end *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})
