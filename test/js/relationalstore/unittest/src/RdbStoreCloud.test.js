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
const STORE_NAME = "cloud_rdb.db"
const PARAMETER_ERROR = 401;
var rdbStore = undefined;
var context = ability_featureAbility.getContext()

describe('rdbStoreDistributedCloudTest', function () {
    beforeAll(async function (done) {
        console.info(TAG + 'beforeAll')
        const config = {
            "name": STORE_NAME,
            securityLevel: relationalStore.SecurityLevel.S1,
        }
        try {
            rdbStore = await relationalStore.getRdbStore(context, config);
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

            sqlStatement = "CREATE TABLE IF NOT EXISTS local (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "name TEXT NOT NULL," +
                "price REAL," +
                "vendor INTEGER," +
                "describe TEXT)"
            try {
                await rdbStore.executeSql(sqlStatement, null)
                console.log(TAG + "create table local success")
                done()
            } catch (err) {
                console.log(TAG + "create table local failed")
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
        await relationalStore.deleteRdbStore(context, STORE_NAME);
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
            rdbStore.setDistributedTables([], relationalStore.DistributedType.DISTRIBUTED_CLOUD, config,
                function (err) {
                    console.log(TAG + "set none to be distributed table cloud success");
                    expect(true).assertTrue();
                    done()
                });
        } catch (err) {
            console.log(TAG + `set none to be distributed table cloud failed, err code is ${err.code}, message is ${err.message}.`);
            expect(false).assertTrue();
            done()
        }
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
            rdbStore.setDistributedTables(['employee'], relationalStore.DistributedType.DISTRIBUTED_CLOUD, config,
                function (err) {
                    console.log(TAG + "set employee to be distributed cloud table success");
                    expect(true).assertTrue();
                    done();
                })
        } catch (err) {
            console.log(TAG + `set employee to be distributed cloud table failed, err code is ${err.code}, message is ${err.message}.`);
            expect(false).assertTrue();
            done()
        }
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
            rdbStore.setDistributedTables(['employee', 'product'],
                relationalStore.DistributedType.DISTRIBUTED_CLOUD, config, function (err) {
                    console.log(TAG + "set employee and product to be distributed cloud table success");
                    expect(true).assertTrue();
                    done()
                })
        } catch (err) {
            console.log(TAG + `set employee and product to be distributed cloud table failed, err code is ${err.code}, message is ${err.message}.`);
            expect(false).assertTrue();
            done()
        }
        console.log(TAG + "************* testRdbStoreCloud0003 end *************");
    })

    /**
     * @tc.name set distributed table cloud with promise
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_0004
     * @tc.desc set distributed table cloud using two table name
     */
    it('testRdbStoreCloud0004', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloud0004 start *************");
        try {
            let config = {
                autoSync:false
            }
            await rdbStore.setDistributedTables(['employee', 'product'],
                relationalStore.DistributedType.DISTRIBUTED_CLOUD, config).then((err)=>{
                console.log(TAG + "set employee and product to be distributed cloud table success");
                expect(true).assertTrue();
                done();
            }).catch((err)=>{
                console.log(TAG + `set employee and product to be distributed table failed, err code is ${err.code}, message is ${err.message}.`);
                expect(false).assertTrue();
                done()
            });
        } catch (err) {
            console.log(TAG + `set employee and product to be distributed table failed, err code is ${err.code}, message is ${err.message}.`);
            expect(false).assertTrue();
            done()
        }
        console.log(TAG + "************* testRdbStoreCloud0004 end *************");
    })

    /**
     * @tc.name undefined parameter of setdistributed with promise
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_0005
     * @tc.desc test the undefined parameter of setdistributed with promise
     */
    it('testRdbStoreCloud0005', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloud0005 start *************");
        try {
            let config = {
                autoSync:false
            }
            await rdbStore.setDistributedTables(['local'], undefined,
                config).then((err)=>{
                console.log(TAG + "set local to be distributed device table success");
                expect(true).assertTrue();
                done();
            }).catch((err)=>{
                console.log(TAG + `set local to be distributed table failed 1, err code is ${err.code}, message is ${err.message}.`);
                expect(false).assertTrue();
                done()
            });
        } catch (err) {
            console.log(TAG + `set local to be distributed table failed 2, err code is ${err.code}, message is ${err.message}.`);
            expect(false).assertTrue();
            done()
        }
        console.log(TAG + "************* testRdbStoreCloud0005 end *************");
    })

    /**
     * @tc.name null parameter of setdistributed with promise
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_0006
     * @tc.desc test the null parameter of setdistributed with promise
     */
    it('testRdbStoreCloud0006', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloud0006 start *************");
        try {
            await rdbStore.setDistributedTables(['local'], null).then((err)=>{
                console.log(TAG + "set local to be distributed device table success");
                expect(true).assertTrue();
                done();
            }).catch((err)=>{
                console.log(TAG + `set local to be distributed table failed 1, err code is ${err.code}, message is ${err.message}.`);
                expect(false).assertTrue();
                done()
            });
        } catch (err) {
            console.log(TAG + `set local to be distributed table failed 2, err code is ${err.code}, message is ${err.message}.`);
            expect(false).assertTrue();
            done()
        }
        console.log(TAG + "************* testRdbStoreCloud0006 end *************");
    })

    /**
     * @tc.name null parameter of setdistributed with promise
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_0007
     * @tc.desc test no parameter of setdistributed with promise
     */
    it('testRdbStoreCloud0007', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloud0007 start *************");
        try {
            await rdbStore.setDistributedTables(['employee'], relationalStore.DistributedType.DISTRIBUTED_CLOUD
            ).then((err)=>{
                console.log(TAG + "set employee to be distributed cloud table success");
                expect(true).assertTrue();
                done();
            }).catch((err)=>{
                console.log(TAG + `set employee to be distributed table failed 1, err code is ${err.code}, message is ${err.message}.`);
                expect(false).assertTrue();
                done()
            });
        } catch (err) {
            console.log(TAG + `set employee to be distributed table failed 2, err code is ${err.code}, message is ${err.message}.`);
            expect(false).assertTrue();
            done()
        }
        console.log(TAG + "************* testRdbStoreCloud0007 end *************");
    })

    /**
     * @tc.name null parameter of setdistributed with promise
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_0008
     * @tc.desc test the undefined parameter of setdistributed with promise
     */
    it('testRdbStoreCloud0008', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloud0008 start *************");
        try {
            await rdbStore.setDistributedTables(['employee'], relationalStore.DistributedType.DISTRIBUTED_CLOUD,
                undefined).then((err)=>{
                console.log(TAG + "set employee to be distributed cloud table success");
                expect(true).assertTrue();
                done();
            }).catch((err)=>{
                console.log(TAG + `set employee to be distributed table failed 1, err code is ${err.code}, message is ${err.message}.`);
                expect(false).assertTrue();
                done()
            });
        } catch (err) {
            console.log(TAG + `set employee to be distributed table failed 2, err code is ${err.code}, message is ${err.message}.`);
            expect(false).assertTrue();
            done()
        }
        console.log(TAG + "************* testRdbStoreCloud0008 end *************");
    })

    /**
     * @tc.name null parameter of setdistributed with promise
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_0009
     * @tc.desc test the null parameter of setdistributed with promise
     */
    it('testRdbStoreCloud0009', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloud0009 start *************");
        try {
            await rdbStore.setDistributedTables(['employee'], relationalStore.DistributedType.DISTRIBUTED_CLOUD, null
            ).then((err)=>{
                console.log(TAG + "set employee to be distributed cloud table success");
                expect(true).assertTrue();
                done();
            }).catch((err)=>{
                console.log(TAG + `set employee to be distributed table failed 1, err code is ${err.code}, message is ${err.message}.`);
                expect(false).assertTrue();
                done()
            });
        } catch (err) {
            console.log(TAG + `set employee to be distributed table failed 2, err code is ${err.code}, message is ${err.message}.`);
            expect(false).assertTrue();
            done()
        }
        console.log(TAG + "************* testRdbStoreCloud0009 end *************");
    })

    /**
     * @tc.name undefined parameter of setdistributed with callback
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_0010
     * @tc.desc test the undefined parameter of setdistributed with callback
     */
    it('testRdbStoreCloud0010', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloud0010 start *************");
        try {
            rdbStore.setDistributedTables(['local'], undefined, function (err) {
                console.log(TAG + "set local to be distributed device table success");
                expect(true).assertTrue();
                done();
            })
        } catch (err) {
            console.log(TAG + `set employee to be distributed table failed, err code is ${err.code}, message is ${err.message}.`);
            expect(false).assertTrue();
            done()
        }
        console.log(TAG + "************* testRdbStoreCloud0010 end *************");
    })

    /**
     * @tc.name null parameter of setdistributed with callback
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_0011
     * @tc.desc test the null parameter of setdistributed with callback
     */
    it('testRdbStoreCloud0011', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloud0011 start *************");
        try {
            let config = {
                autoSync:false
            }
            rdbStore.setDistributedTables(['local'], null, config, function (err) {
                console.log(TAG + "set local to be distributed device table success");
                expect(true).assertTrue();
                done();
            })
        } catch (err) {
            console.log(TAG + `set local to be distributed table failed, err code is ${err.code}, message is ${err.message}.`);
            expect(false).assertTrue();
            done()
        }
        console.log(TAG + "************* testRdbStoreCloud0011 end *************");
    })

    /**
     * @tc.name null parameter of setdistributed with callback
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_0012
     * @tc.desc test the null parameter of setdistributed with callback
     */
    it('testRdbStoreCloud0012', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloud0012 start *************");
        try {
            rdbStore.setDistributedTables(['local'], relationalStore.DistributedType.DISTRIBUTED_CLOUD, null,
                function (err) {
                    console.log(TAG + "set local to be distributed cloud table success");
                    expect(true).assertTrue();
                    done();
                })
        } catch (err) {
            console.log(TAG + `set local to be distributed table failed, err code is ${err.code}, message is ${err.message}.`);
            expect(false).assertTrue();
            done()
        }
        console.log(TAG + "************* testRdbStoreCloud0012 end *************");
    })

    /**
     * @tc.name undefined parameter of setdistributed with callback
     * @tc.number SUB_DDM_AppDataFWK_JSRDB_CLOUD_0013
     * @tc.desc test the undefined parameter of setdistributed with callback
     */
    it('testRdbStoreCloud0013', 0, async function (done) {
        console.log(TAG + "************* testRdbStoreCloud0013 start *************");
        try {
            rdbStore.setDistributedTables(['local'], relationalStore.DistributedType.DISTRIBUTED_CLOUD, undefined,
                function (err) {
                    console.log(TAG + "set local to be distributed cloud table success");
                    expect(true).assertTrue();
                    done();
                })
        } catch (err) {
            console.log(TAG + `set local to be distributed table failed, err code is ${err.code}, message is ${err.message}.`);
            expect(false).assertTrue();
            done()
        }
        console.log(TAG + "************* testRdbStoreCloud0013 end *************");
    })

    console.log(TAG + "*************Unit Test End*************");
})