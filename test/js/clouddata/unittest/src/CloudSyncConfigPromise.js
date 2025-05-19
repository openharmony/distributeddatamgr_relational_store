/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
import cloudData from '@ohos.data.cloudData';
import relationalStore from '@ohos.data.relationalStore';

const TAG = "[CLOUD_CONFIG_JSKITS_TEST]"
describe('CloudConfigPromiseTest', function () {
    /**
     * @tc.name EnabledCloudInvalidArgsTest
     * @tc.desc Test Js Api EnabledCloud with invalid args
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('EnabledCloudInvalidArgsTest', 0, async function (done) {
        console.info('EnabledCloudInvalidArgsTest');
        try {
            let account = "test_id";
            let config = cloudData.Config;
            await config.enableCloud(account, null).then(() => {
                console.info('EnabledCloudInvalidArgsTest success');
                expect(null).assertFail();
            }).catch((error) => {
                console.error('EnabledCloudInvalidArgsTest enableCloud fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(null).assertFail();
            });
        } catch (e) {
            console.error('EnabledCloudInvalidArgsTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name EnabledCloudInvalidArgsNumsTest
     * @tc.desc Test Js Api EnabledCloud which parameters number are less
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('EnabledCloudInvalidArgsNumsTest', 0, async function (done) {
        console.info('EnabledCloudInvalidArgsNumsTest');
        try {
            let account = "test_id";
            await cloudData.Config.enableCloud(account).then(() => {
                console.info('EnabledCloudInvalidArgsNumsTest success');
                expect(null).assertFail();
            }).catch((error) => {
                console.error('EnabledCloudInvalidArgsNumsTest enableCloud fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(null).assertFail();
            });
        } catch (e) {
            console.error('EnabledCloudInvalidArgsNumsTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })


    /**
     * @tc.name DisableCloudInvalidArgsTest
     * @tc.desc Test Js Api DisableCloud with invalid args
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('DisableCloudInvalidArgsTest', 0, async function (done) {
        console.info('DisableCloudInvalidArgsTest');
        try {
            await cloudData.Config.disableCloud(null).then(() => {
                console.info('DisableCloudInvalidArgsTest success');
                expect(null).assertFail();
            }).catch((error) => {
                console.error('DisableCloudInvalidArgsTest disableCloud fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(null).assertFail();
            });
        } catch (e) {
            console.error('DisableCloudInvalidArgsTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name DisableCloudInvalidArgsNumsTest
     * @tc.desc Test Js Api DisableCloud which parameters number are less
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('DisableCloudInvalidArgsNumsTest', 0, async function (done) {
        console.info('DisableCloudInvalidArgsNumsTest');
        try {
            await cloudData.Config.disableCloud().then(() => {
                console.info('DisableCloudInvalidArgsNumsTest success');
                expect(null).assertFail();
            }).catch((error) => {
                console.error('DisableCloudInvalidArgsNumsTest disableCloud fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(null).assertFail();
            });
        } catch (e) {
            console.error('DisableCloudInvalidArgsNumsTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name ChangeAppCloudInvalidArgsTest
     * @tc.desc Test Js Api ChangeAppCloudSwitch with invalid args
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('ChangeAppCloudInvalidArgsTest', 0, async function (done) {
        console.info('ChangeAppCloudInvalidArgsTest');
        try {
            let account = "test_id";
            let bundleName = "test_bundleName";
            await cloudData.Config.changeAppCloudSwitch(account, bundleName, null).then(() => {
                console.info('ChangeAppCloudInvalidArgsTest success');
                expect(null).assertFail();
            }).catch((error) => {
                console.error('ChangeAppCloudInvalidArgsTest changeAppCloudSwitch fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(null).assertFail();
            });
        } catch (e) {
            console.error('ChangeAppCloudInvalidArgsTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name ChangeAppCloudInvalidArgsNumsTest
     * @tc.desc Test Js Api ChangeAppCloudSwitch which parameters number are less
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('ChangeAppCloudInvalidArgsNumsTest', 0, async function (done) {
        console.info('ChangeAppCloudInvalidArgsNumsTest');
        try {
            let account = "test_id";
            let bundleName = "test_bundleName";
            await cloudData.Config.changeAppCloudSwitch(account, bundleName).then(() => {
                console.info('ChangeAppCloudInvalidArgsNumsTest success');
                expect(null).assertFail();
            }).catch((error) => {
                console.error('ChangeAppCloudInvalidArgsNumsTest changeAppCloudSwitch fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(null).assertFail();
            });
        } catch (e) {
            console.error('ChangeAppCloudInvalidArgsNumsTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name NotifyChangeInvalidArgsTest
     * @tc.desc Test Js Api NotifyChange with invalid args
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('NotifyChangeInvalidArgsTest', 0, async function (done) {
        console.info('NotifyChangeInvalidArgsTest');
        try {
            let account = "test_id";
            await cloudData.Config.notifyDataChange(account, null).then((data) => {
                console.info('NotifyChangeInvalidArgsTest success');
                expect(null).assertFail();
            }).catch((error) => {
                console.error('NotifyChangeInvalidArgsTest NotifyChange fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(null).assertFail();
            });
        } catch (e) {
            console.error('NotifyChangeInvalidArgsTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name NotifyChangeInvalidArgsNumsTest
     * @tc.desc Test Js Api NotifyChange which parameters number are less
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('NotifyChangeInvalidArgsNumsTest', 0, async function (done) {
        console.info('NotifyChangeInvalidArgsNumsTest');
        try {
            let account = "test_id";
            await cloudData.Config.notifyDataChange(account).then(() => {
                console.info('NotifyChangeInvalidArgsNumsTest success');
                expect(null).assertFail();
            }).catch((error) => {
                console.error('NotifyChangeInvalidArgsNumsTest NotifyChange fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(null).assertFail();
            });
        } catch (e) {
            console.error('NotifyChangeInvalidArgsNumsTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name NotifyDataChangeInvalidArgsTest
     * @tc.desc Test Js Api NotifyDataChange with invalid args
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('NotifyDataChangeInvalidArgsTest', 0, async function (done) {
        console.info('NotifyDataChangeInvalidArgsTest');
        try {
            await cloudData.Config.notifyDataChange(null).then(() => {
                console.info('NotifyDataChangeInvalidArgsTest success');
                expect(null).assertFail();
            }).catch((error) => {
                console.error('NotifyDataChangeInvalidArgsTest NotifyChange fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(null).assertFail();
            });
        } catch (e) {
            console.error('NotifyDataChangeInvalidArgsTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name NotifyDataChangeInvalidArgsNumsTest
     * @tc.desc Test Js Api NotifyChange which parameters number are less
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('NotifyDataChangeInvalidArgsNumsTest', 0, async function (done) {
        console.info('NotifyDataChangeInvalidArgsNumsTest');
        try {
            await cloudData.Config.notifyDataChange().then(() => {
                console.info('NotifyDataChangeInvalidArgsNumsTest success');
                expect(null).assertFail();
            }).catch((error) => {
                console.error('NotifyDataChangeInvalidArgsNumsTest NotifyChange fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(null).assertFail();
            });
        } catch (e) {
            console.error('NotifyDataChangeInvalidArgsNumsTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name ClearInvalidArgsNumsTest
     * @tc.desc Test Js Api Clean which parameters number are less
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('ClearInvalidArgsNumsTest', 0, async function (done) {
        console.info('ClearInvalidArgsNumsTest');
        try {
            let account = "test_id";
            await cloudData.Config.clear(account).then(() => {
                console.info('ClearInvalidArgsNumsTest success');
                expect(null).assertFail();
            }).catch((error) => {
                console.error('ClearInvalidArgsNumsTest clear fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(null).assertFail();
            });
        } catch (e) {
            console.error('ClearInvalidArgsNumsTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name ClearInvalidArgsTest
     * @tc.desc Test Js Api Clear which parameters are invalid
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('ClearInvalidArgsTest', 0, async function (done) {
        console.info('ClearInvalidArgsTest');
        try {
            let account = "test_id";
            let bundleName1 = "test_bundleName1";
            let appActions = { [bundleName1]: 3 };
            await cloudData.Config.clear(account, appActions).then(() => {
                console.info('ClearInvalidArgsTest success');
                expect(null).assertFail();
            }).catch((error) => {
                console.error('ClearInvalidArgsTest clean fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(null).assertFail();
            });
        } catch (e) {
            console.error('ClearInvalidArgsTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name queryStatisticsTest
     * @tc.desc Test Js Api queryStatistics with parameters number are less
     * @tc.type: FUNC
     */
    it('queryStatisticsTest1', 0, async function (done) {
        console.log(TAG + "************* queryStatisticsTest1 start *************");
        try {
            await cloudData.Config.queryStatistics().then((etc) => {
                console.info('queryStatisticsTest1 success' + `, info is ${JSON.stringify(etc)}`);
                expect(null).assertFail();
            }).catch((error) => {
                console.error('queryStatisticsTest1 fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(null).assertFail();
            });
        } catch (e) {
            console.error('queryStatisticsTest1 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
        console.log(TAG + "************* queryStatisticsTest1 end *************");
    })

    /**
     * @tc.name queryStatisticsTest
     * @tc.desc Test Js Api queryStatistics with parameters number are less
     * @tc.type: FUNC
     */
    it('queryStatisticsTest2', 0, async function (done) {
        console.log(TAG + "************* queryStatisticsTest2 start *************");
        try {
            const accountId = "test_id";
            await cloudData.Config.queryStatistics(accountId).then((etc) => {
                console.info('queryStatisticsTest2 success' + `, info is ${JSON.stringify(etc)}`);
                expect(null).assertFail();
            }).catch((error) => {
                console.error('queryStatisticsTest2 fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(null).assertFail();
            });
        } catch (e) {
            console.error('queryStatisticsTest2 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
        console.log(TAG + "************* queryStatisticsTest2 end *************");
    })

    /**
     * @tc.name queryStatisticsTest
     * @tc.desc Test Js Api queryStatistics with invalid args
     * @tc.type: FUNC
     */
    it('queryStatisticsTest3', 0, async function (done) {
        console.log(TAG + "************* queryStatisticsTest3 start *************");
        try {
            const accountId = 123;
            const bundleName = "bundleName";
            await cloudData.Config.queryStatistics(accountId, bundleName).then((etc) => {
                console.info('queryStatisticsTest3 success' + `, info is ${JSON.stringify(etc)}`);
                expect(null).assertFail();
            }).catch((error) => {
                console.error('queryStatisticsTest3 fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(null).assertFail();
            });
        } catch (e) {
            console.error('queryStatisticsTest3 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
        console.log(TAG + "************* queryStatisticsTest3 end *************");
    })

    /**
     * @tc.name queryStatisticsTest
     * @tc.desc Test Js Api queryStatistics with effective args
     * @tc.type: FUNC
     */
    it('queryStatisticsTest4', 0, async function (done) {
        console.log(TAG + "************* queryStatisticsTest4 start *************");
        try {
            const accountId = "accountId";
            const bundleName = "bundleName";
            await cloudData.Config.queryStatistics(accountId, bundleName).then((etc) => {
                console.info('queryStatisticsTest4 success' + `, info is ${JSON.stringify(etc)}`);
                expect(null).assertFail();
            }).catch((error) => {
                console.error('queryStatisticsTest4 fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(e.code == 201).assertTrue();
            });
        } catch (e) {
            console.error('queryStatisticsTest4 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e != null).assertTrue();
        }
        done();
        console.log(TAG + "************* queryStatisticsTest4 end *************");
    })

    /**
     * @tc.name queryStatisticsTest
     * @tc.desc Test Js Api queryStatistics with effective args
     * @tc.type: FUNC
     */
    it('queryStatisticsTest5', 0, async function (done) {
        console.log(TAG + "************* queryStatisticsTest5 start *************");
        try {
            const accountId = "accountId";
            const bundleName = "bundleName";
            await cloudData.Config.queryStatistics(accountId, bundleName, null).then((etc) => {
                console.info('queryStatisticsTest5 success' + `, info is ${JSON.stringify(etc)}`);
                expect(null).assertFail();
            }).catch((error) => {
                console.error('queryStatisticsTest5 fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(e.code == 201).assertTrue();
            });
        } catch (e) {
            console.error('queryStatisticsTest5 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e != null).assertTrue();
        }
        done();
        console.log(TAG + "************* queryStatisticsTest5 end *************");
    })

    /**
     * @tc.name queryStatisticsTest
     * @tc.desc Test Js Api queryStatistics with effective args
     * @tc.type: FUNC
     */
    it('queryStatisticsTest6', 0, async function (done) {
        console.log(TAG + "************* queryStatisticsTest6 start *************");
        try {
            const accountId = "accountId";
            const bundleName = "bundleName";
            await cloudData.Config.queryStatistics(accountId, bundleName, undefined).then((etc) => {
                console.info('queryStatisticsTest6 success' + `, info is ${JSON.stringify(etc)}`);
                expect(null).assertFail();
            }).catch((error) => {
                console.error('queryStatisticsTest6 fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(e.code == 201).assertTrue();
            });
        } catch (e) {
            console.error('queryStatisticsTest6 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e != null).assertTrue();
        }
        done();
        console.log(TAG + "************* queryStatisticsTest6 end *************");
    })

    /**
     * @tc.name queryStatisticsTest
     * @tc.desc Test Js Api queryStatistics with effective args
     * @tc.type: FUNC
     */
    it('queryStatisticsTest7', 0, async function (done) {
        console.log(TAG + "************* queryStatisticsTest7 start *************");

        try {
            const accountId = "accountId";
            const bundleName = "bundleName";
            const storeId = "storeId";
            await cloudData.Config.queryStatistics(accountId, bundleName, storeId).then((etc) => {
                console.info('queryStatisticsTest7 success' + `, info is ${JSON.stringify(etc)}`);
                expect(null).assertFail();
            }).catch((error) => {
                console.error('queryStatisticsTest7 fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(e.code == 201).assertTrue();
            });
        } catch (e) {
            console.error('queryStatisticsTest7 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e != null).assertTrue();
        }
        done();
        console.log(TAG + "************* queryStatisticsTest7 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CONFIG_SetGlobalCloudStrategy
     * @tc.name setGlobalCloudStrategyTest001
     * @tc.desc Test Js Api setGlobalCloudStrategy with parameters number are less
     */
    it('setGlobalCloudStrategyTest001', 0, async function (done) {
        console.log(TAG + "************* setGlobalCloudStrategyTest001 start *************");
        try {
            cloudData.Config.setGlobalCloudStrategy().then(() => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            });
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* setGlobalCloudStrategyTest001 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CONFIG_SetGlobalCloudStrategy
     * @tc.name setGlobalCloudStrategyTest002
     * @tc.desc Test Js Api setGlobalCloudStrategy with invalid args
     */
    it('setGlobalCloudStrategyTest002', 0, async function (done) {
        console.log(TAG + "************* setGlobalCloudStrategyTest002 start *************");
        try {
            cloudData.Config.setGlobalCloudStrategy(undefined).then(() => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            });
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* setGlobalCloudStrategyTest002 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CONFIG_SetGlobalCloudStrategy
     * @tc.name setGlobalCloudStrategyTest003
     * @tc.desc Test Js Api setGlobalCloudStrategy with invalid args
     */
    it('setGlobalCloudStrategyTest003', 0, async function (done) {
        console.log(TAG + "************* setGlobalCloudStrategyTest003 start *************");
        try {
            cloudData.Config.setGlobalCloudStrategy(cloudData.StrategyType.NETWORK, [undefined, "test"]).then(() => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            });
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* setGlobalCloudStrategyTest003 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CONFIG_SetGlobalCloudStrategy
     * @tc.name setGlobalCloudStrategyTest004
     * @tc.desc Test Js Api setGlobalCloudStrategy with invalid args
     */
    it('setGlobalCloudStrategyTest004', 0, async function (done) {
        console.log(TAG + "************* setGlobalCloudStrategyTest004 start *************");
        try {
            cloudData.Config.setGlobalCloudStrategy(cloudData.StrategyType.NETWORK, [cloudData.NetWorkStrategy.WIFI, "test"]).then(() => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            });
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* setGlobalCloudStrategyTest004 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CONFIG_SetGlobalCloudStrategy
     * @tc.name setGlobalCloudStrategyTest005
     * @tc.desc Test Js Api setGlobalCloudStrategy with valid args
     */
    it('setGlobalCloudStrategyTest005', 0, async function (done) {
        console.log(TAG + "************* setGlobalCloudStrategyTest005 start *************");
        try {
            await cloudData.Config.setGlobalCloudStrategy(cloudData.StrategyType.NETWORK, [cloudData.NetWorkStrategy.WIFI]).then(() => {
                expect(null).assertFail();
            }).catch(err => {
                console.error(TAG + `setGlobalCloudStrategyTest005, errcode:${JSON.stringify(err)}.`);
                expect(err.code == 201).assertTrue();
            });
        } catch (err) {
            console.error(TAG + `setGlobalCloudStrategyTest005, errcode:${JSON.stringify(err)}.`);
            expect(err.code == 201).assertTrue();
        }
        done()
        console.log(TAG + "************* setGlobalCloudStrategyTest005 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CONFIG_SetGlobalCloudStrategy
     * @tc.name setGlobalCloudStrategyTest006
     * @tc.desc Test Js Api setGlobalCloudStrategy with valid args
     */
    it('setGlobalCloudStrategyTest006', 0, async function (done) {
        console.log(TAG + "************* setGlobalCloudStrategyTest006 start *************");
        try {
            await cloudData.Config.setGlobalCloudStrategy(cloudData.StrategyType.NETWORK, [cloudData.NetWorkStrategy.CELLULAR, cloudData.NetWorkStrategy.WIFI]).then(() => {
                expect(null).assertFail();
            }).catch(err => {
                console.error(TAG + `setGlobalCloudStrategyTest006, errcode:${JSON.stringify(err)}.`);
                expect(err.code == 201).assertTrue();
            });
        } catch (err) {
            console.error(TAG + `setGlobalCloudStrategyTest006, errcode:${JSON.stringify(err)}.`);
            expect(err.code == 201).assertTrue();
        }
        done()
        console.log(TAG + "************* setGlobalCloudStrategyTest006 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CONFIG_SetGlobalCloudStrategy
     * @tc.name setGlobalCloudStrategyTest007
     * @tc.desc Test Js Api setGlobalCloudStrategy with valid args
     */
    it('setGlobalCloudStrategyTest007', 0, async function (done) {
        console.log(TAG + "************* setGlobalCloudStrategyTest007 start *************");
        try {
            await cloudData.Config.setGlobalCloudStrategy(cloudData.StrategyType.NETWORK).then(() => {
                expect(null).assertFail();
            }).catch(err => {
                console.error(TAG + `setGlobalCloudStrategyTest007, errcode:${JSON.stringify(err)}.`);
                expect(err.code == 201).assertTrue();
            });
        } catch (err) {
            console.error(TAG + `setGlobalCloudStrategyTest007, errcode:${JSON.stringify(err)}.`);
            expect(err.code == 201).assertTrue();
        }
        done()
        console.log(TAG + "************* setGlobalCloudStrategyTest007 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CONFIG_SetGlobalCloudStrategy
     * @tc.name setGlobalCloudStrategyTest008
     * @tc.desc Test Js Api setGlobalCloudStrategy with valid args
     */
    it('setGlobalCloudStrategyTest008', 0, async function (done) {
        console.log(TAG + "************* setGlobalCloudStrategyTest008 start *************");
        try {
            await cloudData.Config.setGlobalCloudStrategy(cloudData.StrategyType.NETWORK, undefined).then(() => {
                expect(null).assertFail();
            }).catch(err => {
                console.error(TAG + `setGlobalCloudStrategyTest008, errcode:${JSON.stringify(err)}.`);
                expect(err.code == 201).assertTrue();
            });
        } catch (err) {
            console.error(TAG + `setGlobalCloudStrategyTest008, errcode:${JSON.stringify(err)}.`);
            expect(err.code == 201).assertTrue();
        }
        done()
        console.log(TAG + "************* setGlobalCloudStrategyTest008 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CONFIG_SetGlobalCloudStrategy
     * @tc.name setGlobalCloudStrategyTest009
     * @tc.desc Test Js Api setGlobalCloudStrategy with valid args
     */
    it('setGlobalCloudStrategyTest009', 0, async function (done) {
        console.log(TAG + "************* setGlobalCloudStrategyTest009 start *************");
        try {
            await cloudData.Config.setGlobalCloudStrategy(cloudData.StrategyType.NETWORK, null).then(() => {
                expect(null).assertFail();
            }).catch(err => {
                console.error(TAG + `setGlobalCloudStrategyTest009, errcode:${JSON.stringify(err)}.`);
                expect(err.code == 201).assertTrue();
            });
        } catch (err) {
            console.error(TAG + `setGlobalCloudStrategyTest009, errcode:${JSON.stringify(err)}.`);
            expect(err.code == 201).assertTrue();
        }
        done()
        console.log(TAG + "************* setGlobalCloudStrategyTest009 end *************");
    })

    /**
     * @tc.name QueryLastSyncInfoInvalidArgsTest001
     * @tc.desc Test Js Api QueryLastSyncInfo that accountId parameter is number
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoInvalidArgsTest001', 0, async function (done) {
        console.info('QueryLastSyncInfoInvalidArgsTest001');
        try {
            await cloudData.Config.queryLastSyncInfo(123, "bundleName");
            expect(false).assertTrue();
        } catch (e) {
            console.error('QueryLastSyncInfoInvalidArgsTest001 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name QueryLastSyncInfoInvalidArgsTest002
     * @tc.desc Test Js Api QueryLastSyncInfo that bundleName parameter is number
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoInvalidArgsTest002', 0, async function (done) {
        console.info('QueryLastSyncInfoInvalidArgsTest002');
        try {
            await cloudData.Config.queryLastSyncInfo("id", 123);
            expect(false).assertTrue();
        } catch (e) {
            console.error('QueryLastSyncInfoInvalidArgsTest002 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name QueryLastSyncInfoInvalidArgsTest003
     * @tc.desc Test Js Api QueryLastSyncInfo that lack accountId parameter
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoInvalidArgsTest003', 0, async function (done) {
        console.info('QueryLastSyncInfoInvalidArgsTest003');
        try {
            await cloudData.Config.queryLastSyncInfo();
            expect(false).assertTrue();
        } catch (e) {
            console.error('QueryLastSyncInfoInvalidArgsTest003 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name QueryLastSyncInfoInvalidArgsTest004
     * @tc.desc Test Js Api QueryLastSyncInfo that lack bundleName parameter
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoInvalidArgsTest004', 0, async function (done) {
        console.info('QueryLastSyncInfoInvalidArgsTest004');
        try {
            await cloudData.Config.queryLastSyncInfo("id");
            expect(false).assertTrue();
        } catch (e) {
            console.error('QueryLastSyncInfoInvalidArgsTest004 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name QueryLastSyncInfoInvalidArgsTest005
     * @tc.desc Test Js Api QueryLastSyncInfo that storeName parameter is undefined
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoInvalidArgsTest005', 0, async function (done) {
        console.info('QueryLastSyncInfoInvalidArgsTest005');
        try {
            await cloudData.Config.queryLastSyncInfo("id", "bundleName", undefined);
            expect(false).assertTrue();
        } catch (e) {
            console.error('QueryLastSyncInfoInvalidArgsTest005 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 201).assertTrue();
        }
        done();
    })

    /**
     * @tc.name QueryLastSyncInfoInvalidArgsTest006
     * @tc.desc Test Js Api QueryLastSyncInfo that storeName parameter is null
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoInvalidArgsTest006', 0, async function (done) {
        console.info('QueryLastSyncInfoInvalidArgsTest006');
        try {
            await cloudData.Config.queryLastSyncInfo("id", "bundleName", null);
            expect(false).assertTrue();
        } catch (e) {
            console.error('QueryLastSyncInfoInvalidArgsTest006 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 201).assertTrue();
        }
        done();
    })

    /**
     * @tc.name QueryLastSyncInfoValidArgsTest001
     * @tc.desc Test Js Api QueryLastSyncInfo that all parameters is valid
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoValidArgsTest001', 0, async function (done) {
        console.info('QueryLastSyncInfoValidArgsTest001');
        try {
            await cloudData.Config.queryLastSyncInfo("id", "bundleName", "storeId");
            expect(false).assertTrue();
        } catch (e) {
            console.error('QueryLastSyncInfoValidArgsTest001 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 201).assertTrue();
        }
        done();
    })

    /**
     * @tc.name QueryLastSyncInfoValidArgsTest002
     * @tc.desc Test Js Api QueryLastSyncInfo that lack storeId parameter
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoValidArgsTest002', 0, async function (done) {
        console.info('QueryLastSyncInfoValidArgsTest002');
        try {
            await cloudData.Config.queryLastSyncInfo("id", "bundleName");
            expect(false).assertTrue();
        } catch (e) {
            console.error('QueryLastSyncInfoValidArgsTest002 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 201).assertTrue();
        }
        done();
    })

    /**
     * @tc.name CloudSync001
     * @tc.desc Test Js Api cloudSync
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync001', 0, async function (done) {
        console.info('CloudSync001');
        function Progress(detail) {
            console.log('CloudSync001 Progress: ' + JSON.Stringify(detail));
        }
        try {
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync001 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 201).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync002
     * @tc.desc Test Js Api cloudSync, invalid param, no progress
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync002', 0, async function (done) {
        console.info('CloudSync002');
        try {
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync002 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync003
     * @tc.desc Test Js Api cloudSync, invalid param, empty storeId
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync003', 0, async function (done) {
        console.info('CloudSync003');
        function Progress(detail) {
            console.log('CloudSync003 Progress: ' + JSON.Stringify(detail));
        }
        try {
            await cloudData.Config.cloudSync("bundleName", "", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync003 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync004
     * @tc.desc Test Js Api cloudSync, invalid param, wrong syncMode
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync004', 0, async function (done) {
        console.info('CloudSync004');
        function Progress(detail) {
            console.log('CloudSync004 Progress: ' + JSON.Stringify(detail));
        }
        try {
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_PUSH, Progress);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync004 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync005
     * @tc.desc Test Js Api cloudSync, invalid param, wrong syncMode
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync005', 0, async function (done) {
        console.info('CloudSync005');
        function Progress(detail) {
            console.log('CloudSync005 Progress: ' + JSON.Stringify(detail));
        }
        try {
            await cloudData.Config.cloudSync("bundleName", "storeId", 100, Progress);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync005 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync006
     * @tc.desc Test Js Api cloudSync, invalid param, empty bundleName
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync006', 0, async function (done) {
        console.info('CloudSync006');
        function Progress(detail) {
            console.log('CloudSync006 Progress: ' + JSON.Stringify(detail));
        }
        try {
            await cloudData.Config.cloudSync("", "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync006 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync007
     * @tc.desc Test Js Api cloudSync, invalid param, bundleName is null
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync007', 0, async function (done) {
        console.info('CloudSync007');
        function Progress(detail) {
            console.log('CloudSync007 Progress: ' + JSON.Stringify(detail));
        }
        try {
            await cloudData.Config.cloudSync(null, "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync007 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync008
     * @tc.desc Test Js Api cloudSync, invalid param, bundleName is undefined
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync008', 0, async function (done) {
        console.info('CloudSync008');
        function Progress(detail) {
            console.log('CloudSync008 Progress: ' + JSON.Stringify(detail));
        }
        try {
            await cloudData.Config.cloudSync(undefined, "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync008 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync009
     * @tc.desc Test Js Api cloudSync, invalid param, progress is null
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync009', 0, async function (done) {
        console.info('CloudSync009');
        try {
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, null);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync009 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync010
     * @tc.desc Test Js Api cloudSync, invalid param, progress is undefined
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync010', 0, async function (done) {
        console.info('CloudSync010');
        try {
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, undefined);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync010 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })
})