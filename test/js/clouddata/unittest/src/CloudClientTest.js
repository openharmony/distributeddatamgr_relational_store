/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
import cloudData from '@ohos.data.cloudData'
import commonType from '@ohos.data.commonType';
import featureAbility from '@ohos.ability.featureAbility';
import StrategyType from "cloudData.StrategyType";
import NetWorkStrategy from "cloudData.NetWorkStrategy";

const TAG = "[CLOUD_CLIENT_JSKITS_TEST]"
describe('cloudClientTest', function () {
    beforeAll(async function (done) {
        console.info("beforeAll");
    })

    beforeEach(function () {
        console.info("beforeEach");
    })

    afterEach(function () {
        console.info("afterEach");
    })

    afterAll(async function () {
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CLIENT_0010
     * @tc.name setCloudStrategyTest001
     * @tc.desc Test Js Api setCloudStrategy with invalid args.
     */
    it('setCloudStrategyTest001', 0, async function (done) {
        console.log(TAG + "************* setCloudStrategyTest001 start *************");
        try {
            cloudData.setCloudStrategy().then(() => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            });
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* setCloudStrategyTest001 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CLIENT_0010
     * @tc.name setCloudStrategyTest002
     * @tc.desc Test Js Api setCloudStrategy with invalid args.
     */
    it('setCloudStrategyTest002', 0, async function (done) {
        console.log(TAG + "************* setCloudStrategyTest002 start *************");
        try {
            cloudData.setCloudStrategy(undefined).then(() => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            });
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* setCloudStrategyTest002 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CLIENT_0010
     * @tc.name setCloudStrategyTest003
     * @tc.desc Test Js Api setCloudStrategy with invalid args.
     */
    it('setCloudStrategyTest003', 0, async function (done) {
        console.log(TAG + "************* setCloudStrategyTest003 start *************");
        try {
            cloudData.setCloudStrategy(StrategyType.NETWORK, [undefined, "test"]).then(() => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            });
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* setCloudStrategyTest003 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CLIENT_0010
     * @tc.name setCloudStrategyTest004
     * @tc.desc Test Js Api setCloudStrategy with invalid args.
     */
    it('setCloudStrategyTest004', 0, async function (done) {
        console.log(TAG + "************* setCloudStrategyTest004 start *************");
        try {
            cloudData.setCloudStrategy(StrategyType.NETWORK, [NetWorkStrategy.WIFI, "test"]).then(() => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            });
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* setCloudStrategyTest004 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CLIENT_0010
     * @tc.name setCloudStrategyTest005
     * @tc.desc Test Js Api setCloudStrategy with valid args.
     */
    it('setCloudStrategyTest005', 0, async function (done) {
        console.log(TAG + "************* setCloudStrategyTest005 start *************");
        try {
            await cloudData.setCloudStrategy(StrategyType.NETWORK, [NetWorkStrategy.WIFI]).then(() => {
                expect(true).assertTrue();
            }).catch(err => {
                console.error(TAG + `setCloudStrategyTest005, errcode:${JSON.stringify(err)}.`);
                expect(null).assertFail();
            });
        } catch (err) {
            console.error(TAG + `setCloudStrategyTest005, errcode:${JSON.stringify(err)}.`);
            expect(null).assertFail();
        }
        done()
        console.log(TAG + "************* setCloudStrategyTest005 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CLIENT_0010
     * @tc.name setCloudStrategyTest006
     * @tc.desc Test Js Api setCloudStrategy with valid args.
     */
    it('setCloudStrategyTest006', 0, async function (done) {
        console.log(TAG + "************* setCloudStrategyTest006 start *************");
        try {
            await cloudData.setCloudStrategy(StrategyType.NETWORK, [NetWorkStrategy.CELLULAR, NetWorkStrategy.WIFI]).then(() => {
                expect(true).assertTrue();
            }).catch(err => {
                console.error(TAG + `setCloudStrategyTest006, errcode:${JSON.stringify(err)}.`);
                expect(null).assertFail();
            });
        } catch (err) {
            console.error(TAG + `setCloudStrategyTest006, errcode:${JSON.stringify(err)}.`);
            expect(null).assertFail();
        }
        done()
        console.log(TAG + "************* setCloudStrategyTest006 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CLIENT_0010
     * @tc.name setCloudStrategyTest007
     * @tc.desc Test Js Api setCloudStrategy with valid args.
     */
    it('setCloudStrategyTest007', 0, async function (done) {
        console.log(TAG + "************* setCloudStrategyTest007 start *************");
        try {
            await cloudData.setCloudStrategy(StrategyType.NETWORK).then(() => {
                expect(true).assertTrue();
            }).catch(err => {
                console.error(TAG + `setCloudStrategyTest007, errcode:${JSON.stringify(err)}.`);
                expect(null).assertFail();
            });
        } catch (err) {
            console.error(TAG + `setCloudStrategyTest007, errcode:${JSON.stringify(err)}.`);
            expect(null).assertFail();
        }
        done()
        console.log(TAG + "************* setCloudStrategyTest007 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CLIENT_0010
     * @tc.name setCloudStrategyTest008
     * @tc.desc Test Js Api setCloudStrategy with valid args.
     */
    it('setCloudStrategyTest008', 0, async function (done) {
        console.log(TAG + "************* setCloudStrategyTest008 start *************");
        try {
            await cloudData.setCloudStrategy(StrategyType.NETWORK, undefined).then(() => {
                expect(true).assertTrue();
            }).catch(err => {
                console.error(TAG + `setCloudStrategyTest008, errcode:${JSON.stringify(err)}.`);
                expect(null).assertFail();
            });
        } catch (err) {
            console.error(TAG + `setCloudStrategyTest008, errcode:${JSON.stringify(err)}.`);
            expect(null).assertFail();
        }
        done()
        console.log(TAG + "************* setCloudStrategyTest008 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_CLIENT_0010
     * @tc.name setCloudStrategyTest009
     * @tc.desc Test Js Api setCloudStrategy with valid args.
     */
    it('setCloudStrategyTest009', 0, async function (done) {
        console.log(TAG + "************* setCloudStrategyTest009 start *************");
        try {
            await cloudData.setCloudStrategy(StrategyType.NETWORK, null).then(() => {
                expect(true).assertTrue();
            }).catch(err => {
                console.error(TAG + `setCloudStrategyTest009, errcode:${JSON.stringify(err)}.`);
                expect(null).assertFail();
            });
        } catch (err) {
            console.error(TAG + `setCloudStrategyTest009, errcode:${JSON.stringify(err)}.`);
            expect(null).assertFail();
        }
        done()
        console.log(TAG + "************* setCloudStrategyTest009 end *************");
    })
})