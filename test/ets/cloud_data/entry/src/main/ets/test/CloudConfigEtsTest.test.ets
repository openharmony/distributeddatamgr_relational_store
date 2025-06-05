/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or impligetProfileByAbilityEmptyAbilityCalled.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// @ts-nocheck
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from "@ohos/hypium"
import cloudData from '@ohos.data.cloudData';
import relationalStore from '@ohos.data.relationalStore';

export default function CloudConfigEtsTest() {
  describe('CloudConfigEtsTest', function () {
    beforeAll(function () {
      console.info('beforeAll called');
    })

    afterAll(function () {
      console.info('afterAll called');
    })

    beforeEach(function () {
      console.info('beforeEach called');
    })

    afterEach(async function () {
      console.info('afterEach called');
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
            // cloud config permission denied
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
        } catch (e) {
            console.error('CloudSync001 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 201).assertTrue();
        }
        done();
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
            // Parameter error. The number of parameters is incorrect.
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync002 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
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
            // Parameter error. The type of storeId must be string and not empty.
            await cloudData.Config.cloudSync("bundleName", "", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync003 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 14800001).assertTrue();
            done();
        }
        done();
    })

    /**
     * @tc.name CloudSync004
     * @tc.desc Test Js Api cloudSync, invalid param, storeId is null
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync004', 0, async function (done) {
        console.info('CloudSync004');
        function Progress(detail) {
            console.log('CloudSync004 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The type of storeId must be string and not empty.
            await cloudData.Config.cloudSync("bundleName", null, relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync004 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name CloudSync005
     * @tc.desc Test Js Api cloudSync, invalid param, storeId is undefined
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync005', 0, async function (done) {
        console.info('CloudSync005');
        function Progress(detail) {
            console.log('CloudSync005 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The type of storeId must be string and not empty.
            await cloudData.Config.cloudSync("bundleName", undefined, relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync005 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name CloudSync006
     * @tc.desc Test Js Api cloudSync, invalid param, wrong syncMode
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync006', 0, async function (done) {
        console.info('CloudSync006');
        function Progress(detail) {
            console.log('CloudSync006 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The syncMode is invalid.
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_PUSH, Progress);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync006 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 14800001).assertTrue();
            done();
        }
        done();
    })

    /**
     * @tc.name CloudSync007
     * @tc.desc Test Js Api cloudSync, invalid param, wrong syncMode
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync007', 0, async function (done) {
        console.info('CloudSync007');
        function Progress(detail) {
            console.log('CloudSync007 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The syncMode is invalid.
            await cloudData.Config.cloudSync("bundleName", "storeId", 100, Progress);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync007 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 14800001).assertTrue();
            done();
        }
        done();
    })

    /**
     * @tc.name CloudSync008
     * @tc.desc Test Js Api cloudSync, invalid param, wrong syncMode
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync008', 0, async function (done) {
        console.info('CloudSync008');
        function Progress(detail) {
            console.log('CloudSync008 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The type of syncMode must be number.
            await cloudData.Config.cloudSync("bundleName", "storeId", "syncMode", Progress);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync008 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name CloudSync009
     * @tc.desc Test Js Api cloudSync, invalid param, empty bundleName
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync009', 0, async function (done) {
        console.info('CloudSync009');
        function Progress(detail) {
            console.log('CloudSync009 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The type of bundleName must be string and not empty.
            await cloudData.Config.cloudSync("", "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync009 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 14800001).assertTrue();
            done();
        }
        done();
    })

    /**
     * @tc.name CloudSync010
     * @tc.desc Test Js Api cloudSync, invalid param, bundleName is null
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync010', 0, async function (done) {
        console.info('CloudSync010');
        function Progress(detail) {
            console.log('CloudSync010 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The type of bundleName must be string and not empty.
            await cloudData.Config.cloudSync(null, "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync010 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name CloudSync011
     * @tc.desc Test Js Api cloudSync, invalid param, bundleName is undefined
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync011', 0, async function (done) {
        console.info('CloudSync011');
        function Progress(detail) {
            console.log('CloudSync011 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The type of bundleName must be string and not empty.
            await cloudData.Config.cloudSync(undefined, "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync011 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name CloudSync012
     * @tc.desc Test Js Api cloudSync, invalid param, progress is null
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync012', 0, async function (done) {
        console.info('CloudSync012');
        try {
            // Parameter error. The type progress should be function.
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, null);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync012 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name CloudSync013
     * @tc.desc Test Js Api cloudSync, invalid param, progress is undefined
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync013', 0, async function (done) {
        console.info('CloudSync013');
        try {
            // Parameter error. The type progress should be function.
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, undefined);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync013 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name CloudSync014
     * @tc.desc Test Js Api cloudSync, invalid param, progress is undefined
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync014', 0, async function (done) {
        console.info('CloudSync014');
        try {
            // Parameter error. The type progress should be function.
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, 123);
            expect(false).assertTrue();
        } catch (e) {
            console.error('CloudSync014 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })
  })
}