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


import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import cloudData from '@ohos.data.cloudData';

describe('CloudConfigTest', function () {
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
     * @tc.name CleanInvalidArgsNumsTest
     * @tc.desc Test Js Api Clean which parameters number are less
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CleanInvalidArgsNumsTest', 0, async function (done) {
        console.info('CleanInvalidArgsNumsTest');
        try {
            let account = "test_id";
            await cloudData.Config.clean(account).then(() => {
                console.info('CleanInvalidArgsNumsTest success');
                expect(null).assertFail();
            }).catch((error) => {
                console.error('CleanInvalidArgsNumsTest clean fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(null).assertFail();
            });
        } catch (e) {
            console.error('CleanInvalidArgsNumsTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

    /**
     * @tc.name CleanInvalidArgsTest
     * @tc.desc Test Js Api Clean which parameters are invalid
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CleanInvalidArgsTest', 0, async function (done) {
        console.info('CleanInvalidArgsTest');
        try {
            let account = "test_id";
            let bundleName1 = "test_bundleName1";
            let appActions = {[bundleName1]: 3};
            await cloudData.Config.clean(account, appActions).then(() => {
                console.info('CleanInvalidArgsTest success');
                expect(null).assertFail();
            }).catch((error) => {
                console.error('CleanInvalidArgsTest clean fail' + `, error code is ${error.code}, message is ${error.message}`);
                expect(null).assertFail();
            });
        } catch (e) {
            console.error('CleanInvalidArgsTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
        }
        done();
    })

})
