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
     * @tc.name EnabledCloudInvalidArgsCallbackTest
     * @tc.desc Test Js Api EnabledCloud with invalid args
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('EnabledCloudInvalidArgsCallbackTest', 0, async function (done) {
        console.info('EnabledCloudInvalidArgsCallbackTest');
        try {
            let account = "test_id";
            await cloudData.Config.enableCloud(account, null, function (err) {
                if (err == undefined) {
                    expect(null).assertFail();
                    console.info('EnabledCloudInvalidArgsCallbackTest enableCloud success');
                    done();
                    return;
                }
                console.error('EnabledCloudInvalidArgsCallbackTest enableCloud fail' + `, error code is ${err.code}, message is ${err.message}`);
                expect(null).assertFail();
                done();
            });
        } catch (e) {
            console.error('EnabledCloudInvalidArgsCallbackTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })


    /**
     * @tc.name EnabledCloudInvalidArgsNumCallbackTest
     * @tc.desc Test Js Api EnabledCloud which parameters number are less
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('EnabledCloudInvalidArgsNumCallbackTest', 0, function (done) {
        console.info('EnabledCloudInvalidArgsNumCallbackTest');
        try {
            let account = "test_id";
            cloudData.Config.enableCloud(account, function (err) {
                if (err == undefined) {
                    expect(null).assertFail();
                    console.info('EnabledCloudInvalidArgsNumCallbackTest enableCloud success');
                    done();
                    return;
                }
                console.error('EnabledCloudCallbackTest enableCloud fail' + `, error code is ${err.code}, message is ${err.message}`);
                expect(null).assertFail();
                done();
            });
        } catch (e) {
            console.error('EnabledCloudCallbackTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name DisableCloudInvalidArgsCallbackTest
     * @tc.desc Test Js Api DisableCloud with invalid args
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('DisableCloudInvalidArgsCallbackTest', 0, function (done) {
        console.info('DisableCloudInvalidArgsCallbackTest');
        try {
            cloudData.Config.disableCloud(null, function (err) {
                if (err == undefined) {
                    expect(null).assertFail();
                    console.info('DisableCloudInvalidArgsCallbackTest disableCloud success');
                    done();
                    return;
                }
                console.error('DisableCloudInvalidArgsCallbackTest disableCloud fail' + `, error code is ${err.code}, message is ${err.message}`);
                expect(null).assertFail();
                done();
            });
        } catch (e) {
            console.error('DisableCloudInvalidArgsCallbackTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name DisableCloudInvalidArgsNumsCallbackTest
     * @tc.desc Test Js Api DisableCloud which parameters number are less
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('DisableCloudInvalidArgsNumsCallbackTest', 0, function (done) {
        console.info('DisableCloudInvalidArgsNumsCallbackTest');
        try {
            cloudData.Config.disableCloud(function (err) {
                if (err == undefined) {
                    expect(null).assertFail();
                    console.info('DisableCloudInvalidArgsNumsCallbackTest disableCloud success');
                    done();
                    return;
                }
                console.error('DisableCloudInvalidArgsNumsCallbackTest disableCloud fail' + `, error code is ${err.code}, message is ${err.message}`);
                expect(null).assertFail();
                done();
            });
        } catch (e) {
            console.error('DisableCloudInvalidArgsNumsCallbackTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name ChangeAppCloudInvalidArgsCallbackTest
     * @tc.desc Test Js Api ChangeAppCloudSwitch with invalid args
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('ChangeAppCloudInvalidArgsTest', 0, function (done) {
        console.info('ChangeAppCloudInvalidArgsCallbackTest');
        try {
            let account = "test_id";
            let bundleName = "test_bundleName";
            cloudData.Config.changeAppCloudSwitch(account, bundleName, null, function (err) {
                if (err == undefined) {
                    expect(null).assertFail();
                    console.info('ChangeAppCloudInvalidArgsCallbackTest changeAppCloudSwitch success');
                    done();
                    return;
                }
                console.error('ChangeAppCloudInvalidArgsCallbackTest changeAppCloudSwitch fail' + `, error code is ${err.code}, message is ${err.message}`);
                expect(null).assertFail();
                done();
            });
        } catch (e) {
            console.error('ChangeAppCloudInvalidArgsCallbackTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name ChangeAppCloudInvalidArgsNumsCallbackTest
     * @tc.desc Test Js Api ChangeAppCloudSwitch which parameters number are less
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('ChangeAppCloudInvalidArgsNumsCallbackTest', 0, function (done) {
        console.info('ChangeAppCloudInvalidArgsNumsCallbackTest');
        try {
            let account = "test_id";
            let bundleName = "test_bundleName";
            cloudData.Config.changeAppCloudSwitch(account, bundleName, function (err) {
                if (err == undefined) {
                    expect(null).assertFail();
                    console.info('ChangeAppCloudInvalidArgsNumsCallbackTest changeAppCloudSwitch success');
                    done();
                    return;
                }
                console.error('ChangeAppCloudInvalidArgsNumsCallbackTest changeAppCloudSwitch fail' + `, error code is ${err.code}, message is ${err.message}`);
                expect(null).assertFail();
                done();
            });
        } catch (e) {
            console.error('ChangeAppCloudInvalidArgsNumsCallbackTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name NotifyChangeInvalidArgsCallbackTest
     * @tc.desc Test Js Api NotifyChange with invalid args
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('NotifyChangeInvalidArgsCallbackTest', 0, function (done) {
        console.info('NotifyChangeInvalidArgsCallbackTest');
        try {
            let account = "test_id";
            cloudData.Config.notifyDataChange(account, null, function (err) {
                if (err == undefined) {
                    expect(null).assertFail();
                    console.info('NotifyChangeInvalidArgsCallbackTest notifyDataChange success');
                    done();
                    return;
                }
                console.error('NotifyChangeInvalidArgsCallbackTest notifyDataChange fail' + `, error code is ${err.code}, message is ${err.message}`);
                expect(null).assertFail();
                done();
            });
        } catch (e) {
            console.error('NotifyChangeInvalidArgsCallbackTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name NotifyChangeInvalidArgsNumsCallbackTest
     * @tc.desc Test Js Api NotifyChange which parameters number are less
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('NotifyChangeInvalidArgsNumsCallbackTest', 0, function (done) {
        console.info('NotifyChangeInvalidArgsNumsCallbackTest');
        try {
            let account = "test_id";
            cloudData.Config.notifyDataChange(account, function (err) {
                if (err == undefined) {
                    expect(null).assertFail();
                    console.info('NotifyChangeInvalidArgsNumsCallbackTest notifyDataChange success');
                    done();
                    return;
                }
                console.error('NotifyChangeInvalidArgsNumsCallbackTest notifyDataChange fail' + `, error code is ${err.code}, message is ${err.message}`);
                expect(null).assertFail();
                done();
            });
        } catch (e) {
            console.error('NotifyChangeInvalidArgsNumsCallbackTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CleanInvalidArgsNumsCallbackTest
     * @tc.desc Test Js Api Clean which parameters number are less
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CleanInvalidArgsNumsCallbackTest', 0, function (done) {
        console.info('CleanInvalidArgsNumsCallbackTest');
        try {
            let account = "test_id";
            cloudData.Config.clean(account, function (err) {
                if (err == undefined) {
                    expect(null).assertFail();
                    console.info('CleanInvalidArgsNumsCallbackTest clean success');
                    done();
                    return;
                }
                console.error('CleanInvalidArgsNumsCallbackTest clean fail' + `, error code is ${err.code}, message is ${err.message}`);
                expect(null).assertFail();
                done();
            });
        } catch (e) {
            console.error('CleanInvalidArgsNumsCallbackTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CleanInvalidArgsCallbackTest
     * @tc.desc Test Js Api Clean which parameters are invalid
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CleanInvalidArgsCallbackTest', 0, function (done) {
        console.info('CleanInvalidArgsNumsCallbackTest');
        try {
            let account = "test_id";
            let bundleName1 = "test_bundleName1";
            let appActions = {[bundleName1]: 3};
            cloudData.Config.clean(account, appActions, function (err) {
                if (err == undefined) {
                    expect(null).assertFail();
                    console.info('CleanInvalidArgsCallbackTest clean success');
                    done();
                    return;
                }
                console.error('CleanInvalidArgsCallbackTest clean fail' + `, error code is ${err.code}, message is ${err.message}`);
                expect(null).assertFail();
                done();
            });
        } catch (e) {
            console.error('CleanInvalidArgsCallbackTest fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })
})
