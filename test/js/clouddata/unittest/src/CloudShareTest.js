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
import cloudData from '@ohos.data.cloudData'
import data_relationalStore from '@ohos.data.relationalStore';
import featureAbility from '@ohos.ability.featureAbility';

const TAG = "[CLOUD_SHARE_JSKITS_TEST]"
const STORE_NAME = "cloud_rdb.db"
let rdbStore = undefined;
let context = featureAbility.getContext()
const SHARING_RESOURCE = "test sharing resource"
const INVITATION_CODE = "test invitation code"
let privilegeEnable = {
    writable: true,
    readable: true,
    creatable: true,
    deletable: true,
    shareable: true
}
let privilegeDisable = {
    writable: false,
    readable: false,
    creatable: false,
    deletable: false,
    shareable: false
}
let participants1 = {
    identity: '0000000000',
    role: cloudData.sharing.Role.ROLE_INVITER,
    state: cloudData.sharing.State.STATE_UNKNOWN,
    privilege: privilegeEnable,
    attachInfo: 'attachInfo1'
}
let participants2 = {
    identity: '1111111111',
    role: cloudData.sharing.Role.ROLE_INVITER,
    state: cloudData.sharing.State.STATE_UNKNOWN,
    privilege: privilegeDisable,
    attachInfo: 'attachInfo2'
}
let participants = [participants1, participants2];
const rowCount = 1;

describe('cloudSharingTest', function () {
    beforeAll(async function (done) {
        console.info("beforeAll");
        const config = {
            name: STORE_NAME,
            securityLevel: data_relationalStore.SecurityLevel.S1,
        }
        try {
            rdbStore = await data_relationalStore.getRdbStore(context, config);
            console.log(TAG + "create rdb store success")
            let sqlStatement = "CREATE TABLE IF NOT EXISTS employee (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "name TEXT NOT NULL," +
                "age INTEGER)"
            await rdbStore.executeSql(sqlStatement, null)
            console.log(TAG + "create table employee success")

            let valueBucket = {
                id: 1,
                name: "Linda",
                age: 18
            }
            await rdbStore.insert("employee", valueBucket).then((rowId) => {
                console.info(`Insert is successful, rowId = ${rowId}`);
            });
            done();
        } catch (err) {
            console.log(TAG + "create rdb store failed" + `, error code is ${err.code}, message is ${err.message}`)
            expect(null).assertFail()
        }
    })

    beforeEach(function () {
        console.info("beforeEach");
    })

    afterEach(function () {
        console.info("afterEach");
    })

    afterAll(async function () {
        console.info("afterAll");
        const DROP_TABLE_EMPLOYEE = "DROP TABLE IF EXISTS employee";
        await rdbStore.executeSql(DROP_TABLE_EMPLOYEE, null);
        rdbStore = null
        await data_relationalStore.deleteRdbStore(context, STORE_NAME);
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name allocResourceAndShareTest001
     * @tc.desc Test Js Api allocResourceAndShare with invalid args.
     */
    it('allocResourceAndShareTest001', 0, async function (done) {
        console.log(TAG + "************* allocResourceAndShareTest001 start *************");
        try {
            let predicates = new data_relationalStore.RdbPredicates("employee");
            predicates.equalTo("id", 1);
            cloudData.sharing.allocResourceAndShare(undefined, predicates, participants, (err, resultSet) => {
                done()
                if (err) {
                    console.log(TAG + `allocate resource and share failed, errcode:${err.code}, message ${err.message}.`);
                }
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* allocResourceAndShareTest001 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name allocResourceAndShareTest002
     * @tc.desc Test Js Api allocResourceAndShare with invalid args.
     */
    it('allocResourceAndShareTest002', 0, async function (done) {
        console.log(TAG + "************* allocResourceAndShareTest002 start *************");
        try {
            cloudData.sharing.allocResourceAndShare("employee", undefined, participants, (err, resultSet) => {
                done()
                if (err) {
                    console.log(TAG + `allocate resource and share failed, errcode:${err.code}, message ${err.message}.`);
                }
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* allocResourceAndShareTest002 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name allocResourceAndShareTest003
     * @tc.desc Test Js Api allocResourceAndShare with invalid args.
     */
    it('allocResourceAndShareTest003', 0, async function (done) {
        console.log(TAG + "************* allocResourceAndShareTest003 start *************");
        try {
            cloudData.sharing
            let predicates = new data_relationalStore.RdbPredicates("employee");
            predicates.equalTo("id", 1);
            cloudData.sharing.allocResourceAndShare("employee", predicates, undefined, (err, resultSet) => {
                done()
                if (err) {
                    console.log(TAG + `allocate resource and share failed, errcode:${err.code}, message ${err.message}.`);
                }
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* allocResourceAndShareTest003 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name allocResourceAndShareTest004
     * @tc.desc Test Js Api allocResourceAndShare with invalid args.
     */
    it('allocResourceAndShareTest004', 0, async function (done) {
        console.log(TAG + "************* allocResourceAndShareTest004 start *************");
        try {
            let predicates = new data_relationalStore.RdbPredicates("employee");
            predicates.equalTo("id", 1);
            const columns = ["id", "name", "age"];
            await cloudData.sharing.allocResourceAndShare(undefined, predicates, participants, columns).then((resultSet) => {
                expect(null).assertFail();
            }).catch((err) => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue()
        }
        done()
        console.log(TAG + "************* allocResourceAndShareTest004 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name allocResourceAndShareTest005
     * @tc.desc Test Js Api allocResourceAndShare with invalid args.
     */
    it('allocResourceAndShareTest005', 0, async function (done) {
        console.log(TAG + "************* allocResourceAndShareTest005 start *************");
        try {
            const columns = ["id", "name", "age"];
            await cloudData.sharing.allocResourceAndShare("employee", undefined, participants, columns).then((resultSet) => {
                expect(null).assertFail();
            }).catch((err) => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue()
        }
        done()
        console.log(TAG + "************* allocResourceAndShareTest005 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name allocResourceAndShareTest006
     * @tc.desc Test Js Api allocResourceAndShare with invalid args.
     */
    it('allocResourceAndShareTest006', 0, async function (done) {
        console.log(TAG + "************* allocResourceAndShareTest006 start *************");
        try {
            let predicates = new data_relationalStore.RdbPredicates("employee");
            predicates.equalTo("id", 1);
            const columns = ["id", "name", "age"];
            cloudData.sharing.allocResourceAndShare("employee", predicates, undefined, columns).then((resultSet) => {
                expect(null).assertFail();
            }).catch((err) => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue()
        }
        done();
        console.log(TAG + "************* allocResourceAndShareTest006 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name shareTest001
     * @tc.desc Test Js Api share with invalid args.
     */
    it("shareTest001", 0, async function (done) {
        console.log(TAG + "************* shareTest001 start *************");
        try {
            cloudData.sharing.share(undefined, participants, ((err, result) => {
                if (err) {
                    expect(null).assertFail();
                }
                expect(null).assertFail();
            }))
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done();
        console.log(TAG + "************* shareTest001 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name shareTest002
     * @tc.desc Test Js Api share with invalid args.
     */
    it("shareTest002", 0, async function (done) {
        console.log(TAG + "************* shareTest002 start *************");
        try {
            cloudData.sharing.share(SHARING_RESOURCE, undefined, ((err, result) => {
                if (err) {
                    expect(null).assertFail();
                }
                expect(null).assertFail();
            }))
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done();
        console.log(TAG + "************* shareTest002 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name shareTest003
     * @tc.desc Test Js Api share with invalid args.
     */
    it("shareTest003", 0, async function (done) {
        console.log(TAG + "************* shareTest003 start *************");
        try {
            cloudData.sharing.share(undefined, participants).then(result => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* shareTest003 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name shareTest004
     * @tc.desc Test Js Api share with invalid args.
     */
    it("shareTest004", 0, async function (done) {
        console.log(TAG + "************* shareTest004 start *************");
        try {
            cloudData.sharing.share(SHARING_RESOURCE, undefined).then(result => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* shareTest004 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name unshareTest001
     * @tc.desc Test Js Api unshare with invalid args.
     */
    it("unshareTest001", 0, async function (done) {
        console.log(TAG + "************* unshareTest001 start *************");
        try {
            cloudData.sharing.unshare(undefined, participants, ((err, result) => {
                if (err) {
                    expect(null).assertFail();
                }
                expect(null).assertFail();
            }))
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done();
        console.log(TAG + "************* unshareTest001 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name unshareTest002
     * @tc.desc Test Js Api unshare with invalid args.
     */
    it("unshareTest002", 0, async function (done) {
        console.log(TAG + "************* unshareTest002 start *************");
        try {
            cloudData.sharing.unshare(SHARING_RESOURCE, undefined, ((err, result) => {
                if (err) {
                    expect(null).assertFail();
                }
                expect(null).assertFail();
            }))
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done();
        console.log(TAG + "************* unshareTest002 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name unshareTest003
     * @tc.desc Test Js Api unshare with invalid args.
     */
    it("unshareTest003", 0, async function (done) {
        console.log(TAG + "************* unshareTest003 start *************");
        try {
            cloudData.sharing.unshare(undefined, participants).then(result => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* unshareTest003 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name unshareTest004
     * @tc.desc Test Js Api unshare with invalid args.
     */
    it("unshareTest004", 0, async function (done) {
        console.log(TAG + "************* unshareTest004 start *************");
        try {
            cloudData.sharing.unshare(SHARING_RESOURCE, undefined).then(result => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* unshareTest004 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name exitTest001
     * @tc.desc Test Js Api exit with invalid args.
     */
    it("exitTest001", 0, async function (done) {
        console.log(TAG + "************* exitTest001 start *************");
        try {
            cloudData.sharing.exit(undefined, ((err, result) => {
                if (err) {
                    expect(null).assertFail();
                }
                expect(null).assertFail();
            }))
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done();
        console.log(TAG + "************* exitTest001 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name exitTest002
     * @tc.desc Test Js Api exit with invalid args.
     */
    it("exitTest002", 0, async function (done) {
        console.log(TAG + "************* exitTest002 start *************");
        try {
            cloudData.sharing.exit(undefined).then(result => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* exitTest002 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name changePrivilegeTest001
     * @tc.desc Test Js Api changePrivilege with invalid args.
     */
    it("changePrivilegeTest001", 0, async function (done) {
        console.log(TAG + "************* changePrivilegeTest001 start *************");
        try {
            let changed1 = participants1;
            changed1.privilege = privilegeDisable;
            let changed2 = participants2;
            changed2.privilege = privilegeEnable;
            const changePart = [changed1, changed2];
            cloudData.sharing.changePrivilege(undefined, changePart, ((err, result) => {
                if (err) {
                    expect(null).assertFail();
                }
                expect(null).assertFail();
            }))
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* changePrivilegeTest001 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name changePrivilegeTest002
     * @tc.desc Test Js Api changePrivilege with invalid args.
     */
    it("changePrivilegeTest002", 0, async function (done) {
        console.log(TAG + "************* changePrivilegeTest002 start *************");
        try {
            cloudData.sharing.changePrivilege(SHARING_RESOURCE, undefined, ((err, result) => {
                if (err) {
                    expect(null).assertFail();
                }
                expect(null).assertFail();
            }))
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* changePrivilegeTest002 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name changePrivilegeTest003
     * @tc.desc Test Js Api changePrivilege with invalid args.
     */
    it("changePrivilegeTest003", 0, async function (done) {
        console.log(TAG + "************* changePrivilegeTest003 start *************");
        try {
            let changed1 = participants1;
            changed1.privilege = privilegeDisable;
            let changed2 = participants2;
            changed2.privilege = privilegeEnable;
            const changePart = [changed1, changed2];
            cloudData.sharing.changePrivilege(undefined, changePart).then(result => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* changePrivilegeTest003 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name changePrivilegeTest004
     * @tc.desc Test Js Api changePrivilege with invalid args.
     */
    it("changePrivilegeTest004", 0, async function (done) {
        console.log(TAG + "************* changePrivilegeTest004 start *************");
        try {
            cloudData.sharing.changePrivilege(SHARING_RESOURCE, undefined).then(result => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* changePrivilegeTest004 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name queryParticipantsTest001
     * @tc.desc Test Js Api queryParticipants with invalid args.
     */
    it("queryParticipantsTest001", 0, async function (done) {
        console.log(TAG + "************* queryParticipantsTest001 start *************");
        try {
            cloudData.sharing.queryParticipants(undefined, ((err, result) => {
                if (err) {
                    expect(null).assertFail();
                }
                expect(null).assertFail();
            }))
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done();
        console.log(TAG + "************* queryParticipantsTest001 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name queryParticipantsTest002
     * @tc.desc Test Js Api queryParticipants with invalid args.
     */
    it("queryParticipantsTest002", 0, async function (done) {
        console.log(TAG + "************* queryParticipantsTest002 start *************");
        try {
            cloudData.sharing.queryParticipants(undefined).then(result => {
                expect(null).assertFail();


            }).catch(err => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* queryParticipantsTest002 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name queryParticipantsByInvitationTest003
     * @tc.desc Test Js Api queryParticipantsByInvitation with invalid args.
     */
    it("queryParticipantsByInvitationTest003", 0, async function (done) {
        console.log(TAG + "************* queryParticipantsByInvitationTest003 start *************");
        try {
            cloudData.sharing.queryParticipantsByInvitation(undefined, ((err, result) => {
                if (err) {
                    expect(null).assertFail();
                }
                expect(null).assertFail();
            }))
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done();
        console.log(TAG + "************* queryParticipantsByInvitationTest003 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name queryParticipantsByInvitationTest004
     * @tc.desc Test Js Api queryParticipantsByInvitation with invalid args.
     */
    it("queryParticipantsByInvitationTest004", 0, async function (done) {
        console.log(TAG + "************* queryParticipantsByInvitationTest004 start *************");
        try {
            cloudData.sharing.queryParticipantsByInvitation(undefined).then(result => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* queryParticipantsByInvitationTest004 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name confirmInvitationTest001
     * @tc.desc Test Js Api confirmInvitation with invalid args.
     */
    it("confirmInvitationTest001", 0, async function (done) {
        console.log(TAG + "************* confirmInvitationTest001 start *************");
        try {
            cloudData.sharing.confirmInvitation(undefined, cloudData.sharing.State.STATE_SUSPENDED, ((err, result) => {
                if (err) {
                    expect(null).assertFail();
                }
                expect(null).assertFail();
            }))
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* confirmInvitationTest001 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name confirmInvitationTest002
     * @tc.desc Test Js Api confirmInvitation with invalid args.
     */
    it("confirmInvitationTest002", 0, async function (done) {
        console.log(TAG + "************* confirmInvitationTest002 start *************");
        try {
            cloudData.sharing.confirmInvitation(INVITATION_CODE, 100, ((err, result) => {
                if (err) {
                    expect(null).assertFail();
                }
                expect(null).assertFail();
            }))
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* confirmInvitationTest002 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name confirmInvitationTest003
     * @tc.desc Test Js Api confirmInvitation with invalid args.
     */
    it("confirmInvitationTest003", 0, async function (done) {
        console.log(TAG + "************* confirmInvitationTest003 start *************");
        try {
            cloudData.sharing.confirmInvitation(INVITATION_CODE, undefined, ((err, result) => {
                if (err) {
                    expect(null).assertFail();
                }
                expect(null).assertFail();
            }))
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* confirmInvitationTest003 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name confirmInvitationTest004
     * @tc.desc Test Js Api confirmInvitation with invalid args.
     */
    it("confirmInvitationTest004", 0, async function (done) {
        console.log(TAG + "************* confirmInvitationTest004 start *************");
        try {
            cloudData.sharing.confirmInvitation(undefined, cloudData.sharing.State.STATE_SUSPENDED).then(result => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* confirmInvitationTest004 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name confirmInvitationTest005
     * @tc.desc Test Js Api confirmInvitation with invalid args.
     */
    it("confirmInvitationTest005", 0, async function (done) {
        console.log(TAG + "************* confirmInvitationTest005 start *************");
        try {
            cloudData.sharing.confirmInvitation(SHARING_RESOURCE, 100).then(result => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* confirmInvitationTest005 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name confirmInvitationTest006
     * @tc.desc Test Js Api confirmInvitation with invalid args.
     */
    it("confirmInvitationTest006", 0, async function (done) {
        console.log(TAG + "************* confirmInvitationTest006 start *************");
        try {
            cloudData.sharing.confirmInvitation(SHARING_RESOURCE, undefined).then(result => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* confirmInvitationTest006 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name changeConfirmationTest001
     * @tc.desc Test Js Api changeConfirmation with invalid args.
     */
    it("changeConfirmationTest001", 0, async function (done) {
        console.log(TAG + "************* changeConfirmationTest001 start *************");
        try {
            cloudData.sharing.changeConfirmation(undefined, cloudData.sharing.State.STATE_SUSPENDED, ((err, result) => {
                if (err) {
                    expect(null).assertFail();
                }
                expect(null).assertFail();
            }))
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* changeConfirmationTest001 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name changeConfirmationTest002
     * @tc.desc Test Js Api changeConfirmation with invalid args.
     */
    it("changeConfirmationTest002", 0, async function (done) {
        console.log(TAG + "************* changeConfirmationTest002 start *************");
        try {
            cloudData.sharing.changeConfirmation(SHARING_RESOURCE, 100, ((err, result) => {
                if (err) {
                    expect(null).assertFail();
                }
                expect(null).assertFail();
            }))
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* changeConfirmationTest002 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name changeConfirmationTest003
     * @tc.desc Test Js Api changeConfirmation with invalid args.
     */
    it("changeConfirmationTest003", 0, async function (done) {
        console.log(TAG + "************* changeConfirmationTest003 start *************");
        try {
            cloudData.sharing.changeConfirmation(SHARING_RESOURCE, undefined, ((err, result) => {
                if (err) {
                    expect(null).assertFail();
                }
                expect(null).assertFail();
            }))
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* changeConfirmationTest003 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name changeConfirmationTest004
     * @tc.desc Test Js Api changeConfirmation with invalid args.
     */
    it("changeConfirmationTest004", 0, async function (done) {
        console.log(TAG + "************* changeConfirmationTest004 start *************");
        try {
            cloudData.sharing.changeConfirmation(undefined, cloudData.sharing.State.STATE_SUSPENDED).then(result => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* changeConfirmationTest004 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name changeConfirmationTest005
     * @tc.desc Test Js Api changeConfirmation with invalid args.
     */
    it("changeConfirmationTest005", 0, async function (done) {
        console.log(TAG + "************* changeConfirmationTest005 start *************");
        try {
            cloudData.sharing.changeConfirmation(SHARING_RESOURCE, 100).then(result => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* changeConfirmationTest005 end *************");
    })

    /**
     * @tc.number SUB_DDM_CLOUD_SHARE_0010
     * @tc.name changeConfirmationTest006
     * @tc.desc Test Js Api changeConfirmation with invalid args.
     */
    it("changeConfirmationTest006", 0, async function (done) {
        console.log(TAG + "************* changeConfirmationTest006 start *************");
        try {
            cloudData.sharing.changeConfirmation(SHARING_RESOURCE, undefined).then(result => {
                expect(null).assertFail();
            }).catch(err => {
                expect(null).assertFail();
            })
        } catch (err) {
            expect(err.code == 401).assertTrue();
        }
        done()
        console.log(TAG + "************* changeConfirmationTest006 end *************");
    })
})