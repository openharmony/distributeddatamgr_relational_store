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

let rpc = requireNapi('rpc');

const TAG = "sharingCenterExtension";

export var cloudExtension;
!function(e) {
    let t;
    !function(e) {
        e[e.ConnectShareCenter = 0] = "ConnectShareCenter"
    }(t = e.CloudService_Function || (e.CloudService_Function = {}));
    let r;
    !function(e) {
        e[e.Share = 0] = "Share";
        e[e.Unshare = 1] = "Unshare";
        e[e.Exit = 2] = "Exit";
        e[e.ChangePrivilege = 3] = "ChangePrivilege";
        e[e.QueryParticipants = 4] = "QueryParticipants";
        e[e.QueryParticipantsByInvitation = 5] = "QueryParticipantsByInvitation";
        e[e.ConfirmInvitation = 6] = "ConfirmInvitation";
        e[e.ChangeConfirmation = 7] = "ChangeConfirmation";
    }(r = e.ShareCenter_Function || (e.ShareCenter_Function = {}));

    class n extends rpc.RemoteObject {
        constructor(e, t) {
            super(e);
            this.cloudService = t;
            console.info(`${TAG} CloudServiceProxy constructor`);
        }

        async onRemoteMessageRequest(e, r, n, i) {
            console.info(`${TAG}, onRemoteRequest called, code: ${e}`);
            i.setWaitTime(1e3);
            if (e === t.ConnectShareCenter) {
                let e = r.readInt();
                let t = r.readString();
                let i = await this.cloudService.connectShareCenter(e, t);
                if (null == i) {
                    console.error(`${TAG}, sharingCenter is null`);
                    return !1;
                }
                n.writeRemoteObject(i);
                return !0;
            }
            console.error(`${TAG}, invalid request code: ${e}`);
            return !1;
        }
    }

    e.CloudServiceProxy = n;

    class i extends rpc.RemoteObject {
        constructor(e, t) {
            super(e);
            this.shareCenter = t;
            console.info(`${TAG} shareCenter constructor`);
        }

        async onRemoteMessageRequest(e, t, n, i) {
            console.info(`${TAG}, shareCenter onRemoteRequest called, code: ${e}`);
            if (null == this.shareCenter) {
                console.info(`${TAG}, shareCenter undefined`);
                return !1;
            }
            i.setWaitTime(1500);
            switch(e) {
                case r.Share:
                    let e = t.readInt();
                    let i = t.readString();
                    let a = t.readString();
                    let l = this.unMarshallingParticipants(t);
                    let o = await this.shareCenter.share(e, i, a, l);
                    this.marshallingResults(n, o);
                    return !0;
                case r.Unshare:
                    let s = t.readInt();
                    let c = t.readString();
                    let h = t.readString();
                    let d = this.unMarshallingParticipants(t);
                    let u = await this.shareCenter.unshare(s, c, h, d);
                    this.marshallingResults(n, u);
                    return !0;
                case r.Exit:
                    let g = t.readInt();
                    let S = t.readString();
                    let w = t.readString();
                    let C = await this.shareCenter.exit(g, S, w);
                    n.writeInt(C.code);
                    C.description ? n.writeString(C.description) : n.writeString("");
                    return !0;
                case r.ChangePrivilege:
                    let v = t.readInt();
                    let p = t.readString();
                    let I = t.readString();
                    let f = this.unMarshallingParticipants(t);
                    let m = await this.shareCenter.changePrivilege(v, p, I, f);
                    this.marshallingResults(n, m);
                    return !0;
                case r.QueryParticipants:
                    let P = t.readInt();
                    let y = t.readString();
                    let B = t.readString();
                    let R = await this.shareCenter.queryParticipants(P, y, B);
                    this.marshallingResultsArray(n, R);
                    return !0;
                case r.QueryParticipantsByInvitation:
                    let x = t.readInt();
                    let A = t.readString();
                    let b = t.readString();
                    let T = await this.shareCenter.queryParticipantsByInvitation(x, A, b);
                    this.marshallingResultsArray(n, T);
                    return !0;
                case r.ConfirmInvitation:
                    let $ = t.readInt();
                    let E = t.readString();
                    let G = t.readString();
                    let M = t.readInt();
                    let q = await this.shareCenter.confirmInvitation($, E, G, M);
                    n.writeInt(q.code);
                    q.description ? n.writeString(q.description) : n.writeString("");
                    q.value ? n.writeString(q.value) : n.writeString("");
                    return !0;
                case r.ChangeConfirmation:
                    let Q = t.readInt();
                    let _ = t.readString();
                    let F = t.readString();
                    let j = t.readInt();
                    let O = await this.shareCenter.changeConfirmation(Q, _, F, j);
                    n.writeInt(O.code);
                    O.description ? n.writeString(O.description) : n.writeString("");
                    return !0;
                default:
                    console.info(`${TAG}, invalid request code`);
            }
            return !1
        }

        unMarshallingParticipants(e) {
            let t = [];
            let r = e.readInt();
            console.info(`${TAG}, array length: ${r}`);
            for (let n = 0; n < r; n++) t.push(this.unMarshallingParticipant(e));
            return t;
        }

        unMarshallingParticipant(e) {
            let t = e.readString();
            let r;
            let n = e.readInt();
            let i = e.readInt();
            r = {
                identity: t,
                role: -1 == n ? void 0 : n,
                state: -1 == i ? void 0 : i,
                privilege: this.unMarshallingPrivilege(e),
                attachInfo: e.readString()
            };
            return r;
        }

        unMarshallingPrivilege(e) {
            let t;
            t = {
                writable: e.readBoolean(),
                readable: e.readBoolean(),
                creatable: e.readBoolean(),
                deletable: e.readBoolean(),
                shareable: e.readBoolean()
            };
            return t;
        }

        marshallingResultsArray(e, t) {
            e.writeInt(t.code);
            t.description ? e.writeString(t.description) : e.writeString("");
            if (t.value) {
                e.writeInt(t.value.length);
                t.value.forEach((t => {
                    this.marshallingParticipant(e, t);
                }))
            }
        }

        marshallingResults(e, t) {
            e.writeInt(t.code);
            t.description ? e.writeString(t.description) : e.writeString("");
            if (t.value) {
                e.writeInt(t.value.length);
                t.value.forEach((t => {
                    e.writeInt(t.code);
                    t.description ? e.writeString(t.description) : e.writeString("");
                }))
            }
        }

        marshallingParticipant(e, t) {
            e.writeString(t.identity);
            void 0 !== t.role? e.writeInt(t.role) : e.writeInt(-1);
            void 0 !== t.state? e.writeInt(t.state) : e.writeInt(-1);
            if (t.privilege) this.marshallingPrivilege(e, t.privilege); else {
                e.writeBoolean(!1);
                e.writeBoolean(!1);
                e.writeBoolean(!1);
                e.writeBoolean(!1);
                e.writeBoolean(!1);
            }
            t.attachInfo ? e.writeString(t.attachInfo) : e.writeString("");
        }

        marshallingPrivilege(e, t) {
            e.writeBoolean(t.writable);
            e.writeBoolean(t.readable);
            e.writeBoolean(t.creatable);
            e.writeBoolean(t.deletable);
            e.writeBoolean(t.shareable);
        }
    }

    e.ShareCenterProxy = i;
    e.createCloudServiceStub = async function (e) {
        return new n('CloudServiceProxy', e);
    };
    e.createShareServiceStub = async function (e) {
        return new i('ShareCenterProxy', e);
    }
}(cloudExtension || (cloudExtension = {}));

export default {
    cloudExtension,
    createCloudServiceStub: cloudExtension.createCloudServiceStub,
    createShareServiceStub: cloudExtension.createShareServiceStub,
};