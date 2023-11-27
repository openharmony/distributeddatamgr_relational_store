let rpc = requireNapi('rpc');

const TAG = "sharingCenterExtension";

export var cloudExtension;
!function(e) {
    let t;
    !function(e) {
        e[e.ConnectShareCenter = 0] = "ConnectShareCenter";
    }(t = e.CloudService_Function || (e.CloudService_Function = {}));
    let a;
    !function(e) {
        e[e.Share = 0] = "Share";
        e[e.Unshare = 1] = "Unshare";
        e[e.Exit = 2] = "Exit";
        e[e.ChangePrivilege = 3] = "ChangePrivilege";
        e[e.QueryParticipants = 4] = "QueryParticipants";
        e[e.QueryParticipantsByInvitation = 5] = "QueryParticipantsByInvitation";
        e[e.ConfirmInvitation = 6] = "ConfirmInvitation";
        e[e.ChangeConfirmation = 7] = "ChangeConfirmation";
    }(a = e.ShareCenter_Function || (e.ShareCenter_Function = {}));

    class r extends rpc.RemoteObject {
        constructor(e, t) {
            super(e);
            this.cloudService = t;
            console.info(`${TAG} CloudServiceProxy constructor`)
        }

        async onRemoteMessageRequest(e, a, r, n) {
            console.info(`${TAG}, onRemoteRequest called, code = ${e}`);
            n.setWaitTime(1e3);
            if (e === t.ConnectShareCenter) {
                let e = a.readInt();
                let t = a.readInt();
                let n = this.unMarshallingString(a.readRawData(t));
                let i = await this.cloudService.ConnectShareCenter(e, n);
                null == i && console.error(`${TAG}, sharingCenter is null`);
                r.writeRemoteObject(i);
                return !0
            }
            console.error(`${TAG}, invalid request code ${e}`);
            return !1
        }

        unMarshallingString(e) {
            let t = "";
            e.forEach((e => {
                t += String.fromCharCode(e)
            }));
            return t.toString()
        }
    }

    e.CloudServiceProxy = r;

    class n extends rpc.RemoteObject {
        constructor(e, t) {
            super(e);
            this.shareCenter = t;
            console.info(`${TAG} shareCenter constructor`)
        }

        async onRemoteMessageRequest(e, a, r, n) {
            console.info(`${TAG}, onRemoteRequest called, code = ${e}`);
            if (void 0 === this.shareCenter) return !1;
            n.setWaitTime(1500);
            switch(e) {
                case a.Share:
                    let e = t.readInt();
                    let n = t.readInt();
                    let i = this.unMarshallingString(t.readRawData(n));
                    let l = t.readInt();
                    let s = this.unMarshallingString(t.readRawData(l));
                    let o = this.unMarshallingParticipants(t);
                    let h = await this.shareCenter.share(e, i, s, o);
                    this.marshallingResults(r, h);
                    return !0;
                case a.Unshare:
                    let c = t.readInt();
                    let u = t.readInt();
                    let g = this.unMarshallingString(t.readRawData(u));
                    let d = t.readInt();
                    let I = this.unMarshallingString(t.readRawData(d));
                    let w = this.unMarshallingParticipants(t);
                    let S = await this.shareCenter.unshare(c, g, I, w);
                    this.marshallingResults(r, S);
                    return !0;
                case a.Exit:
                    let C = t.readInt();
                    let m = t.readInt();
                    let f = this.unMarshallingString(t.readRawData(m));
                    let p = t.readInt();
                    let v = this.unMarshallingString(t.readRawData(p));
                    let R = await this.shareCenter.exit(C, f, v);
                    r.writeInt(R.code);
                    R.description ? this.marshallingString(r, R.description) : r.writeInt(0);
                    return !0;
                case a.ChangePrivilege:
                    let M = t.readInt();
                    let P = t.readInt();
                    let y = this.unMarshallingString(t.readRawData(P));
                    let D = t.readInt();
                    let x = this.unMarshallingString(t.readRawData(D));
                    let b = this.unMarshallingParticipants(t);
                    let $ = await this.shareCenter.changePrivilege(M, y, x, b);
                    this.marshallingResults(r, $);
                    return !0;
                case a.QueryParticipants:
                    let B = t.readInt();
                    let A = t.readInt();
                    let E = this.unMarshallingString(t.readRawData(A));
                    let T = t.readInt();
                    let q = this.unMarshallingString(t.readRawData(T));
                    let j = await this.shareCenter.queryParticipants(B, E, q);
                    this.marshallingResultsArray(r, j);
                    return !0;
                case a.QueryParticipantsByInvitation:
                    let G = t.readInt();
                    let Q = t.readInt();
                    let F = this.unMarshallingString(t.readRawData(Q));
                    let O = t.readInt();
                    let _ = this.unMarshallingString(t.readRawData(O));
                    let z = await this.shareCenter.queryParticipantsByInvitation(G, F, _);
                    this.marshallingResultsArray(r, z);
                    return !0;
                case a.ConfirmInvitation:
                    let U = t.readInt();
                    let W = t.readInt();
                    let J = this.unMarshallingString(t.readRawData(W));
                    let N = t.readInt();
                    let k = this.unMarshallingString(t.readRawData(N));
                    let H = t.readInt();
                    let K = await this.shareCenter.confirmInvitation(U, J, k, H);
                    r.writeInt(K.code);
                    K.description ? this.marshallingString(r, K.description) : r.writeInt(0);
                    K.value ? this.marshallingString(r, K.value) : r.writeInt(0);
                    return !0;
                case a.ChangeConfirmation:
                    let L = t.readInt();
                    let V = t.readInt();
                    let X = this.unMarshallingString(t.readRawData(V));
                    let Y= t.readInt();
                    let Z = this.unMarshallingString(t.readRawData(Y));
                    let ee = t.readInt();
                    let te = await this.shareCenter.changeConfirmation(L, X, Z, ee);
                    r.writeInt(te.code);
                    te.description ? this.marshallingString(r, te.description) : r.writeInt(0);
                    return !0;
                default:
                    console.info(`${TAG}, invalid request code`)
            }
            return !1
        }

        unMarshallingParticipants(e) {
            let  t = [];
            let a = e.readInt();
            console.info(`${TAG}, query fields length = ${a}`);
            for (let r = 0; r < a; r++) t.push(this.unMarshallingParticipant(e));
            return t
        }

        unMarshallingParticipant(e) {
            let  t = e.readInt();
            let a;
            a = {
                identity: this.unMarshallingString(e.readRawData(t)),
                role: e.readInt(),
                state: e.readInt(),
                privilege: this.unMarshallingPrivilege(e),
                attachInfo: this.unMarshallingString(e.readRawData(e.readInt()))
            };
            return a
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
            return t
        }

        marshallingResultsArray(e, t) {
            e.writeInt(t.code);
            t.description ? this.marshallingString(e, t.description) : e.writeInt(0);
            if (t.value) {
                e.writeInt(t.value.length);
                t.value.forEach((t => {
                    this.marshallingParticipant(e, t)
                }))
            }
        }

        marshallingResults(e, t) {
            e.writeInt(t.code);
            t.description ? this.marshallingString(e, t.description) : e.writeInt(0);
            if (t.value) {
                e.writeInt(t.value.length);
                t.value.forEach((t => {
                    e.writeInt(t.code);
                    t.description ? this.marshallingString(e, t.description) : e.writeInt(0)
                }))
            }
        }

        marshallingParticipant(e, t) {
            this.marshallingString(e, t.identity);
            e.writeInt(t.role);
            e.writeInt(t.state);
            t.privilege && this.marshallingPrivilege(e, t.privilege);
            t.attachInfo ? this.marshallingString(e, t.attachInfo) : e.writeInt(0)
        }

        marshallingPrivilege(e, t) {
            e.writeBoolean(t.writable);
            e.writeBoolean(t.readable);
            e.writeBoolean(t.creatable);
            e.writeBoolean(t.deletable);
            e.writeBoolean(t.shareable);
        }

        unMarshallingString(e) {
            let t = "";
            e.forEach((e => {
                t += String.fromCharCode(e)
            }));
            return t.toString()
        }

        marshallingString(e, t) {
            let a = [];
            let r;
            r = t;
            let n = t.length;
            e.writeInt(n);
            for (let e = 0; e < n; e++) a.push(r.charCodeAt(e));
            e.writeRawData(a, n)
        }
    }

    e.ShareCenterProxy = n;
    e.createCloudServiceStub = async function (e) {
        return new r("CloudServiceProxy", e)
    };
    e.createShareServiceStub = async function (e) {
        return new n("ShareCenterProxy", e)
    }
}(cloudExtension || (cloudExtension = {}));

export default {
    cloudExtension,
    createCloudServiceStub: cloudExtension.createCloudServiceStub,
    createShareServiceStub: cloudExtension.createShareServiceStub,
};