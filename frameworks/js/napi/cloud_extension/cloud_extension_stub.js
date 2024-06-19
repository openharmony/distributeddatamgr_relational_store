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

let relationalStore = requireNapi('data.relationalStore');
let rpc = requireNapi('rpc');

const TAG = 'cloudExtension';
const INVALID_STATE = -1;
const INVALID_STR = '';
const MAX_SIZE = 4 * 1024 * 1024 * 1024 - 1;

export var cloudExtension;
(function (a) {
    let f;
    (function (f) {
        f[f["NULL"] = 0] = "NULL";
        f[f["NUMBER"] = 1] = "NUMBER";
        f[f["REAL"] = 2] = "REAL";
        f[f["TEXT"] = 3] = "TEXT";
        f[f["BOOL"] = 4] = "BOOL";
        f[f["BLOB"] = 5] = "BLOB";
        f[f["ASSET"] = 6] = "ASSET";
        f[f["ASSETS"] = 7] = "ASSETS";
    })(f = a.FieldType || (a.FieldType = {}));
    let g;
    (function (g) {
        g[g["SUCCESS"] = 0] = "SUCCESS";
        g[g["UNKNOWN_ERROR"] = 1] = "UNKNOWN_ERROR";
        g[g["NETWORK_ERROR"] = 2] = "NETWORK_ERROR";
        g[g["CLOUD_DISABLED"] = 3] = "CLOUD_DISABLED";
        g[g["LOCKED_BY_OTHERS"] = 4] = "LOCKED_BY_OTHERS";
        g[g["RECORD_LIMIT_EXCEEDED"] = 5] = "RECORD_LIMIT_EXCEEDED";
        g[g["NO_SPACE_FOR_ASSET"] = 6] = "NO_SPACE_FOR_ASSET";
    })(g = a.ErrorCode || (a.ErrorCode = {}));
    let h;
    (function (h) {
        h[h["ConnectShareCenter"] = 0] = "ConnectShareCenter";
        h[h["ConnectAssetLoader"] = 1] = "ConnectAssetLoader";
        h[h["ConnectDatabase"] = 2] = "ConnectDatabase";
        h[h["GetAppBriefInfo"] = 3] = "GetAppBriefInfo";
        h[h["GetServiceInfo"] = 4] = "GetServiceInfo";
        h[h["GetAppSchema"] = 5] = "GetAppSchema";
        h[h["Subscribe"] = 6] = "Subscribe";
        h[h["Unsubscribe"] = 7] = "Unsubscribe";
    })(h || (h = {}));
    let i;
    (function (i) {
        i[i["Share"] = 0] = "Share";
        i[i["Unshare"] = 1] = "Unshare";
        i[i["Exit"] = 2] = "Exit";
        i[i["ChangePrivilege"] = 3] = "ChangePrivilege";
        i[i["QueryParticipants"] = 4] = "QueryParticipants";
        i[i["QueryParticipantsByInvitation"] = 5] = "QueryParticipantsByInvitation";
        i[i["ConfirmInvitation"] = 6] = "ConfirmInvitation";
        i[i["ChangeConfirmation"] = 7] = "ChangeConfirmation";
    })(i || (i = {}));
    let j;
    (function (j) {
        j[j["GenerateIds"] = 0] = "GenerateIds";
        j[j["Insert"] = 1] = "Insert";
        j[j["Update"] = 2] = "Update";
        j[j["Delete"] = 3] = "Delete";
        j[j["Query"] = 4] = "Query";
        j[j["Lock"] = 5] = "Lock";
        j[j["Unlock"] = 6] = "Unlock";
        j[j["Heartbeat"] = 7] = "Heartbeat";
    })(j || (j = {}));
    let k;
    (function (k) {
        k[k["Download"] = 0] = "Download";
        k[k["Upload"] = 1] = "Upload";
    })(k || (k = {}));

    class l extends rpc.RemoteObject {
        constructor(q, r) {
            super(q);
            this.cloudService = r;
        }

        async onRemoteMessageRequest(s, t, u, v) {
            v.setWaitTime(1000);
            let w = this.getDescriptor();
            switch (s) {
                case h.GetServiceInfo:
                    let x = await this.cloudService.getServiceInfo();
                    this.marshallingCloudInfo(u, x);
                    return true;
                case h.GetAppBriefInfo:
                    let y = await this.cloudService.getAppBriefInfo();
                    this.marshallingAppBriefInfo(u, y);
                    return true;
                case h.GetAppSchema:
                    let z = t.readString();
                    let a1 = await this.cloudService.getAppSchema(z);
                    u.writeInt(a1.code);
                    if (a1.code === a.ErrorCode.SUCCESS) {
                        this.marshallingAppSchema(u, a1.value);
                    }
                    return true;
                case h.Subscribe:
                    let b1 = t.readLong();
                    let c1 = this.unMarshallingSubInfo(t);
                    let d1 = await this.cloudService.subscribe(c1, b1);
                    u.writeInt(d1.code);
                    if (d1.code === a.ErrorCode.SUCCESS) {
                        this.marshallingSubscribeInfo(u, d1.value);
                    }
                    return true;
                case h.Unsubscribe:
                    let e1 = this.unMarshallingUnSubInfo(t);
                    let f1 = await this.cloudService.unsubscribe(e1);
                    u.writeInt(f1 > 0 ? a.ErrorCode.SUCCESS : a.ErrorCode.UNKNOWN_ERROR);
                    return true;
                case h.ConnectDatabase:
                    let g1 = t.readString();
                    let h1 = this.unMarshallingDatabase(t);
                    let i1 = await this.cloudService.connectDB(g1, h1);
                    u.writeRemoteObject(i1);
                    return true;
                case h.ConnectAssetLoader:
                    let j1 = t.readString();
                    let k1 = this.unMarshallingDatabase(t);
                    let l1 = await this.cloudService.connectAssetLoader(j1, k1);
                    u.writeRemoteObject(l1);
                    return true;
                case h.ConnectShareCenter:
                    let m1 = t.readInt();
                    let n1 = t.readString();
                    let o1 = await this.cloudService.connectShareCenter(m1, n1);
                    if (o1 == null) {
                        return false;
                    }
                    u.writeRemoteObject(o1);
                    return true;
                default:
                    return false;
            }
        }

        marshallingCloudInfo(u, p1) {
            u.writeBoolean(p1.enableCloud);
            u.writeString(p1.id);
            u.writeLong(p1.totalSpace);
            u.writeLong(p1.remainingSpace);
            u.writeInt(p1.user);
        }

        marshallingAppBriefInfo(u, q1) {
            let r1 = Object.keys(q1);
            u.writeInt(r1.length);
            r1.forEach(s1 => {
                u.writeString(s1);
                let t1 = q1[s1];
                u.writeString(t1.appId);
                u.writeString(t1.bundleName);
                u.writeInt(t1.cloudSwitch ? 1 : 0);
                u.writeInt(t1.instanceId);
            });
        }

        marshallingAppSchema(u, u1) {
            u.writeInt(u1.version);
            u.writeString(u1.bundleName);
            u.writeInt(u1.databases.length);
            u1.databases.forEach((h1) => {
                u.writeString(h1.alias);
                u.writeString(h1.name);
                u.writeInt(h1.tables.length);
                h1.tables.forEach((v1) => {
                    u.writeString(v1.alias);
                    u.writeString(v1.name);
                    u.writeInt(v1.fields.length);
                    v1.fields.forEach((w1) => {
                        u.writeString(w1.alias);
                        u.writeString(w1.colName);
                        u.writeInt(w1.type);
                        u.writeBoolean(w1.primary);
                        u.writeBoolean(w1.nullable);
                    });
                });
            });
        }

        marshallingSubscribeInfo(u, x1) {
            u.writeLong(x1.expirationTime);
            let r1 = Object.keys(x1.subscribe);
            u.writeInt(r1.length);
            r1.forEach(s1 => {
                u.writeString(s1);
                let y1 = x1.subscribe[s1];
                u.writeInt(y1.length);
                y1.forEach(h1 => {
                    u.writeString(h1.databaseAlias);
                    u.writeString(h1.id);
                });
            });
        }

        unMarshallingSubInfo(t) {
            let z = t.readString();
            let c1 = {};
            let z1 = t.readInt();
            c1[z] = [];
            if (z1 < 0 || z1 > MAX_SIZE) {
                return c1;
            }
            for (let a2 = 0; a2 < z1; a2++) {
                c1[z].push(this.unMarshallingDatabase(t));
            }
            return c1;
        }

        unMarshallingUnSubInfo(t) {
            let e1 = {};
            let b2 = t.readInt();
            if (b2 < 0 || b2 > MAX_SIZE) {
                return e1;
            }
            for (let c2 = 0; c2 < b2; c2++) {
                let d2 = t.readString();
                e1[d2] = [];
                let e2 = t.readInt();
                if (e2 < 0 || e2 > MAX_SIZE) {
                    continue;
                }
                for (let f2 = 0; f2 < e2; f2++) {
                    e1[d2].push(t.readString());
                }
            }
            return e1;
        }

        unMarshallingDatabase(t) {
            let h1 = {
                alias: '',
                name: '',
                tables: []
            };
            h1.name = t.readString();
            h1.alias = t.readString();
            h1.tables = [];
            let g2 = t.readInt();
            if (g2 < 0 || g2 > MAX_SIZE) {
                return h1;
            }
            for (let c2 = 0; c2 < g2; c2++) {
                let h2 = t.readString();
                let i2 = t.readString();
                let v1 = {
                    alias: h2,
                    name: i2,
                    fields: []
                };
                h1.tables.push(v1);
                let j2 = t.readInt();
                if (j2 < 0 || j2 > MAX_SIZE) {
                    continue;
                }
                for (let k2 = 0; k2 < j2; k2++) {
                    let w1 = {
                        alias: t.readString(),
                        colName: t.readString(),
                        type: t.readInt(),
                        primary: t.readBoolean(),
                        nullable: t.readBoolean()
                    };
                    h1.tables[c2].fields.push(w1);
                }
            }
            return h1;
        }
    }

    a.CloudServiceStub = l;

    class m extends rpc.RemoteObject {
        constructor(q, i1) {
            super(q);
            this.cloudDb = i1;
        }

        async onRemoteMessageRequest(s, t, u, v) {
            if (this.cloudDb === undefined) {
                return false;
            }
            let w = this.getDescriptor();
            v.setWaitTime(1500);
            switch (s) {
                case j.GenerateIds:
                    let l2 = t.readInt();
                    let m2 = await this.cloudDb.generateId(l2);
                    u.writeInt(m2.code);
                    if (m2.code === 0) {
                        u.writeInt(m2.value.length);
                        m2.value.forEach(d3 => {
                            u.writeString(d3);
                        });
                    }
                    return true;
                case j.Insert:
                    let n2 = t.readString();
                    let o2 = this.unMarshallingValuesBuckets(t);
                    let p2 = this.unMarshallingValuesBuckets(t);
                    if (o2.length === 0) {
                        u.writeInt(0);
                        return true;
                    }
                    try {
                        let e3 = await this.cloudDb.insert(n2, o2, p2);
                        this.marshallingResultValueBucket(u, e3);
                    }
                    catch (f3) {
                        u.writeInt(g.UNKNOWN_ERROR);
                    }
                    return true;
                case j.Update:
                    let q2 = t.readString();
                    let r2 = this.unMarshallingValuesBuckets(t);
                    let s2 = this.unMarshallingValuesBuckets(t);
                    try {
                        let e3 = await this.cloudDb.update(q2, r2, s2);
                        this.marshallingResultValueBucket(u, e3);
                    }
                    catch (f3) {
                        u.writeInt(g.UNKNOWN_ERROR);
                    }
                    return true;
                case j.Delete:
                    let v1 = t.readString();
                    let t2 = this.unMarshallingValuesBuckets(t);
                    try {
                        let e3 = await this.cloudDb.delete(v1, t2);
                        this.marshallingResultValueBucket(u, e3);
                    }
                    catch (f3) {
                        u.writeInt(g.UNKNOWN_ERROR);
                    }
                    return true;
                case j.Query:
                    let u2 = t.readString();
                    let v2 = this.unMarshallingFiledArray(t);
                    let w2 = t.readInt();
                    let x2 = t.readString();
                    if (x2 === '') {
                        x2 = '0';
                    }
                    try {
                        let g3 = await this.cloudDb.query(u2, v2, w2, x2);
                        u.writeInt(g3.code);
                        if (g3.code === 0) {
                            this.marshallingCloudData(u, g3.value);
                        }
                    }
                    catch (f3) {
                        u.writeInt(g.UNKNOWN_ERROR);
                    }
                    return true;
                case j.Lock:
                    let y2 = await this.cloudDb.lock();
                    u.writeInt(y2.code);
                    if (y2.code === 0) {
                        u.writeInt(y2.value.interval);
                        u.writeInt(y2.value.lockId);
                    }
                    return true;
                case j.Heartbeat:
                    let z2 = t.readInt();
                    let a3 = await this.cloudDb.heartbeat(z2);
                    u.writeInt(a3.code);
                    if (a3.code === 0) {
                        u.writeInt(a3.value.interval);
                        u.writeInt(a3.value.lockId);
                    }
                    return true;
                case j.Unlock:
                    let b3 = t.readInt();
                    let c3 = await this.cloudDb.unlock(b3);
                    u.writeInt(c3.code);
                    if (a3.code === 0) {
                        u.writeBoolean(c3.value);
                    }
                    return true;
                default:
                    break;
            }
            return false;
        }

        unMarshallingFiledArray(t) {
            let v2 = [];
            let h3 = t.readInt();
            if (h3 < 0 || h3 > MAX_SIZE) {
                return v2;
            }
            for (let f2 = 0; f2 < h3; f2++) {
                v2.push(t.readString());
            }
            return v2;
        }

        marshallingCloudData(u, g3) {
            u.writeString(g3.nextCursor);
            u.writeBoolean(g3.hasMore);
            this.marshallingValuesBuckets(u, g3.values);
        }

        marshallingResultValueBucket(u, i3) {
            if (i3.length > MAX_SIZE) {
                return;
            }
            u.writeInt(i3.length);
            for (let f2 = 0; f2 < i3.length; f2++) {
                u.writeInt(i3[f2].code);
                if (i3[f2].value) {
                    let j3 = i3[f2].value;
                    this.marshallingValueBucket(u, j3);
                }
                else {
                    u.writeInt(0);
                }
            }
        }

        marshallingValueBucket(u, k3) {
            let r1 = Object.keys(k3);
            u.writeInt(r1.length);
            r1.forEach(s1 => {
                u.writeString(s1);
                let t1 = k3[s1];
                if (t1 === undefined || t1 === null) {
                    u.writeInt(f.NULL);
                }
                else {
                    if (typeof t1 === 'number') {
                        if (Number(t1).toString().indexOf('.') !== -1) {
                            u.writeInt(f.REAL);
                            u.writeFloat(t1);
                        }
                        else {
                            u.writeInt(f.NUMBER);
                            u.writeLong(t1);
                        }
                    }
                    else if (typeof t1 === 'string') {
                        u.writeInt(f.TEXT);
                        u.writeString(t1);
                    }
                    else if (typeof t1 === 'boolean') {
                        u.writeInt(f.BOOL);
                        u.writeBoolean(t1);
                    }
                    else {
                        if (t1 instanceof Array) {
                            u.writeInt(f.ASSETS);
                            u.writeInt(t1.length);
                            t1.forEach((d3) => {
                                u.writeString(d3.name);
                                u.writeString(d3.uri);
                                u.writeString(d3.path);
                                u.writeString(d3.createTime);
                                u.writeString(d3.modifyTime);
                                u.writeString(d3.size);
                                if (d3.status) {
                                    u.writeInt(d3.status);
                                }
                                else {
                                    u.writeInt(relationalStore.AssetStatus.ASSET_NORMAL);
                                }
                                u.writeString(d3.assetId);
                                u.writeString(d3.hash);
                            });
                        }
                        else if (t1 instanceof Uint8Array) {
                            u.writeInt(f.BLOB);
                            var l3 = [];
                            for (let f2 = 0; f2 < t1.length; f2++) {
                                l3.push(t1[f2]);
                            }
                            u.writeIntArray(l3);
                        }
                        else {
                            u.writeInt(f.ASSET);
                            u.writeString(t1.name);
                            u.writeString(t1.uri);
                            u.writeString(t1.path);
                            u.writeString(t1.createTime);
                            u.writeString(t1.modifyTime);
                            u.writeString(t1.size);
                            if (t1.status) {
                                u.writeInt(t1.status);
                            }
                            else {
                                u.writeInt(relationalStore.AssetStatus.ASSET_NORMAL);
                            }
                            u.writeString(t1.assetId);
                            u.writeString(t1.hash);
                        }
                    }
                }
            });
        }

        marshallingValuesBuckets(u, m3) {
            if (m3.length > MAX_SIZE) {
                return;
            }
            u.writeInt(m3.length);
            for (let f2 = 0; f2 < m3.length; f2++) {
                this.marshallingValueBucket(u, m3[f2]);
            }
        }

        unMarshallingValuesBuckets(t) {
            let n3 = t.readInt();
            let m3 = [];
            if (n3 < 0 || n3 > MAX_SIZE) {
                return m3;
            }
            for (let f2 = 0; f2 < n3; f2++) {
                m3.push(this.unMarshallingValuesBucket(t));
            }
            return m3;
        }

        unMarshallingValuesBucket(t) {
            let k3 = {};
            let n3 = t.readInt();
            if (n3 < 0 || n3 > MAX_SIZE) {
                return k3;
            }
            for (let f2 = 0; f2 < n3; f2++) {
                let s1 = t.readString();
                let t1 = this.unMarshallingValueType(t);
                k3[s1] = t1;
            }
            return k3;
        }

        unMarshallingValueType(t) {
            let o3 = t.readInt();
            switch (o3) {
                case f.NULL: // null
                    return null;
                case f.NUMBER: // number
                    return t.readLong();
                case f.REAL: // number
                    return t.readFloat();
                case f.TEXT: // number
                    return t.readString();
                case f.BOOL: // boolean
                    return t.readBoolean();
                case f.BLOB: // Uint8Array
                    return Uint8Array.from(t.readIntArray());
                case f.ASSET: // Asset
                    return {
                        name: t.readString(),
                        uri: t.readString(),
                        path: t.readString(),
                        createTime: t.readString(),
                        modifyTime: t.readString(),
                        size: t.readString(),
                        status: t.readInt(),
                        assetId: t.readString(),
                        hash: t.readString(),
                    };
                case f.ASSETS: // Assets
                    let p3 = t.readInt();
                    let q3 = [];
                    if (p3 < 0 || p3 > MAX_SIZE) {
                        return q3;
                    }
                    for (let c2 = 0; c2 < p3; c2++) {
                        q3.push({
                            name: t.readString(),
                            uri: t.readString(),
                            path: t.readString(),
                            createTime: t.readString(),
                            modifyTime: t.readString(),
                            size: t.readString(),
                            status: t.readInt(),
                            assetId: t.readString(),
                            hash: t.readString(),
                        });
                    }
                    return q3;
            }
            return null;
        }
    }

    a.CloudDbStub = m;

    class n extends rpc.RemoteObject {
        constructor(q, l1) {
            super(q);
            this.assetLoader = l1;
        }

        async onRemoteMessageRequest(s, t, u, v) {
            v.setWaitTime(500);
            let w = this.getDescriptor();
            let v1 = t.readString();
            let r3 = t.readString();
            let s3 = t.readString();
            switch (s) {
                case k.Download:
                    let t3 = this.unmarshallingAssets(t);
                    let q3 = await this.assetLoader.download(v1, r3, s3, t3);
                    this.marshallingAssets(u, q3);
                    return true;
                case k.Upload:
                    let u3 = this.unmarshallingAssets(t);
                    let v3 = await this.assetLoader.upload(v1, r3, u3);
                    this.marshallingAssets(u, v3);
                    return true;
            }
            return false;
        }

        unmarshallingAssets(t) {
            let h3 = t.readInt();
            let w3 = [];
            if (h3 < 0 || h3 > MAX_SIZE) {
                return w3;
            }
            for (let f2 = 0; f2 < h3; f2++) {
                w3.push({
                    name: t.readString(),
                    uri: t.readString(),
                    path: t.readString(),
                    createTime: t.readString(),
                    modifyTime: t.readString(),
                    size: t.readString(),
                    status: t.readInt(),
                    assetId: t.readString(),
                    hash: t.readString()
                });
            }
            return w3;
        }

        marshallingAssets(u, q3) {
            u.writeInt(q3.length);
            if (q3.length > MAX_SIZE) {
                return;
            }
            for (let f2 = 0; f2 < q3.length; f2++) {
                u.writeInt(q3[f2].code);
                u.writeString(q3[f2].value.name);
                u.writeString(q3[f2].value.uri);
                u.writeString(q3[f2].value.path);
                u.writeString(q3[f2].value.createTime);
                u.writeString(q3[f2].value.modifyTime);
                u.writeString(q3[f2].value.size);
                u.writeInt(q3[f2].value.status);
                u.writeString(q3[f2].value.assetId);
                u.writeString(q3[f2].value.hash);
            }
        }
    }

    a.AssetLoaderStub = n;

    class o extends rpc.RemoteObject {
        constructor(q, x3) {
            super(q);
            this.shareCenter = x3;
        }

        async onRemoteMessageRequest(s, t, u, v) {
            if (this.shareCenter == undefined) {
                return false;
            }
            v.setWaitTime(1500);
            switch (s) {
                case i.Share:
                    let y3 = t.readInt();
                    let n1 = t.readString();
                    let z3 = t.readString();
                    let a4 = this.unMarshallingParticipants(t);
                    let b4 = await this.shareCenter.share(y3, n1, z3, a4);
                    this.marshallingResults(u, b4);
                    return true;
                case i.Unshare:
                    let c4 = t.readInt();
                    let d4 = t.readString();
                    let e4 = t.readString();
                    let f4 = this.unMarshallingParticipants(t);
                    let g4 = await this.shareCenter.unshare(c4, d4, e4, f4);
                    this.marshallingResults(u, g4);
                    return true;
                case i.Exit:
                    let h4 = t.readInt();
                    let i4 = t.readString();
                    let j4 = t.readString();
                    let k4 = await this.shareCenter.exit(h4, i4, j4);
                    u.writeInt(k4.code);
                    if (k4.description) {
                        u.writeString(k4.description);
                    }
                    else {
                        u.writeString(INVALID_STR);
                    }
                    return true;
                case i.ChangePrivilege:
                    let l4 = t.readInt();
                    let m4 = t.readString();
                    let n4 = t.readString();
                    let o4 = this.unMarshallingParticipants(t);
                    let p4 = await this.shareCenter.changePrivilege(l4, m4, n4, o4);
                    this.marshallingResults(u, p4);
                    return true;
                case i.QueryParticipants:
                    let q4 = t.readInt();
                    let r4 = t.readString();
                    let s4 = t.readString();
                    let t4 = await this.shareCenter.queryParticipants(q4, r4, s4);
                    this.marshallingResultsArray(u, t4);
                    return true;
                case i.QueryParticipantsByInvitation:
                    let u4 = t.readInt();
                    let v4 = t.readString();
                    let w4 = t.readString();
                    let x4 = await this.shareCenter.queryParticipantsByInvitation(u4, v4, w4);
                    this.marshallingResultsArray(u, x4);
                    return true;
                case i.ConfirmInvitation:
                    let y4 = t.readInt();
                    let z4 = t.readString();
                    let a5 = t.readString();
                    let b5 = t.readInt();
                    let c5 = await this.shareCenter.confirmInvitation(y4, z4, a5, b5);
                    u.writeInt(c5.code);
                    if (c5.description) {
                        u.writeString(c5.description);
                    }
                    else {
                        u.writeString(INVALID_STR);
                    }
                    if (c5.value) {
                        u.writeString(c5.value);
                    }
                    else {
                        u.writeString(INVALID_STR);
                    }
                    return true;
                case i.ChangeConfirmation:
                    let d5 = t.readInt();
                    let e5 = t.readString();
                    let f5 = t.readString();
                    let g5 = t.readInt();
                    let h5 = await this.shareCenter.changeConfirmation(d5, e5, f5, g5);
                    u.writeInt(h5.code);
                    if (h5.description) {
                        u.writeString(h5.description);
                    }
                    else {
                        u.writeString(INVALID_STR);
                    }
                    return true;
                default:
                    break;
            }
            return false;
        }

        unMarshallingParticipants(t) {
            let i5 = [];
            let h3 = t.readInt();
            if (h3 < 0 || h3 > MAX_SIZE) {
                return i5;
            }
            for (let f2 = 0; f2 < h3; f2++) {
                i5.push(this.unMarshallingParticipant(t));
            }
            return i5;
        }

        unMarshallingParticipant(t) {
            let j5 = t.readString();
            let k5;
            let l5 = t.readInt();
            let m5 = t.readInt();
            k5 = {
                identity: j5,
                role: l5 == INVALID_STATE ? undefined : l5,
                state: m5 == INVALID_STATE ? undefined : m5,
                privilege: this.unMarshallingPrivilege(t),
                attachInfo: t.readString(),
            };
            return k5;
        }

        unMarshallingPrivilege(t) {
            let n5;
            n5 = {
                writable: t.readBoolean(),
                readable: t.readBoolean(),
                creatable: t.readBoolean(),
                deletable: t.readBoolean(),
                shareable: t.readBoolean(),
            };
            return n5;
        }

        marshallingResultsArray(u, i3) {
            u.writeInt(i3.code);
            if (i3.description) {
                u.writeString(i3.description);
            }
            else {
                u.writeString(INVALID_STR);
            }
            if (i3.value) {
                u.writeInt(i3.value.length);
                i3.value.forEach(q3 => {
                    this.marshallingParticipant(u, q3);
                });
            }
        }

        marshallingResults(u, i3) {
            u.writeInt(i3.code);
            if (i3.description) {
                u.writeString(i3.description);
            }
            else {
                u.writeString(INVALID_STR);
            }
            if (i3.value) {
                u.writeInt(i3.value.length);
                i3.value.forEach(q3 => {
                    u.writeInt(q3.code);
                    if (q3.description) {
                        u.writeString(q3.description);
                    }
                    else {
                        u.writeString(INVALID_STR);
                    }
                });
            }
        }

        marshallingParticipant(u, k5) {
            u.writeString(k5.identity);
            if (typeof k5.role !== 'undefined') {
                u.writeInt(k5.role);
            }
            else {
                u.writeInt(-1);
            }
            if (typeof k5.state !== 'undefined') {
                u.writeInt(k5.state);
            }
            else {
                u.writeInt(-1);
            }
            if (k5.privilege) {
                this.marshallingPrivilege(u, k5.privilege);
            }
            else {
                u.writeBoolean(false);
                u.writeBoolean(false);
                u.writeBoolean(false);
                u.writeBoolean(false);
                u.writeBoolean(false);
            }
            if (k5.attachInfo) {
                u.writeString(k5.attachInfo);
            }
            else {
                u.writeString(INVALID_STR);
            }
        }

        marshallingPrivilege(u, n5) {
            u.writeBoolean(n5.writable);
            u.writeBoolean(n5.readable);
            u.writeBoolean(n5.creatable);
            u.writeBoolean(n5.deletable);
            u.writeBoolean(n5.shareable);
        }
    }

    a.ShareCenterProxy = o;

    async function b(o5) {
        return new l("CloudServiceProxy", o5);
    }

    a.createCloudServiceStub = b;

    async function c(i1) {
        return new m("CloudDbProxy", i1);
    }

    a.createCloudDBStub = c;

    async function d(l1) {
        return new n("AssetLoaderProxy", l1);
    }

    a.createAssetLoaderStub = d;

    async function e(x3) {
        return new o('ShareCenterProxy', x3);
    }

    a.createShareServiceStub = e;
})(cloudExtension || (cloudExtension = {}));

export default {
    cloudExtension,
    FieldType: cloudExtension.FieldType,
    ErrorCode: cloudExtension.ErrorCode,
    createCloudServiceStub: cloudExtension.createCloudServiceStub,
    createCloudDBStub: cloudExtension.createCloudDBStub,
    createAssetLoaderStub: cloudExtension.createAssetLoaderStub,
    createShareServiceStub: cloudExtension.createShareServiceStub,
};