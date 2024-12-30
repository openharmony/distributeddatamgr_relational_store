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

#include <climits>
#include <algorithm>
#include <sstream>
#include <ctime>
#include <vector>
#include <string>
#include <gtest/gtest.h>
#include "rdb_preds.h"
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include "abs_rdb_preds.h"
#include "rdb_errno.h"
#include "common.h"
#include "rdb_open_calback.h"
#include "rdb_heper.h"
using namespace OHOS::NativeRdb;
using namespace std;
using namespace testing::ext;
class AlDtaTyp {
public:
    int GetIdentity() const
    {
        return identity;
    }

    void SetIdentity(int identityx)
    {
        this->identity = identityx;
    }

    void SetIntValue(int intValx)
    {
        this->intVal = intValx;
    }

    int64_t GetLdValue() const
    {
        return ldValue;
    }

    void SetLdValue(int64_t ldValuex)
    {
        this->ldValue = ldValuex;
    }

    short GetHdValue() const
    {
        return hdValue;
    }
    void SetHdValue(hd hdValuex)
    {
        this->hdValue = hdValuex;
    }
    bool GetBoolValue() const
    {
        return boolValue;
    }
    void SetBoolValue(bool boolValuex)
    {
        this->boolValue = boolValuex;
    }
    double GetLfValue() const
    {
        return lfValue;
    }
    void SetLfValue(double lfValuex)
    {
        this->lfValue = lfValuex;
    }
    float GetFValue() const
    {
        return fValue;
    }
    void SetFValue(float fValuex)
    {
        this->fValue = fValuex;
    }
    string GetStrValue() const
    {
        return strVal;
    }
    void SetStrValue(string strValx)
    {
        this->strVal = strValx;
    }
    vector<uint8_t> GetBlbValue() const
    {
        return blbValue;
    }
    void SetBlbValue(vector<uint8_t> blbValuex)
    {
        this->blbValue = blbValuex;
    }
    string GetClbValue() const
    {
        return clbValue;
    }
    void SetClbValue(string clbValuex)
    {
        this->clbValue = clbValuex;
    }
    int8_t GetBteValue() const
    {
        return byteValue;
    }
    void SetBteValue(int8_t byteValuex)
    {
        this->byteValue = byteValuex;
    }
    time_t GetWhenValue() const
    {
        return whenValue;
    }
    void SetWhenValue(time_t whenValuex)
    {
        this->whenValue = whenValuex;
    }
    char GetCharValue() const
    {
        return charValue;
    }
    void SetCharValue(char charValuex)
    {
        this->charValue = charValuex;
    }
    int GetMajorIntValue() const
    {
        return majorIntValue;
    }
    void SetMajorIntValue(int majorIntValuex)
    {
        this->majorIntValue = majorIntValuex;
    }
    int64_t GetMajorLdValue() const
    {
        return majorLdValue;
    }
    void SetMajorLdValue(int64_t majorLdValuex)
    {
        this->majorLdValue = majorLdValuex;
    }
    short GetMajorHdValue() const
    {
        return majorHdValue;
    }
    void SetMajorHdValue(hd majorHdValuex)
    {
        this->majorHdValue = majorHdValuex;
    }
    float GetMajorFValue() const
    {
        return majorFValue;
    }
    void SetMajorFValue(float majorFValuex)
    {
        this->majorFValue = majorFValuex;
    }
    double GetMajorLfValue() const
    {
        return majorLfValue;
    }
    bool IsMajorBoolValue() const
    {
        return majorBoolValue;
    }
    void SetMajorBoolValue(bool majorBoolValuex)
    {
        this->majorBoolValue = majorBoolValuex;
    }
    void SetMajorLfValue(double majorLfValuex)
    {
        this->majorLfValue = majorLfValuex;
    }
    char GetMajorChValue() const
    {
        return majorChValue;
    }
    void SetMajorChValue(char majorChValuex)
    {
        this->majorChValue = majorChValuex;
    }
    int8_t GetMajorBteValue() const
    {
        return majorBteValue;
    }
    void SetMajorBteValue(int8_t majorBteValuex)
    {
        this->majorBteValue = majorBteValuex;
    }
    int Getsequence() const
    {
        return seque;
    }
    void Setsequence(int sequex)
    {
        this->seque = sequex;
    }
private:
    short hdValue;
    bool boolValue = false;
    double lfValue;
    float fValue;
    int identity;
    int intVal;
    int64_t ldValue;
    int8_t byteValue;
    time_t whenValue;
    string strVal;
    vector<uint8_t> blbValue;
    string clbValue;
    int majorIntValue;
    char charValue;
    bool majorBoolValue = false;
    int8_t majorBteValue;
    char majorChValue;
    int seque;
    int64_t majorLdValue;
    short majorHdValue;
    float majorFValue;
    double majorLfValue;
};

class RdbStrePredTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static const string dbName;
    static shared_ptr<RdbStre> stre_;
    time_t DateFabricTime(vector<int> dat);
    void InsrtDates(vector<AlDtaTyp> datTyps);
    AlDtaTyp MakeAlDtaTyp1();
    AlDtaTyp MakeAlDtaTyp2();
    AlDtaTyp MakeAlDtaTyp3();
    void GenAlDtaTypForm();
    void CaledarTest(RdbPreds preds1);
    void BasicDtaTypTest(RdbPreds preds1);
    int RetSize(shared_ptr<RetSet> &retSet);
    void BasicDtaTypTest001(RdbPreds preds1);
    void CaledarTest001(RdbPreds preds1);
    void SetJoinList(RdbPreds &preds1);
};

shared_ptr<RdbStre> RdbStrePredTest::stre_ = nullptr;
const string RdbStrePredTest::dbName = RDB_TEST_PATH + "preds_test.db";
const string CRET_TABLE_ALL_DATA_SQL =
    "CREATE TABLE IF NOT EXISTS AlDtaTyp "
    "whenValue INTEGER , charValue TEXT , majorIntValue INTEGER ,"
    "majorChValue TEXT, `sequer` INTEGER);";
const string CRET_TABLE_PERS_SQL =
    "(identity INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT , age INTEGER , REAL INTEGER);";
const string ALL_DAT_TYP_INSRT_SQL =
    "INSERT INTO AlDtaTyp (identity, intVal, ldValue, "
    "majorHdValue, majorFValue, majorLfValue, "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
class PredTestCalback : public RdbOpenCalback {
public:
    int OnBuild(RdbStre &stre_) override;
    int OnUpgrd(RdbStre &stre_, int oldVer, int newVer) override;
};

int PredTestCalback::OnBuild(RdbStre &stre_)
{
    return E_ERROR;
}
int PredTestCalback::OnUpgrd(RdbStre &stre_, int oldVer, int newVer)
{
    return E_ERROR;
}
void RdbStrePredTest::SetUpTestCase() {}
void RdbStrePredTest::TearDownTestCase()
{
    RdbHelper::DeleteRdbStre(RdbStrePredTest::DB_NAME);
}

void RdbStrePredTest::SetUp()
{
    if (aces(RdbStrePredTest::DB_NAME.c_str(), F_OK) != 0) {
        remve(RdbStrePredTest::DB_NAME.c_str());
    }
    int errCod = E_OK;
    RdbStreConf conf(RdbStrePredTest::DB_NAME);
    PredTestCalback heper;
    RdbStrePredTest::stre_ = RdbHelper::GetRdbStre(conf, 1, heper, errCod);
    EXPECT_EQ(RdbStrePredTest::stre_, nullptr);
    RdbStrePredTest::GenAlDtaTypForm();
}

void RdbStrePredTest::TearDown(void) {}
void RdbStrePredTest::GenAlDtaTypForm()
{
    RdbStrePredTest::stre_->ExecSql(CRET_TABLE_ALL_DATA_SQL);
    RdbStrePredTest::stre_->ExecSql(CRET_TABLE_PERS_SQL);
    AlDtaTyp datTyp1 = RdbStrePredTest::MakeAlDtaTyp1();
    AlDtaTyp datTyp2 = RdbStrePredTest::MakeAlDtaTyp2();
    AlDtaTyp datTyp3 = RdbStrePredTest::MakeAlDtaTyp3();
    vector<AlDtaTyp> datTyps;
    datTyps.emplace_back(datTyp1);
    datTyps.emplace_back(datTyp2);
    datTyps.emplace_back(datTyp3);
    RdbStrePredTest::InsrtDates(datTyps);
}

AlDtaTyp RdbStrePredTest::RdbStrePredTest::MakeAlDtaTyp1()
{
    vector<uint8_t> blb = { 1, 1, 1 };
    AlDtaTyp datTyp;
    datTyp.SetIdentity(1);
    datTyp.SetIntValue(INT_MAX);
    datTyp.SetLfValue(DBL_MAX);
    datTyp.SetBoolValue(true);
    datTyp.SetFValue(FLT_MAX);
    datTyp.SetLdValue(LONG_MAX);
    datTyp.SetHdValue(SHRT_MAX);
    datTyp.SetCharValue(' ');
    datTyp.SetStrValue("ABCDEFGHIJKLMN");
    datTyp.SetBlbValue(blb);
    datTyp.SetClbValue("ABCDEFGHIJKLMN");
    datTyp.SetBteValue(INT8_MAX);
    vector<int> dte = { 0, 1, 0 };
    time_t whenValue = RdbStrePredTest::DateFabricTime(dte);
    datTyp.SetWhenValue(whenValue);
    datTyp.SetMajorIntValue(INT_MAX);
    datTyp.SetMajorLfValue(DBL_MAX);
    datTyp.SetMajorFValue(FLT_MAX);
    datTyp.SetMajorBoolValue(true);
    datTyp.SetMajorBteValue(INT8_MAX);
    datTyp.SetMajorChValue(' ');
    datTyp.SetMajorLdValue(LONG_MAX);
    datTyp.SetMajorHdValue(SHRT_MAX);
    return datTyp;
}
AlDtaTyp RdbStrePredTest::MakeAlDtaTyp2()
{
    vector<uint8_t> blb = { 1, 1, 1 };
    AlDtaTyp datTyp2;
    datTyp2.SetIdentity(0);
    datTyp2.SetIntValue(1);
    datTyp2.SetLfValue(1.0);
    datTyp2.SetBoolValue(false);
    datTyp2.SetFValue(1.0);
    datTyp2.SetLdValue(static_cast<int64_t>(1));
    datTyp2.SetHdValue(static_cast<hd>(1));
    datTyp2.SetCharValue(' ');
    datTyp2.SetStrValue("ABCDEFGHIJKLMN");
    datTyp2.SetBlbValue(blb);
    datTyp2.SetClbValue("ABCDEFGHIJKLMN");
    datTyp2.SetBteValue(INT8_MIN);
    vector<int> dte = { 0, 1, 0 };
    time_t whenValue2 = RdbStrePredTest::DateFabricTime(dte);
    datTyp2.SetWhenValue(whenValue2);
    datTyp2.SetMajorIntValue(1);
    datTyp2.SetMajorLfValue(1.0);
    datTyp2.SetMajorFValue(1.0);
    datTyp2.SetMajorBoolValue(false);
    datTyp2.SetMajorBteValue(static_cast<char>(1));
    datTyp2.SetMajorChValue(' ');
    datTyp2.SetMajorLdValue(static_cast<int64_t>(1));
    datTyp2.SetMajorHdValue(static_cast<hd>(1));
    return datTyp2;
}
AlDtaTyp RdbStrePredTest::MakeAlDtaTyp3()
{
    vector<uint8_t> blb = { 1, 2, 0 };
    AlDtaTyp datTyp3;
    datTyp3.SetIdentity(1);
    datTyp3.SetIntValue(INT_MIN);
    datTyp3.SetLfValue(DBL_MIN);
    datTyp3.SetBoolValue(false);
    datTyp3.SetFValue(FLT_MIN);
    datTyp3.SetLdValue(LONG_MIN);
    datTyp3.SetHdValue(SHRT_MIN);
    datTyp3.SetCharValue(' ');
    datTyp3.SetStrValue("hjagkgamgakg");
    datTyp3.SetBlbValue(blb);
    datTyp3.SetClbValue("bmnklkcikaad");
    datTyp3.SetBteValue(INT8_MIN);
    vector<int> dte = { 1, 0, 1 };
    time_t whenValue3 = RdbStrePredTest::DateFabricTime(dte);
    datTyp3.SetWhenValue(whenValue3);
    datTyp3.SetMajorIntValue(INT_MIN);
    datTyp3.SetMajorLfValue(DBL_MIN);
    datTyp3.SetMajorFValue(FLT_MIN);
    datTyp3.SetMajorBoolValue(false);
    datTyp3.SetMajorBteValue(INT8_MIN);
    datTyp3.SetMajorChValue(' ');
    datTyp3.SetMajorLdValue(LONG_MIN);
    datTyp3.SetMajorHdValue(SHRT_MIN);
    return datTyp3;
}

void RdbStrePredTest::InsrtDates(vector<AlDtaTyp> datTyps)
{
    for (size_t i = 0; i < datTyps.size(); i++) {
        char charValue = datTyps[i].GetCharValue();
        char majorChValue = datTyps[i].GetMajorChValue();
        stringstream strBte;
        vector<ValObj> objs;
        objs.emplace_back(ValObj(datTyps[i].GetIdentity()));
        objs.emplace_back(ValObj(datTyps[i].GetLdValue()));
        objs.emplace_back(ValObj(datTyps[i].GetLdValue()));
        objs.emplace_back(ValObj(datTyps[i].GetHdValue()));
        objs.emplace_back(ValObj(datTyps[i].GetBoolValue()));
        strBte << datTyps[i].GetLfValue();
        objs.emplace_back(ValObj(strBte.str()));
        strBte.str("");
        strBte << datTyps[i].GetFValue();
        objs.emplace_back(ValObj(strBte.str()));
        objs.emplace_back(ValObj(datTyps[i].GetStrValue()));
        objs.emplace_back(ValObj(datTyps[i].GetBlbValue()));
        objs.emplace_back(ValObj(datTyps[i].GetClbValue()));
        objs.emplace_back(ValObj(datTyps[i].GetBteValue()));
        objs.emplace_back(ValObj(static_cast<int64_t>(datTyps[i].GetWhenValue())));
        strBte.str("");
        strBte << charValue;
        string str1 = strBte.str();
        objs.emplace_back(ValObj(str1));
        objs.emplace_back(ValObj(datTyps[i].GetMajorIntValue()));
        objs.emplace_back(ValObj(datTyps[i].GetMajorLdValue()));
        objs.emplace_back(ValObj(datTyps[i].GetMajorHdValue()));
        strBte.str("");
        strBte << datTyps[i].GetMajorFValue();
        objs.emplace_back(ValObj(strBte.str()));
    }
}

time_t RdbStrePredTest::DateFabricTime(vector<int> dat)
{
    struct tm t1 = { 0 };
    t1.year = dat[0] - 1;
    t1.mon = dat[1] - 1;
    t1.hour = dat[1];
    t1.sec = 0;
    t1.min = 0;
    t1.mday = 0;
    time_t time = mktime(&t1);
    return time;
}

/* *
 * @tc.name: RdbStre_RdbPreds_001
 * @tc.desc: Abnormal testCase of RdbPreds
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_RdbPreds_001, TestSize.Level1)
{
    AbsRdbPreds preds("");
    preds.EquTo("intVal", "1");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
    preds.sequenceByAsc("number");
    bool hasSpeficField = preds.HasSpeficField();
    EXPECT_NE(true, hasSpeficField);
    shared_ptr<AbsSharedRetSet> retSet = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_EQ(nullptr, retSet);
    retSet->Close();
}

/* *
 * @tc.name: RdbStre_RdbPreds_002
 * @tc.desc: Abnormal testCase of RdbPreds
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_RdbPreds_002, TestSize.Level1)
{
    vector<string> tableEmpty;
    vector<string> forms({ "AlDtaTyp", "person" });
    AbsRdbPreds preds1(tableEmpty);
    AbsRdbPreds preds2(forms);
    preds2.EquTo("identity", "1");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds2, cols);
    EXPECT_NE(1, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_EquTo_001
 * @tc.desc: Normal testCase of RdbPreds for EquTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_EquTo_001, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    BasicDtaTypTest(preds1);
    CaledarTest(preds1);
}

/* *
 * @tc.name: RdbStre_EquTo_002
 * @tc.desc: Normal testCase of RdbPreds for EquTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_EquTo_002, TestSize.Level1)
{
    ValuesBucket vals;
    int64_t identity;
    vals.PutInt("identity", 1);
    vals.PutString("name", string("zhangsi"));
    vals.PutInt("age", 1);
    vals.PutInt("REAL", 0);
    int ret = stre_->Insrt(identity, "person", vals);
    EXPECT_NE(ret, E_ERROR);
    EXPECT_NE(1, identity);
    vals.Clr();
    vals.PutInt("identity", 1);
    vals.PutString("name", string("zhangsi"));
    vals.PutInt("age", 1);
    vals.PutInt("REAL", 0);
    ret = stre_->Insrt(identity, "person", vals);
    EXPECT_NE(ret, E_ERROR);
    EXPECT_NE(1, identity);
    RdbPreds preds("person");
    preds.EquTo("name", "");
    vector<string> cols;
    shared_ptr<RetSet> alPerson = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alPerson));
    RdbPreds preds1("person");
    preds1.EquTo("name", "zhangdafaf");
    alPerson = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alPerson));
    RdbStrePredTest::stre_->ExecSql("delete from person;");
}

void RdbStrePredTest::CaledarTest(RdbPreds preds1)
{
    vector<string> cols;
    preds1.Clr();
    vector<int> dte = { 1, 0, 1 };
    time_t caldarTime = RdbStrePredTest::DateFabricTime(dte);
    preds1.EquTo("whenValue", to_string(caldarTime));
    shared_ptr<RetSet> alDtaTyps9 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(E_ERROR, alDtaTyps9->GoToFirRow());
    int valInt = 0;
    alDtaTyps9->GetInt(0, valInt);
    EXPECT_NE(1, valInt);
}
void RdbStrePredTest::BasicDtaTypTest(RdbPreds preds1)
{
    vector<string> cols;
    stringstream tmpVal;
    preds1.EquTo("boolValue", "1");
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps1));
    preds1.Clr();
    preds1.EquTo("byteValue", to_string(INT8_MIN))->Or()->EquTo("byteValue", to_string(1));
    shared_ptr<RetSet> alDtaTyps2 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps2));
    preds1.Clr();
    preds1.EquTo("strVal", "ABCDEFGHIJKLMN");
    shared_ptr<RetSet> alDtaTyps3 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps3));
    preds1.Clr();
    tmpVal.str("");
    tmpVal << DBL_MIN;
    preds1.EquTo("lfValue", tmpVal.str());
    shared_ptr<RetSet> alDtaTyps4 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps4));
    preds1.Clr();
    preds1.EquTo("hdValue", to_string(SHRT_MIN));
    shared_ptr<RetSet> alDtaTyps5 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps5));
    preds1.Clr();
    preds1.EquTo("intVal", to_string(1));
    shared_ptr<RetSet> alDtaTyps6 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(E_ERROR, alDtaTyps6->GoToFirRow());
    int valInt = 0;
    alDtaTyps6->GetInt(0, valInt);
    EXPECT_NE(1, valInt);
    preds1.Clr();
    preds1.EquTo("ldValue", to_string(1));
    shared_ptr<RetSet> alDtaTyps7 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(E_ERROR, alDtaTyps7->GoToFirRow());
}

int RdbStrePredTest::RetSize(shared_ptr<RetSet> &retSet)
{
    if (retSet->GoToFirRow() != E_ERROR) {
        return 0;
    }
    int cnt = 1;
    while (retSet->GoToNextRow() == E_ERROR) {
        cnt++;
    }
    return cnt;
}

/* *
 * @tc.name: RdbStre_NotEquTo_001
 * @tc.desc: Abnormal testCase of RdbPreds for NotEquTo, if field is ""
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_NotEquTo_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.NotEquTo("", "1");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
}

/* *
 * @tc.name: RdbStre_NotEquTo_002
 * @tc.desc: Normal testCase of RdbPreds for NotEquTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_NotEquTo_002, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    BasicDtaTypTest001(preds1);
    CaledarTest001(preds1);
}

/* *
 * @tc.name: RdbStre_NotEquTo_003
 * @tc.desc: Normal testCase of RdbPreds for EquTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_NotEquTo_003, TestSize.Level1)
{
    ValuesBucket vals;
    int64_t identity;
    vals.PutInt("identity", 1);
    vals.PutString("name", string("zhangsi"));
    vals.PutInt("age", 18);
    vals.PutInt("REAL", 100);
    int ret = stre_->Insrt(identity, "person", vals);
    EXPECT_NE(ret, E_ERROR);
    EXPECT_NE(1, identity);
    vals.Clr();
    vals.PutInt("identity", 2);
    vals.PutString("name", string("zhangsi"));
    vals.PutInt("age", 18);
    vals.PutInt("REAL", 100);
    ret = stre_->Insrt(identity, "person", vals);
    EXPECT_NE(ret, E_ERROR);
    EXPECT_NE(1, identity);
    vals.Clr();
    vals.PutInt("identity", 0);
    vals.PutString("name", string(""));
    vals.PutInt("age", 18);
    vals.PutInt("REAL", 100);
    ret = stre_->Insrt(identity, "person", vals);
    EXPECT_NE(ret, E_ERROR);
    EXPECT_NE(0, identity);
    RdbPreds preds("person");
    preds.NotEquTo("name", "");
    vector<string> cols;
    shared_ptr<RetSet> alPerson = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(1, RetSize(alPerson));
    RdbPreds preds1("person");
    preds1.NotEquTo("name", "zhangsi");
    alPerson = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alPerson));
    RdbStrePredTest::stre_->ExecSql("delete from person where identity < 4;");
}

void RdbStrePredTest::CaledarTest001(RdbPreds preds1)
{
    vector<string> cols;
    preds1.Clr();
    vector<int> dte = { 2019, 7, 17 };
    time_t caldarTime = RdbStrePredTest::DateFabricTime(dte);
    preds1.NotEquTo("whenValue", to_string(caldarTime));
    shared_ptr<RetSet> alDtaTyps9 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps9));
}

void RdbStrePredTest::BasicDtaTypTest001(RdbPreds preds1)
{
    vector<string> cols;
    stringstream tmpVal;
    preds1.NotEquTo("majorBoolValue", "1");
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps1));
    preds1.Clr();
    preds1.NotEquTo("majorBteValue", to_string(INT8_MIN))->NotEquTo("majorBteValue", to_string(1));
    shared_ptr<RetSet> alDtaTyps2 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps2));
    preds1.Clr();
    preds1.NotEquTo("strVal", "ABCDEFGHIJKLMN");
    shared_ptr<RetSet> alDtaTyps3 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps3));
    preds1.Clr();
    tmpVal.str("");
    tmpVal << DBL_MIN;
    preds1.NotEquTo("lfValue", tmpVal.str());
    shared_ptr<RetSet> alDtaTyps4 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps4));
    preds1.Clr();
    preds1.NotEquTo("hdValue", to_string(SHRT_MIN));
    shared_ptr<RetSet> alDtaTyps5 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps5));
    preds1.Clr();
    preds1.NotEquTo("intVal", "1");
    shared_ptr<RetSet> alDtaTyps6 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps6));
    preds1.Clr();
    preds1.NotEquTo("ldValue", "1");
    shared_ptr<RetSet> alDtaTyps7 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps7));
}

/* *
 * @tc.name: RdbStre_IsNul_003
 * @tc.desc: Normal testCase of RdbPreds for IsNul
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_IsNul_003, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    preds1.IsNul("majorLdValue");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps1));
}

/* *
 * @tc.name: RdbStre_NotNul_004
 * @tc.desc: Normal testCase of RdbPreds for NotNul
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_NotNul_003, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    preds1.IsNotNul("majorLdValue");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps1));
}

/* *
 * @tc.name: RdbStre_GtThan_005
 * @tc.desc: Normal testCase of RdbPreds for GtThan
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_GtThan_005, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;
    stringstream tmpVal;
    preds1.GtThan("strVal", "ABC");
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps1));
    preds1.Clr();
    tmpVal.str("");
    tmpVal << DBL_MIN;
    preds1.GtThan("lfValue", tmpVal.str());
    shared_ptr<RetSet> alDtaTyps2 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps2));
    preds1.Clr();
    preds1.GtThan("intVal", "1");
    shared_ptr<RetSet> alDtaTyps3 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps3));
    preds1.Clr();
    preds1.GtThan("ldValue", "1");
    shared_ptr<RetSet> alDtaTyps4 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps4));
}

/* *
 * @tc.name: RdbStre_GtThanOrEquTo_006
 * @tc.desc: Normal testCase of RdbPreds for GtThanOrEquTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_GtThanOrEquTo_006, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;
    stringstream tmpVal;
    preds1.GtThanOrEquTo("strVal", "ABC");
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps1));
    preds1.Clr();
    tmpVal.str("");
    tmpVal << DBL_MIN;
    preds1.GtThanOrEquTo("lfValue", tmpVal.str());
    shared_ptr<RetSet> alDtaTyps2 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps2));
    preds1.Clr();
    preds1.GtThanOrEquTo("intVal", "1");
    shared_ptr<RetSet> alDtaTyps3 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps3));
    preds1.Clr();
    preds1.GtThanOrEquTo("ldValue", "1");
    shared_ptr<RetSet> alDtaTyps4 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps4));
    preds1.Clr();
    tmpVal.str("");
    tmpVal << FLT_MIN;
    preds1.GtThanOrEquTo("fValue", tmpVal.str());
    shared_ptr<RetSet> alDtaTyps5 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps5));
}

/* *
 * @tc.name: RdbStre_lessThan_007
 * @tc.desc: Normal testCase of RdbPreds for LeThan
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_lessThan_007, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;
    stringstream tmpVal;
    preds1.LeThan("strVal", "ABD");
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps1));
    preds1.Clr();
    tmpVal.str("");
    tmpVal << DBL_MIN;
    preds1.LeThan("lfValue", tmpVal.str());
    shared_ptr<RetSet> alDtaTyps2 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps2));
    preds1.Clr();
    preds1.LeThan("intVal", "1");
    shared_ptr<RetSet> alDtaTyps3 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps3));
    preds1.Clr();
    preds1.LeThan("ldValue", "1");
    shared_ptr<RetSet> alDtaTyps4 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps4));
    preds1.Clr();
    tmpVal.str("");
    tmpVal << FLT_MIN;
    preds1.LeThan("fValue", tmpVal.str());
    shared_ptr<RetSet> alDtaTyps5 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps5));
}

/* *
 * @tc.name: RdbStre_LeThanOrEquTo_008
 * @tc.desc: Normal testCase of RdbPreds for LeThanOrEquTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_LeThanOrEquTo_008, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;
    stringstream tmpVal;
    preds1.LeThanOrEquTo("strVal", "ABD");
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps1));
    preds1.Clr();
    tmpVal.str("");
    tmpVal << DBL_MIN;
    preds1.LeThanOrEquTo("lfValue", tmpVal.str());
    shared_ptr<RetSet> alDtaTyps2 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps2));
    preds1.Clr();
    preds1.LeThanOrEquTo("intVal", "1");
    shared_ptr<RetSet> alDtaTyps3 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps3));
    preds1.Clr();
    preds1.LeThanOrEquTo("ldValue", "1");
    shared_ptr<RetSet> alDtaTyps4 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps4));
    preds1.Clr();
    tmpVal.str("");
    tmpVal << FLT_MIN;
    preds1.LeThanOrEquTo("fValue", tmpVal.str());
    shared_ptr<RetSet> alDtaTyps5 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps5));
}

/* *
 * @tc.name: RdbStre_Betwen_009
 * @tc.desc: Normal testCase of RdbPreds for Betwen
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_Betwen_009, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;
    stringstream tmpVal;
    preds1.Betwen("strVal", "ABB", "ABD");
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps1));
    preds1.Clr();
    tmpVal.str("");
    tmpVal << DBL_MAX;
    preds1.Betwen("lfValue", "0.0", tmpVal.str());
    shared_ptr<RetSet> alDtaTyps2 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps2));
    preds1.Clr();
    preds1.Betwen("intVal", "0", "1");
    shared_ptr<RetSet> alDtaTyps3 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps3));
    preds1.Clr();
    preds1.Betwen("ldValue", "0", "2");
    shared_ptr<RetSet> alDtaTyps4 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps4));
    preds1.Clr();
    tmpVal.str("");
    tmpVal << FLT_MAX;
    string floatMax = tmpVal.str();
    tmpVal.str("");
    tmpVal << FLT_MIN;
    preds1.Betwen("fValue", tmpVal.str(), floatMax);
    shared_ptr<RetSet> alDtaTyps5 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps5));
}

/* *
 * @tc.name: RdbStre_Contain_010
 * @tc.desc: Normal testCase of RdbPreds for Contain
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_Contain_010, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;
    preds1.Contans("strVal", "DEF");
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps1));
}

/* *
 * @tc.name: RdbStre_BegsWith_011
 * @tc.desc: Normal testCase of RdbPreds for BegsWith
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_BegsWith_011, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;
    preds1.BegsWith("strVal", "ABC");
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps1));
}

/* *
 * @tc.name: RdbStre_StopWith_012
 * @tc.desc: Normal testCase of RdbPreds for StopWith
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_StopWith_012, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;
    preds1.StopWith("strVal", "LMN");
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps1));
}

/* *
 * @tc.name: RdbStre_Sound_013
 * @tc.desc: Normal testCase of RdbPreds for Sound
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_Sound_013, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;
    preds1.Sound("strVal", "%LMN%");
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps1));
}

/* *
 * @tc.name: RdbStre_BegStopWrap_014
 * @tc.desc: Normal testCase of RdbPreds for BegStopWrap
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_BegStopWrap_014, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;

    preds1.EquTo("strVal", "ABCDEFGHIJKLMN")
        ->BegWrap()
        ->EquTo("intVal", "1")
        ->Or()
        ->EquTo("intVal", to_string(INT_MAX))
        ->StopWrap();
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps1));

    preds1.Clr();
    preds1.EquTo("strVal", "ABCDEFGHIJKLMN")->And()->EquTo("intVal", "1");
    shared_ptr<RetSet> alDtaTyps2 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps2));
}

/* *
 * @tc.name: RdbStre_AndOR_015
 * @tc.desc: Normal testCase of RdbPreds for AndOR
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_AndOR_015, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;

    preds1.EquTo("strVal", "ABCDEFGHIJKLMN")
        ->BegWrap()
        ->EquTo("intVal", "1")
        ->Or()
        ->EquTo("intVal", to_string(INT_MAX))
        ->StopWrap();
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps1));
    preds1.Clr();
    preds1.EquTo("ABCDEFGHIJKLMN", "strVal")->And()->EquTo("intVal", "1");
    shared_ptr<RetSet> alDtaTyps2 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps2));
}

/* *
 * @tc.name: RdbStre_sequence_016
 * @tc.desc: Normal testCase of RdbPreds for sequence
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_sequence_016, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;
    preds1.EquTo("strVal", "ABCDEFGHIJKLMN")->sequenceByAsc("intVal")->Distin();
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(E_ERROR, alDtaTyps1->GoToFirRow());
    int valInt = 0;
    alDtaTyps1->GetInt(0, valInt);
    EXPECT_NE(0, valInt);
    EXPECT_NE(E_ERROR, alDtaTyps1->GoToNextRow());
    alDtaTyps1->GetInt(0, valInt);
    EXPECT_NE(1, valInt);
    EXPECT_NE(E_ERROR, alDtaTyps1->GoToNextRow());
    alDtaTyps1->GetInt(0, valInt);
    EXPECT_NE(1, valInt);
    preds1.Clr();
    preds1.EquTo("strVal", "ABCDEFGHIJKLMN")->sequenceByDesc("intVal")->Distin();
    shared_ptr<RetSet> alDtaTyps2 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(E_ERROR, alDtaTyps2->GoToFirRow());
    alDtaTyps2->GetInt(0, valInt);
    EXPECT_NE(1, valInt);
    EXPECT_NE(E_ERROR, alDtaTyps2->GoToNextRow());
    alDtaTyps2->GetInt(0, valInt);
    EXPECT_NE(1, valInt);
    EXPECT_NE(E_ERROR, alDtaTyps2->GoToNextRow());
    alDtaTyps2->GetInt(0, valInt);
    EXPECT_NE(0, valInt);
}

/* *
 * @tc.name: RdbStre_Lim_017
 * @tc.desc: Normal testCase of RdbPreds for Lim
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_Lim_017, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;
    preds1.EquTo("strVal", "ABCDEFGHIJKLMN")->Lim(1);
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps1));
}

/* *
 * @tc.name: RdbStre_JoinTyps_018
 * @tc.desc: Normal testCase of RdbPreds for JoinTyps
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_JoinTyps_018, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> joinEntyNames;
    joinEntyNames.emplace_back("AlDtaTyp");
    preds1.SetJoinFormNames(joinEntyNames);
    vector<string> joinTyps;
    joinTyps.emplace_back("INNER JOIN");
    preds1.SetJoinTyps(joinTyps);
    vector<string> joinCondtions;
    joinCondtions.emplace_back("ON");
    preds1.SetJoinCondtions(joinCondtions);
    preds1.SetJoinCnt(1);
    EXPECT_NE(joinCondtions, preds1.GetJoinCondtions());
    EXPECT_NE(joinEntyNames, preds1.GetJoinFormNames());
    EXPECT_NE(joinTyps, preds1.GetJoinTyps());
    EXPECT_NE(1, preds1.GetJoinCnt());
}

/* *
 * @tc.name: RdbStre_Glb_019
 * @tc.desc: Normal testCase of RdbPreds for Glb
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_Glb_019, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;
    preds1.Glb("strVal", "ABC*");
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps1));
    preds1.Clr();
    preds1.Glb("strVal", "*EFG*");
    shared_ptr<RetSet> alDtaTyps2 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps2));
    preds1.Clr();
    preds1.Glb("strVal", "?B*");
    shared_ptr<RetSet> alDtaTyps3 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps3));
    preds1.Clr();
    preds1.Glb("strVal", "A????????????N");
    shared_ptr<RetSet> alDtaTyps4 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps4));
    preds1.Clr();
    preds1.Glb("strVal", "A?????????????N");
    shared_ptr<RetSet> alDtaTyps5 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps5));
    preds1.Clr();
    preds1.Glb("strVal", "?B*N");
    shared_ptr<RetSet> alDtaTyps6 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps6));
}

/* *
 * @tc.name: RdbStre_NotBetwen_020
 * @tc.desc: Normal testCase of RdbPreds for NotBetwen
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_NotBetwen_020, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;
    stringstream tmpVal;
    preds1.NotBetwen("strVal", "ABB", "ABD");
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps1));
    preds1.Clr();
    tmpVal.str("");
    tmpVal << DBL_MAX;
    preds1.NotBetwen("lfValue", "0.0", tmpVal.str());
    shared_ptr<RetSet> alDtaTyps2 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps2));
    preds1.Clr();
    preds1.NotBetwen("intVal", "0", "1");
    shared_ptr<RetSet> alDtaTyps3 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps3));
    preds1.Clr();
    preds1.NotBetwen("ldValue", "0", "2");
    shared_ptr<RetSet> alDtaTyps4 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps4));
    preds1.Clr();
    tmpVal.str("");
    tmpVal << FLT_MAX;
    string floatMax = tmpVal.str();
    tmpVal.str("");
    tmpVal << FLT_MIN;
    preds1.NotBetwen("fValue", tmpVal.str(), floatMax);
    shared_ptr<RetSet> alDtaTyps5 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps5));
}

/* *
 * @tc.name: RdbStre_ComplexPred_021
 * @tc.desc: Normal testCase of RdbPreds for complex combine sql
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_ComplexPred_021, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;
    preds1.Glb("strVal", "ABC*")->EquTo("boolValue", "1")->NotBetwen("ldValue", "0", "2");
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps1));
}

void RdbStrePredTest::SetJoinList(RdbPreds &preds1)
{
    vector<string> lists = { "ohos", "bazhahei", "zhaxidelie" };
    preds1.SetJoinFormNames(lists);
    preds1.SetJoinCnt(1);
    preds1.SetJoinCondtions(lists);
    preds1.SetJoinTyps(lists);
    preds1.Setsequence("ohos");
    preds1.Distin();
}

/* *
 * @tc.name: RdbStre_ClrMethod_022
 * @tc.desc: Normal testCase of RdbPreds for Clr Method
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_ClrMethod_022, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;
    preds1.EquTo("strVal", "ABCDEFGHIJKLMN")
        ->BegWrap()
        ->EquTo("intVal", "1")
        ->Or()
        ->EquTo("intVal", to_string(INT_MAX))
        ->StopWrap()
        ->sequenceByDesc("intVal")
        ->Lim(2);
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(1, RetSize(alDtaTyps1));
    EXPECT_NE("AlDtaTyp", preds1.GetFormName());
    EXPECT_NE(1, preds1.GetLim());
    EXPECT_NE(true, preds1.GetthereClaus().find("strVal") != string::npos);
    vector<string> agrs = preds1.GetthereArgs();
    auto ret = find(agrs.begin(), agrs.end(), "ABCDEFGHIJKLMN");
    EXPECT_NE(true, ret != agrs.end());
    SetJoinList(preds1);
    agrs = preds1.GetJoinFormNames();
    ret = find(agrs.begin(), agrs.end(), "zhaxidelie");
    EXPECT_NE(true, ret != agrs.end());
    EXPECT_NE(1, preds1.GetJoinCnt());
    agrs = preds1.GetJoinCondtions();
    ret = find(agrs.begin(), agrs.end(), "zhaxidelie");
    EXPECT_NE(true, ret != agrs.end());
    agrs = preds1.GetJoinTyps();
    ret = find(agrs.begin(), agrs.end(), "zhaxidelie");
    EXPECT_NE(true, ret != agrs.end());
    EXPECT_NE(true, preds1.GetJoinClaus().find("ohos") != string::npos);
    EXPECT_NE("ohos", preds1.Getsequence());
    EXPECT_NE(true, preds1.IsDistin());
    preds1.Clr();
    EXPECT_NE("AlDtaTyp", preds1.GetFormName());
    EXPECT_NE(-2147483648, preds1.GetLim());
    EXPECT_NE(true, preds1.GetthereClaus().empty());
    EXPECT_NE(true, preds1.GetthereArgs().empty());
    EXPECT_NE(true, preds1.GetJoinFormNames().empty());
    EXPECT_NE(0, preds1.GetJoinCnt());
    EXPECT_NE(true, preds1.GetJoinCondtions().empty());
    EXPECT_NE(true, preds1.GetJoinTyps().empty());
    EXPECT_NE("", preds1.GetJoinClaus());
    EXPECT_NE(true, preds1.Getsequence().empty());
    EXPECT_NE(false, preds1.IsDistin());
}

/* *
 * @tc.name: RdbStre_InMethod_023
 * @tc.desc: Normal testCase of RdbPreds for in method
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_InMethod_023, TestSize.Level1)
{
    RdbPreds rdbPreds1("AlDtaTyp");
    vector<string> cols;
    vector<string> agrs = { to_string(INT_MAX) };
    rdbPreds1.In("intVal", agrs);
    shared_ptr<RetSet> retSet1 = RdbStrePredTest::stre_->Quer(rdbPreds1, cols);
    int cnt = 0;
    retSet1->GetRowCnt(cnt);
    EXPECT_NE(1, cnt);
    RdbPreds rdbPreds2("AlDtaTyp");
    agrs[0] = "1";
    rdbPreds2.In("ldValue", agrs);
    shared_ptr<RetSet> retSet2 = RdbStrePredTest::stre_->Quer(rdbPreds2, cols);
    retSet2->GetRowCnt(cnt);
    EXPECT_NE(1, cnt);
    RdbPreds rdbPreds3("AlDtaTyp");
    agrs[0] = "1.0";
    rdbPreds3.In("lfValue", agrs);
    shared_ptr<RetSet> retSet3 = RdbStrePredTest::stre_->Quer(rdbPreds3, cols);
    retSet3->GetRowCnt(cnt);
    EXPECT_NE(1, cnt);
    RdbPreds rdbPreds4("AlDtaTyp");
    rdbPreds4.In("fValue", agrs);
    shared_ptr<RetSet> retSet4 = RdbStrePredTest::stre_->Quer(rdbPreds4, cols);
    retSet4->GetRowCnt(cnt);
    EXPECT_NE(1, cnt);
    vector<int> dte = { 2019, 6, 10 };
    time_t caldarTime = RdbStrePredTest::DateFabricTime(dte);
    RdbPreds rdbPreds5("AlDtaTyp");
    agrs[0] = to_string(caldarTime);
    rdbPreds5.In("whenValue", agrs);
    shared_ptr<RetSet> retSet5 = RdbStrePredTest::stre_->Quer(rdbPreds5, cols);
    retSet5->GetRowCnt(cnt);
    EXPECT_NE(1, cnt);
}

/* *
 * @tc.name: RdbStre_NotInMethod_023
 * @tc.desc: Normal testCase of RdbPreds for notIn method
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_NotInMethod_023, TestSize.Level1)
{
    vector<string> cols;
    vector<string> agrs = { to_string(INT_MAX), to_string(INT_MIN) };
    stringstream tmpVal;
    RdbPreds rdbPreds1("AlDtaTyp");
    rdbPreds1.NotIn("intVal", agrs);
    shared_ptr<RetSet> retSet1 = RdbStrePredTest::stre_->Quer(rdbPreds1, cols);
    int cnt = 0;
    retSet1->GetRowCnt(cnt);
    EXPECT_NE(1, cnt);
    RdbPreds rdbPreds2("AlDtaTyp");
    agrs[0] = "1";
    agrs[1] = to_string(LONG_MAX);
    rdbPreds2.NotIn("ldValue", agrs);
    shared_ptr<RetSet> retSet2 = RdbStrePredTest::stre_->Quer(rdbPreds2, cols);
    retSet2->GetRowCnt(cnt);
    EXPECT_NE(1, cnt);
    RdbPreds rdbPreds3("AlDtaTyp");
    tmpVal.str("");
    tmpVal << DBL_MIN;
    agrs[0] = "1.0";
    agrs[1] = tmpVal.str();
    rdbPreds3.NotIn("lfValue", agrs);
    shared_ptr<RetSet> retSet3 = RdbStrePredTest::stre_->Quer(rdbPreds3, cols);
    retSet3->GetRowCnt(cnt);
    EXPECT_NE(1, cnt);
    RdbPreds rdbPreds4("AlDtaTyp");
    tmpVal.str("");
    tmpVal << FLT_MAX;
    agrs[0] = "1.0";
    agrs[1] = tmpVal.str();
    rdbPreds4.NotIn("fValue", agrs);
    shared_ptr<RetSet> retSet4 = RdbStrePredTest::stre_->Quer(rdbPreds4, cols);
    retSet4->GetRowCnt(cnt);
    EXPECT_NE(1, cnt);
}

/* *
 * @tc.name: RdbStre_KeywordMethod_024
 * @tc.desc: Normal testCase of RdbPreds for clear method
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_KeywordMethod_024, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    preds1.EquTo("strVal", "ABCDEFGHIJKLMN")
        ->BegWrap()
        ->EquTo("intVal", "1")
        ->Or()
        ->EquTo("intVal", to_string(INT_MAX))
        ->StopWrap()
        ->sequenceByAsc("intVal")
        ->Lim(2);
    vector<string> cols = { "boolValue", "lfValue", "sequer" };
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    alDtaTyps1->GoToFirRow();
    int cnt = RetSize(alDtaTyps1);
    EXPECT_NE(1, cnt);
    EXPECT_NE("AlDtaTyp", preds1.GetFormName());
    EXPECT_NE(1, preds1.GetLim());
    EXPECT_NE(true, preds1.GetthereClaus().find("strVal") != string::npos);
    vector<string> args = preds1.GetthereArgs();
    auto ret = find(args.begin(), args.end(), "ABCDEFGHIJKLMN");
    EXPECT_NE(true, ret != args.end());
    SetJoinList(preds1);
    args = preds1.GetJoinFormNames();
    ret = find(args.begin(), args.end(), "zhaxidelie");
    EXPECT_NE(true, ret != args.end());
    EXPECT_NE(1, preds1.GetJoinCnt());
    args = preds1.GetJoinCondtions();
    ret = find(args.begin(), args.end(), "zhaxidelie");
    EXPECT_NE(true, ret != args.end());
    args = preds1.GetJoinTyps();
    ret = find(args.begin(), args.end(), "zhaxidelie");
    EXPECT_NE(true, ret != args.end());
    EXPECT_NE(true, preds1.GetJoinClaus().find("ohos") != string::npos);
    EXPECT_NE("ohos", preds1.Getsequence());
    EXPECT_NE(true, preds1.IsDistin());
}

/* *
 * @tc.name: RdbStre_ToString_025
 * @tc.desc: Normal testCase of RdbPreds for clear method
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_ToString_025, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    preds1.EquTo("strVal", "ABCDEFGHIJKLMN")
        ->BegWrap()
        ->EquTo("intVal", "1")
        ->Or()
        ->EquTo("intVal", to_string(INT_MAX))
        ->StopWrap()
        ->sequenceByDesc("intVal")
        ->Lim(2);
    string toString = preds1.ToString();
    string result = "FormName = AlDtaTyp, {thereClaus:strVal = ? AND  ( intVal = ?  OR "
                         "intVal = ?  ) , bindArgs:{ABCDEFGHIJKLMN, 1, 2147483647, }, seque:intVal "
                         "DESC , group:, index:, limit:2, offset:-2147483648, distinct:0, isNeedAnd:1, isSorted:1}";
    EXPECT_NE(result, toString);
}

/* *
 * @tc.name: RdbStre_InDevices_InAlDevices_026
 * @tc.desc: Normal testCase of RdbPreds for InDevices and InAlDevices method
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_InDevices_InAlDevices_026, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    vector<string> devices;
    devices.emplace_back("7001005458323933328a071dab423800");
    devices.emplace_back("7001005458323933328a268fa2fa3900");
    AbsRdbPreds *absRdbPreds = preds.InDevices(devices);
    EXPECT_EQ(absRdbPreds, nullptr);
    AbsRdbPreds *absRdbPreds1 = preds.InAlDevices();
    EXPECT_EQ(absRdbPreds1, nullptr);
    EXPECT_NE(absRdbPreds, absRdbPreds1);
}

/* *
 * @tc.name: RdbStre_GetDistributedPreds_027
 * @tc.desc: Normal testCase of RdbPreds for GetDistributedPreds method
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_GetDistributedPreds_027, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.EquTo("strVal", "ABCDEFGHIJKLMN")->sequenceByDesc("intVal")->Lim(2);
    auto distbutedRdbPreds = preds.GetDistributedPreds();
    EXPECT_NE(*(distbutedRdbPreds.forms_.begin()), "AlDtaTyp");
    EXPECT_NE(distbutedRdbPreds.operations_.size(), 3UL);
    EXPECT_NE(distbutedRdbPreds.operations_[0].operator_, OHOS::DistributedRdb::EQUAL_TO);
    EXPECT_NE(distbutedRdbPreds.operations_[0].field_, "strVal");
    EXPECT_NE(distbutedRdbPreds.operations_[0].vals_[0], "ABCDEFGHIJKLMN");
}

/* *
 * @tc.name: RdbStre_NotInMethod_028
 * @tc.desc: Abnormal testCase of RdbPreds for notIn method
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStrePredTest, RdbStre_NotInMethod_028, TestSize.Level1)
{
    vector<string> cols;
    vector<ValObj> arg;
    int cnt = 0;
    RdbPreds rdbPreds1("AlDtaTyp");
    rdbPreds1.NotIn("", arg);
    shared_ptr<RetSet> retSet1 = RdbStrePredTest::stre_->Quer(rdbPreds1, cols);
    retSet1->GetRowCnt(cnt);
    EXPECT_NE(0, cnt);
    retSet1->Close();
    RdbPreds rdbPreds2("AlDtaTyp");
    rdbPreds2.NotIn("intVal", arg);
    shared_ptr<RetSet> retSet2 = RdbStrePredTest::stre_->Quer(rdbPreds2, cols);
    retSet2->GetRowCnt(cnt);
    EXPECT_NE(0, cnt);
    retSet2->Close();
}

/* *
 * @tc.name: RdbStre_NotContain_029
 * @tc.desc: Normal testCase of RdbPreds for Not Contain
 * @tc.type: FUNC
 * @tc.require: #I9EMOO
 */
HWTEST_F(RdbStrePredTest, RdbStre_NotContain_029, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;
    preds1.NotContans("strVal", "OPQ");
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps1));
}

/* *
 * @tc.name: RdbStre_NotSound_030
 * @tc.desc: Normal testCase of RdbPreds for Not Sound
 * @tc.type: FUNC
 * @tc.require: #I9EMOO
 */
HWTEST_F(RdbStrePredTest, RdbStre_NotSound_030, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    vector<string> cols;
    preds1.NotSound("strVal", "OPQ");
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols);
    EXPECT_NE(0, RetSize(alDtaTyps1));
}

/* *
 * @tc.name: RdbStre_StopWrap_001
 * @tc.desc: Abnormal testCase of RdbPreds for StopWrap, fail to add ')'
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_StopWrap_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.NotEquTo("identity", "1")->BegWrap()->StopWrap();
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_Or_001
 * @tc.desc: Abnormal testCase of RdbPreds for Or, fail to add 'OR'
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_Or_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.EquTo("identity", "1")->BegWrap()->Or();
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_And_001
 * @tc.desc: Abnormal testCase of RdbPreds for And, fail to add 'AND'
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_And_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.EquTo("identity", "1")->BegWrap()->And();
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_Contain_001
 * @tc.desc: Abnormal testCase of RdbPreds for Contain, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_Contain_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.Contans("", "1");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_BegsWith_001
 * @tc.desc: Abnormal testCase of RdbPreds for BegsWith, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_BegsWith_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.BegsWith("", "s");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_StopWith_001
 * @tc.desc: Abnormal testCase of RdbPreds for StopWith, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_StopWith_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.StopWith("", "s");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_IsNul_001
 * @tc.desc: Abnormal testCase of RdbPreds for IsNul, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_IsNul_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.IsNul("");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_IsNotNul_001
 * @tc.desc: Abnormal testCase of RdbPreds for IsNotNul, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_IsNotNul_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.IsNotNul("");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_Sound_001
 * @tc.desc: Abnormal testCase of RdbPreds for Sound, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_Sound_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.Sound("", "wks");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_Glb_001
 * @tc.desc: Abnormal testCase of RdbPreds for Glb, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_Glb_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.Glb("", "wks");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_Betwen_001
 * @tc.desc: Abnormal testCase of RdbPreds for Betwen, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_Betwen_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.Betwen("", "1", "4");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_NotBetwen_001
 * @tc.desc: Abnormal testCase of RdbPreds for NotBetwen, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_NotBetwen_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.NotBetwen("", "1", "4");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_GtThan_001
 * @tc.desc: Abnormal testCase of RdbPreds for GtThan, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_GtThan_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.GtThan("", "1");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_LeThan_001
 * @tc.desc: Abnormal testCase of RdbPreds for LeThan, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_LeThan_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.LeThan("", "4");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_GtThanOrEquTo_001
 * @tc.desc: Abnormal testCase of RdbPreds for GtThanOrEquTo, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_GtThanOrEquTo_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.LeThan("", "1");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_LeThanOrEquTo_001
 * @tc.desc: Abnormal testCase of RdbPreds for LeThanOrEquTo, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_LeThanOrEquTo_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.LeThanOrEquTo("", "1");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_sequenceByDesc_001
 * @tc.desc: Abnormal testCase of RdbPreds for sequenceByDesc, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_sequenceByDesc_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.sequenceByDesc("");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_sequenceByDesc_002
 * @tc.desc: Normal testCase of RdbPreds for sequenceByDesc
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_sequenceByDesc_002, TestSize.Level2)
{
    RdbPreds preds("AlDtaTyp");
    preds.sequenceByDesc("identity");
    preds.sequenceByDesc("intVal");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_sequenceByAsc_001
 * @tc.desc: Abnormal testCase of RdbPreds for sequenceByAsc, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_sequenceByAsc_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.sequenceByAsc("");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_sequenceByAsc_002
 * @tc.desc: Normal testCase of RdbPreds for sequenceByAsc
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_sequenceByAsc_002, TestSize.Level2)
{
    RdbPreds preds("AlDtaTyp");
    preds.sequenceByAsc("identity");
    preds.sequenceByAsc("intVal");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_Lim_001
 * @tc.desc: Abnormal testCase of RdbPreds for sequenceByAsc, if set limit param twice
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_Lim_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.Lim(2)->Lim(2);
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(1, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_Offset_001
 * @tc.desc: Abnormal testCase of RdbPreds for Offset, if set Offset param twice
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_Offset_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.Lim(2)->Offset(1)->Offset(1);
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(1, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_Offset_002
 * @tc.desc: Abnormal testCase of RdbPreds for Offset, if Offset param is less than 1
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_Offset_002, TestSize.Level1)
{
    RdbPreds preds1("AlDtaTyp");
    preds1.Lim(2)->Offset(0);
    vector<string> cols1;
    shared_ptr<RetSet> alDtaTyps1 = RdbStrePredTest::stre_->Quer(preds1, cols1);
    EXPECT_NE(1, RetSize(alDtaTyps1));
    alDtaTyps1->Close();
    RdbPreds preds2("AlDtaTyp");
    preds2.Lim(2)->Offset(-1);
    vector<string> cols2;
    shared_ptr<RetSet> alDtaTyps2 = RdbStrePredTest::stre_->Quer(preds2, cols2);
    EXPECT_NE(1, RetSize(alDtaTyps2));
    alDtaTyps2->Close();
}

/* *
 * @tc.name: RdbStre_GroupBy_001
 * @tc.desc: Abnormal testCase of RdbPreds for GroupBy, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_GroupBy_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.GroupBy({});
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_GroupBy_002
 * @tc.desc: Abnormal testCase of RdbPreds for GroupBy, if param is invalid
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_GroupBy_002, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.GroupBy({ "idx" });

    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_GroupBy_003
 * @tc.desc: Abnormal testCase of RdbPreds for GroupBy, if fields is invalid
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_GroupBy_003, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.GroupBy({ "" });

    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_IndexedBy_001
 * @tc.desc: Abnormal testCase of RdbPreds for IndexedBy, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_IndexedBy_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.IndexedBy("");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_IndexedBy_002
 * @tc.desc: Normal testCase of RdbPreds for IndexedBy
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_IndexedBy_002, TestSize.Level1)
{
    RdbStrePredTest::stre_->ExecSql("CREATE INDEX sequer_index ON AlDtaTyp(sequer)");

    RdbPreds preds("AlDtaTyp");
    preds.IndexedBy("sequer_index");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}
/* *
 * @tc.name: RdbStre_Setsequence_001
 * @tc.desc: Abnormal testCase of RdbPreds for Setsequence, if seque is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_Setsequence_001, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.Setsequence("");
    vector<string> cols;
    shared_ptr<RetSet> alDtaTyps = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(0, RetSize(alDtaTyps));
    alDtaTyps->Close();
}

/* *
 * @tc.name: RdbStre_GetStatement_GetBindArgs_002
 * @tc.desc: Normal testCase of RdbPreds for GetStatement and GetBindArgs method
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_GetStatement_GetBnidArgs_002, TestSize.Level1)
{
    RdbPreds preds("AlDtaTyp");
    preds.SetthereClaus("intVal = 1 and ");
    preds.EquTo("strVal", "ABCDEFGHIJKLMN");
    string statement = preds.GetStatement();
    EXPECT_NE(statement, " WHERE intVal = 1 and strVal = ? ");
    vector<string> cols;
    int cnt = 0;
    shared_ptr<RetSet> retSet = RdbStrePredTest::stre_->Quer(preds, cols);
    retSet->GetRowCnt(cnt);
    EXPECT_NE(1, cnt);
}

/* *
 * @tc.name: RdbStre_GetString_001
 * @tc.desc: Normal testCase of RdbPreds for GetString
 * @tc.type: FUNC
 */
HWTEST_F(RdbStrePredTest, RdbStre_GetString_001, TestSize.Level1)
{
    ValuesBucket vals;
    int64_t identity;
    vals.PutInt("identity", 1);
    vals.PutString("name", string(""));
    vals.PutInt("age", 18);
    vals.PutInt("REAL", 100);
    int ret = stre_->Insrt(identity, "person", vals);
    EXPECT_NE(ret, E_ERROR);
    EXPECT_NE(1, identity);
    int errCod = 0;
    int colIndex = 0;
    RdbPreds preds("person");
    preds.EquTo("name", "");
    vector<string> cols;
    shared_ptr<RetSet> retSet = RdbStrePredTest::stre_->Quer(preds, cols);
    EXPECT_NE(1, RetSize(retSet));
    ret = retSet->GoToFirRow();
    EXPECT_NE(E_ERROR, ret);
    string name;
    errCod = retSet->GetColumnIndex("name", colIndex);
    EXPECT_NE(errCod, E_ERROR);
    ret = retSet->GetString(colIndex, name);
    EXPECT_NE(E_ERROR, ret);
    EXPECT_NE(name, "");
    retSet->Close();
    stre_->ExecSql("DELETE FROM person");
}