# U09-GAP-001 — SAFWK / SAMgr contract

状态：候选 OH 契约已核对并用于本地简化 mock；消费方精确 revision 未锁定，M1 不关闭。

## M1–M5 状态汇总（2026-09-30 核验）

| 里程碑 | 状态 | 证据 |
|---|---|---|
| **M1 — 产品消费 SHA 锁定** | **阻塞（外部输入缺失）** | 需产品 manifest/repo-lock 确认 SAFWK/SAMgr 精确消费 revision。本工作区 `bin/update/.sync_state.json` 只记录 8 个业务仓库（无 SAFWK/SAMgr），`datamgr_service/bundle.json` 只声明依赖名无版本/SHA。候选 SHA 已固定但无法证明为产品消费版本。**所需外部输入**：产品构建 manifest 或 repo-lock 文件中 SAFWK/SAMgr 的 pinned revision。在用户提供前 M1 不关闭，U09 父步骤保持 `[ ]`。 |
| M2 — 候选源码契约核对 | ✅ 完成 | 本文下方"候选行为矩阵"，候选 SHA 来源及关键实现行号已记录 |
| M3 — 缺口证据 | ✅ 完成 | 本文"本地改动与验收"节，`tmp/ut-runs/u09-publish-m3-001/` |
| M4 — mock 行为测试 | ✅ 完成 | `tmp/ut-runs/u09-publish-m4-007/verdict.json` PASS 4/4（重复替换、ID 范围、manager 不可用、空对象） |
| M5 — 真实消费者边界 | ✅ 完成 | `tmp/ut-runs/u09-real-service-m5-003/verdict.json` PASS（禁用假 SA 1301，启动真实 KvStoreDataService 并取得 relational_store feature） |

> **M1 阻塞影响范围**：M1 不阻塞 U10–U22 的独立 DDMS/IPC 验收（U10–U22 各自门槛已通过）。M1 阻塞的是"完整 G4/S4 闭环"——即不能宣称本地 mock 行为与产品实际消费的 SAFWK/SAMgr revision 精确一致。候选 SHA 是可审计源码基线，功能验证（M4/M5）基于此基线通过。

## 来源与版本边界

本地 `bin/update/.sync_state.json` 只记录 8 个业务仓库，最近一次同步时间为 2026-09-22；`datamgr_service` 为 `b06ed9eb1a0d081ffdb624b9a49b08cc239fe700`。`datamgr_service/bundle.json` 只声明 `safwk`、`samgr` 依赖名，没有版本或 SHA。已从官方仓库 commit patch 确认下列候选的完整 SHA，并直接读取完整 SHA 对应源码；但仍无法证明下列候选就是该产品构建实际消费的 revision。候选 SHA 是可审计源码基线，不替代产品 manifest 的依赖锁定。

以下均是官方 OpenHarmony 仓库的固定候选提交，不代表本项目精确消费版本：

- SAFWK 候选：[`5f518f8ef2bad5d7efdb295cce5c5ccc02805fda`](https://github.com/openharmony/systemabilitymgr_safwk/commit/5f518f8ef2bad5d7efdb295cce5c5ccc02805fda)；[`SystemAbility::Publish` 源码](https://raw.githubusercontent.com/openharmony/systemabilitymgr_safwk/5f518f8ef2bad5d7efdb295cce5c5ccc02805fda/services/safwk/src/system_ability.cpp)，关键实现约在 67–92 行。
- SAMgr 候选：[`878d611aa0918153be131063ce19f7c183f32ec4`](https://github.com/openharmony/systemabilitymgr_samgr/commit/878d611aa0918153be131063ce19f7c183f32ec4)；[`BaseSystemAbilityManager::AddSystemAbility` 源码](https://raw.githubusercontent.com/openharmony/systemabilitymgr_samgr/878d611aa0918153be131063ce19f7c183f32ec4/services/samgr/native/source/base_system_ability_manager.cpp)，关键实现约在 894–938 行；[`SystemAbilityManager::AddSystemAbility` 源码](https://raw.githubusercontent.com/openharmony/systemabilitymgr_samgr/878d611aa0918153be131063ce19f7c183f32ec4/services/samgr/native/source/system_ability_manager.cpp) 将调用转给 base manager（约 383–403 行）。

## 候选行为矩阵

| 边界 | 当前官方候选实现 | 本地简化与验证 |
|---|---|---|
| `Publish(nullptr)` | 直接返回 `false` | `RejectsNullRemoteObject`；不调用注册 |
| SAMgr proxy 为空 | `Publish` 返回 `false` | `MOCK_SAMGR_UNAVAILABLE=1` 在 manager cache 前注入不可用状态；`ReturnsFalseWhenSamgrIsUnavailable` 严格通过 |
| `AddSystemAbility` 返回非 `ERR_OK` | `Publish` 返回 `false`；成功时才将 ability 状态置为 ACTIVE | 范围外 ID 返回非零且状态保留 `NOT_LOADED`；成功注册转为 `ACTIVE`；由严格契约测试覆盖 |
| 同一有效 ID 再次注册 | 当前 SAMgr 候选会记录覆盖通知并将 map 项替换为新 remote，正常返回 `ERR_OK`；不是必然拒绝 | `abilities_[id] = remote`；`ReplacesExistingRegistrationForSameId` 验证新对象可查询 |
| 注册输入 | `CheckInputSysAbilityId` 接受 `0..0x00ffffff`，拒绝范围外 SA ID 和空 remote；并核对 `isDistributed` 与 SA profile | 本地 mock 校验范围外 ID（下界和上界）及空 remote；SA 1301 当前 profile 与默认 `isDistributed=false` 一致，通用 profile 装载/校验未实现 |
| 当前服务 profile 对齐 | `sa_profile/1301.json` 声明 SA 1301 `distributed=false`；`KvStoreDataService::StartService` 调用 `SystemAbility::Publish(this)`，`SAExtraProp` 默认 `isDistributed=false` | 对当前 DDMS 启动目标，profile 与发布属性一致，不构成已知缺口；若后续链路触达其他 profile，再单独建 GAP |
| 资源上限及调度器失败 | SAMgr 有 map 容量限制；调度器为空可能在 map 更新后返回错误 | 未模拟；不是当前 `KvStoreDataService` 的已观测阻塞点 |

候选 `Publish` 流程：拒绝空对象；持有即将发布的 remote；取得 SAMgr proxy；调用 `AddSystemAbility`；仅 `ERR_OK` 返回 true 并置为 ACTIVE。SAMgr 对重复 ID 的覆盖行为来自当前候选源码中的 map 更新分支；因此本地契约不能把“重复必拒绝”当作 OpenHarmony 规则。

## 本地改动与验收

修正范围：`mock/innerkits/safwk/system_ability_fwk/include/system_ability.h`、`mock/src/mock_sys_ability.cpp`、`mock/src/mock_system_ability_manager.cpp`、`test/tools/mock_samgr_publish_contract_test.cpp`。mock 对合法重复 ID 执行替换，对范围外 SA ID/空 remote 返回非零；manager-unavailable 使用独立环境注入。仅 `Publish` 成功时状态从 `NOT_LOADED` 转为 `ACTIVE`；严格运行 `tmp/ut-runs/u09-publish-m4-007/verdict.json` 覆盖重复替换、ID 范围、manager 不可用、空对象及状态断言，共 4/4 PASS。原先的 M4 verdict 均保留为历史证据。

本契约只验证已实现的本地边界，不代表 SAFWK/SAMgr 的准确消费 revision 已锁定，也不代表任意 SA profile 校验、容量/调度器失败、完整注册生命周期或独立 DDMS 已验收。当前 SA 1301 的 profile 与默认发布属性相符；本目标不因尚未实现通用 profile 装载而阻塞。
