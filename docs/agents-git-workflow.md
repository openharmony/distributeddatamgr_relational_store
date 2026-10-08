# 变更提交

## Mock 仓库与上游的关系

本仓库的 git remote `origin` 指向 mock 仓库自身的远程（gitee），与 OpenHarmony 上游仓库（gitcode.com/openharmony/*）是不同的仓库。本地修改分两类：

1. **Mock 仓库自身的产物**（提交到 gitee）：`CMakeLists.txt`、`test/`、`mock/`、`AGENTS.md`、`docs/`、`bin/` 等受保护内容。
2. **从上游同步来的代码**（不提交到 mock 仓库）：各模块目录下非受保护的 `.cpp`/`.h` 文件，这些由 `sync.ps1` 管理。

> 上游同步是单向的（上游 → 本地）。`sync.ps1` 不支持反向同步。如需将本地对上游代码的修改回传 OpenHarmony，需在上游仓库的 `bin/update/tmp/<repo_name>` 工作树中手动操作。

## Git 提交规范

提交信息使用以下前缀：

| 前缀 | 用途 | 示例 |
|---|---|---|
| `feat:` | 新功能 | `feat(runtime_manager): register ProgressCallback per taskId` |
| `fix:` | 修复缺陷 | `fix: resolve memory leak in rdb_service` |
| `test:` | 测试用例 | `test: add 11 batch processing tests (022-032)` |
| `docs:` | 文档 | `docs: add Stop interface and batch progress test scenarios` |
| `refactor:` | 重构 | `refactor: remove dead EventManager code` |
| `cleanup:` | 清理 | `cleanup: remove temporary backups and sync workspace` |

```bash
# 提交并推送到 mock 仓库远程
git add <files>
git commit -m "feat(<module>): <description>"
git push origin master
```

## Git 分支策略

| 分支 | 用途 | 操作 |
|------|------|------|
| `master` | 上游同步的干净镜像 | `sync.ps1` 在此分支执行同步；同步后此分支的代码仓内容与上游完全一致 |
| `feature/*` | 本地代码修改 | 从 `master` 新建分支，在此分支上修改 mock 代码、CMakeLists.txt、测试等 |

**工作流：**

```bash
# 1. 切换到 master，执行上游同步
git checkout master
.\bin\update\sync.ps1 -FullSync -Force

# 2. 同步完成后，从 master 创建功能分支
git checkout -b feature/my-adaptation

# 3. 在功能分支上修改代码（mock 适配、CMake、测试等）
# ... 修改文件 ...

# 4. 提交到功能分支
git add <files>
git commit -m "feat(rdb): add mock for TmpFileGuard"

# 5. 下次上游同步前，先切回 master
git checkout master
.\bin\update\sync.ps1 -FullSync -Force

# 6. 将 master 的上游更新合并到功能分支
git checkout feature/my-adaptation
git rebase master  # 或 merge
```

> **核心原则**：`master` 分支只用于上游同步，不在其上直接修改代码。所有本地修改（mock 适配、CMake 配置、测试代码等）在功能分支上进行。
