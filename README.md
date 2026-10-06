# 太空碎片接近预警与规避协调

模块化纯 Python 3.9.6+ 标准库项目，默认端口 `8331`。

## 模块

- `app.py`：参数解析、依赖组装和 HTTP 生命周期。
- `src/domain.py`：领域类型、校验和错误定义。
- `src/rules.py`：风险评估、意见冲突和状态机。
- `src/repository.py`：SQLite、事务、乐观版本、双链审计账、监管回执和分叉处置。
- `src/service.py`：身份、权限、用例编排、隔离守卫。
- `src/http_api.py`：JSON API 和静态首页。
- `src/audit.py`：哈希摘要、事件链/总账链重算与回执对账定位。

## 审计总账模型

审计账是**双链**，业务动作落账时在同一事务内同步推进：

- **事件链**：每个接近事件一条哈希链（`previous_hash`/`event_hash`），供按事件逐条查阅；
- **整库总账**：全库唯一连续链位 `seq=1,2,3,…`，每条含 `global_previous_hash`/`global_hash`，删行、补写都能从连续总账上发现。

监管每季度持有回执锚值（链位 + 该链位总账锚值）。对账时从 `GENESIS` 重算：先做结构校验（链位连续、存储链接环），再用回执锚值比对，**从最近一次一致的链位之后定位分叉起点**，并给出涉及的接近事件。

分叉处置（`enforce`，监管发起）：

- 分叉涉及的接近事件进入隔离，**停止批准（approve）和下发（execute）**，接口返回 `event_quarantined`；
- 已批准未执行（`coordinating`）的事件退回 `assessed` 重议，并落 `returned_for_review` 账；
- 核实处理完后监管可解除隔离，事件留在 `assessed` 重新走批准。

旧库升级：启动时若审计表缺少总账列，按审计行原 `id` 顺序在同一事务内回填总账摘要（可重复执行）；**既有事件链摘要值永不改写**。链位由写事务（`BEGIN IMMEDIATE`）串行分配，并由 `seq` 唯一索引兜底，两人同时保存同一事件绝不会写出同一链位。

## 接口

除原有接口外，新增：

- `GET /api/items/<id>/audit`：按接近事件逐条查账，含事件链校验结果 `chain`。
- `GET /api/ledger`：整库连续总账（全部事件、链位、锚值、结构校验、已登记回执）。
- `POST /api/receipts`：监管登记季度回执锚值 `{period, seq, anchor}`（`X-Role: regulator`）。
- `GET /api/receipts`：已登记回执。
- `POST /api/reconcile`：对账，可用已登记回执或在请求体给 `anchors: [{seq, anchor}]`；`enforce` 默认 `true`，分叉时自动隔离并退回重议，设为 `false` 只出报告。
- `POST /api/items/<id>/quarantine/release`：监管解除隔离。

## 运行

```bash
python3 app.py --init --db ./data.db
python3 app.py --db ./data.db --port 8331
```

服务提供 `GET /health`、`GET /api/state`、`GET /api/items`、`POST /api/items`、`POST /api/items/<id>/sources` 和 `POST /api/items/<id>/actions`。身份使用 `X-User-Id`、`X-Role` 请求头。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

测试覆盖评估、批准、执行、解决、重复告警、权限、版本冲突、过期轨道和运营方意见冲突，以及整库总账连续性、删行/补写检测、监管回执对账与分叉定位、隔离与退回重议、旧库回填幂等性、并发链位唯一。数据使用 SQLite 持久化；规则是可运行的演示模型，不替代真实轨道力学、碰撞概率和空间交通协调服务。
