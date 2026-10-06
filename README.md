# 太空碎片接近预警与规避协调

模块化纯 Python 3.9.6+ 标准库项目，默认端口 `8331`。

## 模块

- `app.py`：参数解析、依赖组装和 HTTP 生命周期。
- `src/domain.py`：领域类型、校验和错误定义。
- `src/rules.py`：风险评估、意见冲突和状态机。
- `src/repository.py`：SQLite、事务、乐观版本和审计链。
- `src/service.py`：身份、权限、用例编排。
- `src/http_api.py`：JSON API 和静态首页。
- `src/audit.py`：哈希审计事件。

## 运行

```bash
python3 app.py --init --db ./data.db
python3 app.py --db ./data.db --port 8331
```

服务提供 `GET /health`、`GET /api/state`、`GET /api/items`、`POST /api/items`、`POST /api/items/<id>/sources` 和 `POST /api/items/<id>/actions`。身份使用 `X-User-Id`、`X-Role` 请求头。

## 审计账与监管回执

业务动作落账时，除按接近事件各串一条审计链外，还会在整库连续的总账（`ledger_entries`）里同步追加一条哈希链，两条链在同一事务内推进。总账每个链位（`seq`）唯一，并发保存时由 `BEGIN IMMEDIATE` 串行分配，不会写出同一链位。

- `GET /api/audit/receipt`：当前总账链头，即监管季度对账时持有的回执锚值。
- `GET /api/audit/ledger`：整库连续的总账。
- `POST /api/audit/reconcile`：提交 `{"anchor": "<锚值>", "anchor_seq": <链位>}` 对账。从创世链位起重放整库总账，锚值对不上即从最近一致处往后定位分叉（`fork_seq`），并冻结分叉涉及的接近事件：停止批准（`approve`）和下发（`execute`），已批准未执行（`coordinating`）的退回重议（`assessed`）。不传锚值则只做整库内部一致性校验。

旧数据升级时，`initialize()` 会把既有审计事件按原顺序补入总账，只补缺、不重算，既有摘要值一律不动。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

测试覆盖评估、批准、执行、解决、重复告警、权限、版本冲突、过期轨道、运营方意见冲突、总账连续落账、回执对账、篡改分叉定位与冻结、旧数据补齐和并发链位唯一。数据使用 SQLite 持久化；规则是可运行的演示模型，不替代真实轨道力学、碰撞概率和空间交通协调服务。
