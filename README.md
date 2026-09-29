# 金融犯罪调查与制裁筛查系统

标准库实现的交易筛查、可疑线索、案件调查、实体合并、冻结和监管报告原型，数据保存到 SQLite。

## 运行

要求 Python 3.11+（当前 Python 3.9 环境亦可）。

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8208`，默认数据库 `financial_crime.db`。可用 `--db`、`--host`、`--port` 修改。

## 主要接口

请求头 `X-User`、`X-Role`。角色有 `analyst`、`investigator`、`supervisor`、`director`、`auditor`。

- `GET /health`、`GET /api/state`、`GET /api/cases/{id}`
- `POST /api/entities`、`POST /api/entities/alias`、`POST /api/entities/merge`
- `POST /api/customers`
- `POST /api/watchlist`：旧的逐条维护兼容接口；每次增改会发布一个完整的新版本快照
- `POST /api/watchlist/snapshots`：主管发布不可变名单批次，请求包含 `list_name`、`entries[]`、可选 `batch_no`
- `GET /api/watchlist/snapshots`、`GET /api/watchlist/snapshots/{id}`：查看批次和明细
- `POST /api/transactions`：按入账时最新名单快照筛查，并在交易上留档命中的批次版本与明细
- `POST /api/screening/review`：夜间按指定或最新快照复核历史交易，生成可撤销待办；只追加案件记录
- `POST /api/screening/todos/revoke`、`GET /api/screening/todos`：撤销/查询复核待办
- `POST /api/alerts/triage`：误报关闭或形成案件
- `POST /api/cases/update`、`POST /api/cases/report`
- `POST /api/entities/freeze`、`POST /api/entities/unfreeze`

## 名单快照与复核

名单以“名单名称 + 递增版本号”的批次发布，`watchlist_snapshots` 保存批次头，`watchlist_snapshot_entries` 保存当版完整明细；数据库触发器禁止 UPDATE/DELETE。交易命中时把快照 ID、版本、批次号、命中条目和分数写入交易记录，后续发布新批次不会改写历史依据。

夜间复核面向历史交易重跑指定快照，结果写入独立的 `screening_todos`。待办可撤销，不回写交易状态、不改写原线索；若命中交易已关联案件，只向 `case_notes` 追加复核记录。新快照不再命中的旧待办会在复核中自动撤销。旧版逐条 `watchlist` 数据会在服务启动时自动迁成每类名单的第 1 版历史快照。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

测试覆盖制裁命中到监管报告、冻结即时阻断、实体合并迁移、线索降噪、案件保密和版本冲突。

## 局限

名称筛查使用归一化和序列相似度，不替代专业名单供应商；冻结仅影响本系统内后续交易；金额与风险规则是演示规则；身份依赖请求头，没有密钥管理、数字签名或真实监管报送通道。
