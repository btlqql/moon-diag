# 外部对照：can-isotp 2.0.7 与 udsoncan 1.26.1

日期：2026-10-24。参考实现安装到 `D:\Codex\tools\pyrefs`，仅用于开发对照，不是 MoonDiag 的运行时依赖。

## 方法

```powershell
python -m pip install --target D:\Codex\tools\pyrefs can-isotp==2.0.7 udsoncan==1.26.1
$env:MOONBIT_PYREFS = "D:\Codex\tools\pyrefs"
python scripts\reference_compare.py
```

`scripts/reference_compare.py` 用 `can-isotp` 重组 MoonDiag 示例中的 FF/CF 帧，用 `udsoncan` 解析同一批 UDS 响应。

## 结果

| 对照项 | 输入 | 参考结果 | MoonDiag | 结论 |
|---|---|---|---|---|
| ISO-TP 多帧重组 | `10 14 62 F1 90 31 32 33` + 两条 CF | `62F190...4647` | 同一 payload | 一致 |
| UDS 负响应 | `7F 22 31` | `ReadDataByIdentifier`，NRC `0x31` | `Negative(0x22, 0x31)` | 一致 |
| UDS DID 正响应 | `62 F1 90 ...` | `ReadDataByIdentifier`，data `F190...` | DID `0xF190` + VIN | 一致 |
| UDS DTC 记录 | `59 02 FF 03 01 2F 00` | 1 条 DTC，ID `0x03012F`，status `0x00` | `P0301-2F`，failure type `0x2F`，status `0x00` | 一致 |

脚本输出：

```text
[PASS] isots reassembly payload=62F1903132333435363738393041424344454647
[PASS] uds negative 7F 22 31 positive=False code=0x31
[PASS] uds DID F190 service=ReadDataByIdentifier data=F1903132333435363738393041424344454647
[PASS] uds DTC 03 01 2F 00 count=1 id=0x03012F status=0x00
All reference comparisons passed.
```

## 对照发现并修复的问题

第一次对照时，MoonDiag 把 UDS DTC 记录按 3 字节（2 字节 DTC + 1 字节状态）解析；`udsoncan` 显示正确记录是 **4 字节：3 字节 DTC + 1 字节状态**，其中第三个 DTC 字节是 failure type。已修正：

- `parse_dtc_response` 按 4 字节记录读取。
- 显示格式从 `P0301` 改为 `P0301-2F`（failure type 保留）。
- `Dtc` 增加 `failure_type` 字段；JSON 输出包含 `code`、`failureType`、`status`。
- 测试同步更新。

这个差异在原来的自造样例里没有暴露，是外部对照的直接收益。

## 差异与未覆盖

- `udsoncan` 把 DTC 显示为 24 位 ID `0x03012F`；MoonDiag 拆成 2 字节代码 + failure type。两者字节解释一致，只是展示约定不同。
- 只对照了 UDS 负响应、DID 正响应和 DTC；没有覆盖所有服务、会话控制、安全访问、下载流程。
- ISO-TP 只对照了多帧重组；没有对照流控时序、STmin、块大小、超时和 CAN FD。
- 输入仍是作者构造的合法帧，不是真实车辆日志。
- 参考库版本固定为上述版本；升级后应重跑脚本。

## 参考库许可证

- `can-isotp` 2.0.7：MIT。
- `udsoncan` 1.26.1：MIT。

两者只在对照脚本中导入，不进入 MoonDiag 的构建或发布产物。
