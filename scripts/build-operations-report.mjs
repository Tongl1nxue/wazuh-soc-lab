import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Workbook, SpreadsheetFile } from '@oai/artifact-tool';

const [project, destination, reportDate, python] = process.argv.slice(2);
if (!project || !destination || !python || !/^\d{4}-\d{2}-\d{2}$/.test(reportDate ?? '')) {
  throw new Error('Usage: node build-operations-report.mjs PROJECT OUTPUT YYYY-MM-DD BUNDLED_PYTHON');
}
const read = (name) => fs.readFile(path.join(project, name), 'utf8');
const summary = JSON.parse(await read('output/operations/analysis-summary.json'));
const tickets = JSON.parse(await read('output/tickets/tickets.json'));
const verification = JSON.parse(await read('evidence/detection/verification.json'));

function readCsv(name) {
  // CSV import can infer date types. Preserve the explicit UTC+08:00 timestamp and IDs.
  const reader = `import csv, json, sys
with open(sys.argv[1], encoding='utf-8-sig', newline='') as source:
    json.dump(list(csv.DictReader(source)), sys.stdout, ensure_ascii=True)
`;
  return JSON.parse(execFileSync(python, ['-c', reader, path.join(project, name)], { encoding: 'utf8' }));
}

const [alerts, archives, stats] = await Promise.all([
  readCsv('output/operations/alerts.csv'),
  readCsv('output/operations/archives.csv'),
  readCsv('output/operations/alert-statistics.csv'),
]);
assert.equal(summary.run_id, verification.run_id);
assert.equal(alerts.length, summary.alert_records);
assert.equal(archives.length, summary.archive_records);
assert.equal(stats.reduce((total, row) => total + Number(row.alert_count), 0), alerts.length);
for (const row of stats) {
  const matches = alerts.filter((alert) => String(alert.rule_id) === String(row.rule_id));
  assert.equal(matches.length, Number(row.alert_count));
  assert.equal(matches.length, summary.alert_counts_by_rule[row.rule_id]);
  assert(matches.every((alert) => alert.category === row.category && Number(alert.rule_level) === Number(row.rule_level)));
}
const linkedIds = new Set(tickets.flatMap((ticket) => ticket.primary_alert_ids));
assert.deepEqual(linkedIds, new Set([...verification.ssh_alert_ids, ...verification.custom_alert_ids]));
const alertById = new Map(alerts.map((alert) => [String(alert.event_id), alert]));
for (const ticket of tickets) {
  assert.equal(ticket.run_id, summary.run_id);
  assert.equal(ticket.evidence_sha256, summary.source_sha256);
  assert.equal(ticket.status === '已关闭（模拟工单）', Boolean(ticket.closed_at));
  ticket.primary_alert_ids.forEach((id, index) => {
    const alert = alertById.get(id);
    assert(alert && ticket.rule_ids.includes(String(alert.rule_id)));
    assert.equal(alert.document_id, ticket.primary_document_ids[index]);
  });
}

const dates = new Set(alerts.map((row) => row.timestamp_china.slice(0, 10)));
assert.equal(dates.size, 1, 'This weekly report expects one observed experiment date');
const [observedDate] = dates;
const start = new Date(`${observedDate}T00:00:00Z`);
start.setUTCDate(start.getUTCDate() - (start.getUTCDay() + 6) % 7);
const end = new Date(start);
end.setUTCDate(end.getUTCDate() + 6);
const week = `${start.toISOString().slice(0, 10)} 至 ${end.toISOString().slice(0, 10)}`;
const pending = tickets.filter((ticket) => !ticket.closed_at).length;

const wb = Workbook.create();
const overview = wb.worksheets.add('汇总');
const alertSheet = wb.worksheets.add('告警明细');
const archiveSheet = wb.worksheets.add('归档明细');
const ticketSheet = wb.worksheets.add('模拟工单');
const ink = '#172B43';
const muted = '#52647A';
const headerFill = '#203A59';
const stripe = '#F0F5FA';
const fmtTime = 'yyyy-mm-dd hh:mm:ss.000';

function prepare(sheet, extent, widths, title) {
  sheet.showGridLines = false;
  const region = sheet.getRange(extent);
  region.format.font = { name: 'Arial', size: 10, color: ink };
  region.format.verticalAlignment = 'center';
  region.format.rowHeight = 21;
  widths.forEach((width, index) => {
    sheet.getRangeByIndexes(0, index, 1, 1).format.columnWidthPx = width;
  });
  sheet.getRange('A2').values = [[title]];
  sheet.getRange('A2').format.font = { name: 'Arial', size: 15, bold: true, color: ink };
  sheet.getRange('A2').format.rowHeight = 30;
}

function header(sheet, address) {
  const cells = sheet.getRange(address);
  cells.format = { fill: headerFill, font: { name: 'Arial', size: 10, bold: true, color: '#FFFFFF' },
    horizontalAlignment: 'center', verticalAlignment: 'center', rowHeight: 26 };
  cells.format.borders = { insideVertical: { style: 'thin', color: '#FFFFFF' } };
}

function alternate(sheet, first, count, columns) {
  for (let offset = 0; offset < count; offset += 2) {
    sheet.getRangeByIndexes(first - 1 + offset, 0, 1, columns).format.fill = stripe;
  }
}

function excelTime(iso) {
  return iso ? Date.parse(`${iso.slice(0, 23)}Z`) / 86400000 + 25569 : null;
}

const alertEnd = 5 + alerts.length;
const archiveEnd = 5 + archives.length;
function detail(sheet, rows, title, source) {
  const last = 5 + rows.length;
  prepare(sheet, `A1:K${last + 2}`, [178, 159, 75, 59, 117, 73, 173, 229, 156, 177, 227], title);
  sheet.getRange('A3').values = [[`来源 ${source} · 时间 UTC+08:00 · ${summary.run_id}`]];
  sheet.getRange('A3').format.font = { name: 'Arial', size: 10, italic: true, color: muted };
  sheet.getRange('A5:K5').values = [[
    '北京时间', '事件分类', '规则编号', '级别', '主机别名', 'HTTP 状态', '请求路径', '日志来源', '事件编号', '索引文档 ID', '索引名称',
  ]];
  header(sheet, 'A5:K5');
  sheet.getRange(`A6:A${last}`).setNumberFormat(fmtTime);
  sheet.getRange(`C6:C${last}`).setNumberFormat('@');
  sheet.getRange(`I6:K${last}`).setNumberFormat('@');
  sheet.getRange(`A6:K${last}`).values = rows.map((row) => [
    excelTime(row.timestamp_china), row.category, String(row.rule_id),
    row.rule_level === '' ? null : Number(row.rule_level), row.agent_alias,
    row.http_status === '' ? null : Number(row.http_status), String(row.url_path).split('?')[0],
    row.log_source, String(row.event_id), String(row.document_id).replace(/^'(?=[=+\-@])/, ''), row.index,
  ]);
  alternate(sheet, 6, rows.length, 11);
  sheet.freezePanes.freezeRows(5);
}

detail(alertSheet, alerts, '告警明细', 'alerts.csv');
detail(archiveSheet, archives, '归档明细', 'archives.csv');

const ticketEnd = 5 + tickets.length;
const linkHeader = ticketEnd + 3;
const linkRows = tickets.flatMap((ticket) => ticket.primary_alert_ids.map((id, index) =>
  [ticket.ticket_id, id, ticket.primary_document_ids[index], String(alertById.get(id).rule_id)]));
const linkEnd = linkHeader + linkRows.length;
prepare(ticketSheet, `A1:G${linkEnd}`, [205, 195, 227, 185, 80, 184, 435], '模拟工单与告警关联');
ticketSheet.getRange('A3').values = [['来源 tickets.json · 授权实验记录 · 时间 UTC+08:00']];
ticketSheet.getRange('A5:G5').values = [['工单编号', '场景', '当前状态', '首条告警时间', '关联数', '关闭时间', '复测证据']];
header(ticketSheet, 'A5:G5');
ticketSheet.getRange(`A6:G${ticketEnd}`).values = tickets.map((ticket) => [
  ticket.ticket_id, ticket.title, ticket.status, excelTime(ticket.first_alert_time_china),
  null, excelTime(ticket.closed_at), ticket.retest,
]);
ticketSheet.getRange(`D6:D${ticketEnd}`).setNumberFormat(fmtTime);
ticketSheet.getRange(`F6:F${ticketEnd}`).setNumberFormat('yyyy-mm-dd hh:mm:ss');
ticketSheet.getRange(`A6:G${ticketEnd}`).format.rowHeight = 38;
ticketSheet.getRange(`G6:G${ticketEnd}`).format.wrapText = true;
alternate(ticketSheet, 6, tickets.length, 7);
ticketSheet.getRange(`C6:C${ticketEnd}`).conditionalFormats.add('containsText', {
  text: '待关闭复核', format: { fill: '#FFF2D9', font: { color: '#805000' } },
});
ticketSheet.getRange(`A${linkHeader - 1}`).values = [['主告警关联']];
ticketSheet.getRange(`A${linkHeader}:D${linkHeader}`).values = [['工单编号', '告警编号', '索引文档 ID', '规则编号']];
header(ticketSheet, `A${linkHeader}:D${linkHeader}`);
ticketSheet.getRange(`A${linkHeader + 1}:D${linkEnd}`).setNumberFormat('@');
ticketSheet.getRange(`A${linkHeader + 1}:D${linkEnd}`).values = linkRows;
alternate(ticketSheet, linkHeader + 1, linkRows.length, 4);
tickets.forEach((_, index) => {
  const row = index + 6;
  ticketSheet.getRange(`E${row}`).formulas = [[`=COUNTIF(A${linkHeader + 1}:A${linkEnd},A${row})`]];
});

const statStart = 9;
const statEnd = statStart + stats.length - 1;
const totalsRow = statEnd + 1;
prepare(overview, 'A1:F23', [226, 176, 118, 113, 25, 350], 'SOC 实验运营台账');
overview.tabColor = headerFill;
overview.getRange('A4:B6').values = [
  ['报告日期', excelTime(`${reportDate}T00:00:00.000`)],
  ['实验日期', excelTime(`${observedDate}T00:00:00.000`)],
  ['实验批次', summary.run_id],
];
overview.getRange('B4:B5').setNumberFormat('yyyy-mm-dd');
overview.getRange('F4:F6').values = [[`报告周期 ${week}`], ['统计范围为该批次的留存快照'], ['数据来源见各明细页及工单页']];
overview.getRange('F4:F6').format.font = { name: 'Arial', size: 10, italic: true, color: muted };
overview.getRange('A8:D8').values = [['告警分类', '规则编号', '规则级别', '告警数']];
header(overview, 'A8:D8');
overview.getRange(`B${statStart}:B${statEnd}`).setNumberFormat('@');
overview.getRange(`A${statStart}:C${statEnd}`).values = stats.map((row) => [row.category, String(row.rule_id), Number(row.rule_level)]);
stats.forEach((_, index) => {
  const row = statStart + index;
  overview.getRange(`D${row}`).formulas = [[`=COUNTIF('告警明细'!$C$6:$C$${alertEnd},B${row})`]];
});
alternate(overview, statStart, stats.length, 4);
overview.getRange(`A${totalsRow}`).values = [['告警合计']];
overview.getRange(`D${totalsRow}`).formulas = [[`=SUM(D${statStart}:D${statEnd})`]];
overview.getRange(`A${totalsRow}:D${totalsRow}`).format.font = { name: 'Arial', bold: true, color: ink };
overview.getRange('A14:D14').values = [['归档与工单', '数量', '单位', '']];
header(overview, 'A14:D14');
overview.getRange('A15:A19').values = [['归档记录'], ['模拟工单'], ['待关闭复核'], ['已关闭'], ['已关联主告警']];
overview.getRange('C15:C19').values = [['条'], ['份'], ['份'], ['份'], ['条']];
overview.getRange('B15:B19').formulas = [
  [`=COUNTA('归档明细'!J6:J${archiveEnd})`],
  [`=COUNTA('模拟工单'!A6:A${ticketEnd})`],
  ['=B16-B18'],
  [`=COUNT('模拟工单'!F6:F${ticketEnd})`],
  [`=SUM('模拟工单'!E6:E${ticketEnd})`],
];
alternate(overview, 15, 5, 4);
overview.getRange('A21').values = [['归档与告警各自计数。事件研判和复测依据见模拟工单。']];
overview.getRange('A21').format.font = { name: 'Arial', size: 10, italic: true, color: muted };

wb.recalculate();
assert.deepEqual(overview.getRange(`D${statStart}:D${statEnd}`).values.flat(), stats.map((row) => Number(row.alert_count)));
assert.equal(overview.getRange(`D${totalsRow}`).values[0][0], alerts.length);
assert.deepEqual(overview.getRange('B15:B19').values.flat(), [archives.length, tickets.length, pending, tickets.length - pending, linkedIds.size]);
assert.deepEqual(ticketSheet.getRange(`E6:E${ticketEnd}`).values.flat(), tickets.map((ticket) => ticket.primary_alert_ids.length));
const inspected = await wb.inspect({ kind: 'table', range: '汇总!A8:D19', include: 'values,formulas', tableMaxRows: 12, tableMaxCols: 4 });
console.log(inspected.ndjson);
const errors = await wb.inspect({ kind: 'match', searchTerm: '#REF!|#DIV/0!|#VALUE!|#N/A|#NAME\\?|#NUM!|#SPILL!', options: { useRegex: true, maxResults: 30 } });
console.log(errors.ndjson);

await fs.mkdir(destination, { recursive: true });
const previewDir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'previews');
await fs.mkdir(previewDir, { recursive: true });
for (const [name, range, file] of [
  ['汇总', 'A1:F21', 'overview'], ['告警明细', `A1:K${alertEnd}`, 'alerts'],
  ['归档明细', `A1:K${archiveEnd}`, 'archives'], ['模拟工单', `A1:G${linkEnd}`, 'tickets'],
]) {
  const image = await wb.render({ sheetName: name, range, scale: 1, format: 'png' });
  await fs.writeFile(path.join(previewDir, `${file}.png`), new Uint8Array(await image.arrayBuffer()));
}
const workbookName = `SOC-运营台账-${reportDate}.xlsx`;
const output = await SpreadsheetFile.exportXlsx(wb);
await output.save(path.join(destination, workbookName));

const report = `# SOC 安全运营周报

报告周期 ${week}  
整理日期 ${reportDate}  
统计范围 ${observedDate} 的本地授权实验批次 \`${summary.run_id}\`

本周验证了 SSH 与 Nginx 的日志采集、归档和告警查询，并对规则 \`100110\` 完成真实日志回放及实时复测。下表统计的是留存的单批次快照。归档与告警分别计数。

| 统计项 | 数量 |
| --- | ---: |
| 原始归档 | ${archives.length} |
| 告警 | ${alerts.length} |
${stats.map((row) => `| ${row.category}（规则 \`${row.rule_id}\`） | ${row.alert_count} |`).join('\n')}
| 模拟工单 | ${tickets.length} |
| 待关闭复核 | ${pending} |
| 已关闭 | ${tickets.length - pending} |

## 告警研判与复测

- **SSH 无效用户名连接。** 最终批次发起 ${verification.ssh_connections} 次本机连接，检索到 ${verification.ssh_invalid_user_log_entries} 条对应的 Invalid user 日志和 ${summary.alert_counts_by_rule['5710']} 条规则 \`5710\` 告警。已核对测试背景与原始日志，结论为授权模拟活动。
- **Web 环境配置路径访问。** 五条对照请求均可在 archives 查询。\`/.env\` 返回 HTTP 404，产生 ${verification.custom_alert_count} 条 level 7 自定义告警。对照中四条请求的自定义规则命中数为 ${verification.negative_custom_matches}。本次响应状态支持“目标资源未找到”的研判，验证范围为检测。

候选规则曾将包含 \`.env\` 的文档路径提升为敏感路径告警。调优后使用精确路径边界，并允许查询参数，保留了正例命中。普通 404 仍由原生规则处理。

Manager 重建后曾出现归档转发关闭。检查发现 Manager 仍生成归档，Filebeat 的基础开关恢复为关闭。通过持久挂载启动脚本并设置 \`-M wazuh.archives.enabled=true\` 后，重建 Manager 并使用新请求复验了归档和告警链路。

## 工单跟踪

| 工单 | 场景 | 主告警 | 状态 | 关闭时间（北京时间） |
| --- | --- | ---: | --- | --- |
${tickets.map((ticket) => `| ${ticket.ticket_id} | ${ticket.title} | ${ticket.primary_alert_ids.length} | ${ticket.status} | ${ticket.closed_at || '待填写'} |`).join('\n')}

两类实验共关联 ${linkedIds.size} 条主告警。其余普通 Web 4xx 告警作为对照保留在告警明细中。工单动作与复测记录见对应 Markdown 和台账关联页。

## 后续安排

1. 复核模拟工单的关闭依据，记录实际关闭时间后刷新台账与周报。
2. 整理 README、可复现步骤和脱敏后的真实查询截图，准备 GitHub 项目交付。
3. 完成基础交付后，再评估 Suricata、外部通知与威胁情报集成。

## 数据来源

- 告警明细、归档明细和分组统计来自 \`output/operations\` 中的 CSV 及分析摘要。
- 工单状态来自 \`output/tickets/tickets.json\`，检测结果来自 \`evidence/detection/verification.json\`。
- 同批台账 [${workbookName}](./${workbookName}) 提供规则级别、事件编号和索引文档 ID，便于对账。
`;
await fs.writeFile(path.join(destination, `SOC-运营周报-${reportDate}.md`), report, 'utf8');
console.log(`Verified ${alerts.length} alerts, ${archives.length} archives, ${tickets.length} tickets, ${pending} pending, ${linkedIds.size} links.`);
