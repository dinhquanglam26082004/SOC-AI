const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync(require('node:path').join(__dirname, '../web/index.html'), 'utf8');
const rowSource = html.slice(html.indexOf('    function row('), html.indexOf('    function empty('));
const renderSource = html.slice(html.indexOf('    function renderAlerts('), html.indexOf('    function render(data)'));
const node = () => ({innerHTML:'', textContent:'', querySelectorAll:()=>[]});
const nodes = {'recent-alerts':node(),'all-alerts':node(),'alert-summary':node(),'investigation-list':node()};
const alert = id => ({id, rule:{id:'100181',description:'DNS'}, agent:{name:'victim'}, ai_status:'completed'});
const representative = alert('first');
const related = {...alert('second'),ai_status:'skipped',ai_group:{representative_alert_id:'first'}};
const scope = {alerts:[representative,related],alertTotal:2,selectedInvestigation:null,
  $:id=>nodes[id],attentionHTML:()=>'',wireRows:()=>{},severityName:()=>'',
  esc:x=>String(x ?? '—'),date:x=>String(x ?? '—'),badge:x=>String(x ?? ''),state:x=>String(x ?? '')};
vm.runInNewContext(rowSource+'\n'+renderSource+'\nthis.render=renderAlerts;',scope);
scope.render();
assert.match(nodes['all-alerts'].innerHTML,/data-alert="first"/);
assert.match(nodes['all-alerts'].innerHTML,/data-alert="second"/);
assert.doesNotMatch(nodes['all-alerts'].innerHTML,/data-alert-group|cảnh báo liên quan đã tải/);
assert.equal(related.ai_group.representative_alert_id,'first');
console.log('Alert list displays individual records.');
