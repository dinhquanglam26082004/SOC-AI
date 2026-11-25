const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync(require('node:path').join(__dirname, '../web/index.html'), 'utf8');
const source = html.slice(html.indexOf('    function row('), html.indexOf('    function empty('));
const scope = {
  esc: x => String(x ?? '—').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),
  date: x => String(x ?? '—'), badge: x => String(x ?? ''), state: x => String(x ?? '')
};
vm.runInNewContext(source + '\nthis.group=groupLoadedAlerts;this.render=alertGroupsHTML;', scope);
const alert = id => ({id, rule:{id:'100181',description:'DNS'}, agent:{name:'victim'}, ai_status:'completed'});
const representative = alert('first');
const related = {...alert('second'), ai_status:'skipped', ai_group:{representative_alert_id:'first'}};
const other = alert('third');
let output = scope.render([related, other, representative], new Set());
assert.match(output, /Xem 2 cảnh báo liên quan đã tải/);
assert.match(output, /data-alert="first"/);
assert.doesNotMatch(output, /data-alert="second"/);
assert.match(output, /data-alert="third"/);
output = scope.render([related, other, representative], new Set(['first']));
assert.match(output, /Thu gọn 2 cảnh báo liên quan đã tải/);
assert.match(output, /data-alert="second"/);
assert.equal(scope.group([alert('a'),alert('b')]).length, 2);
const more = {...alert('fourth'), ai_group:{representative_alert_id:'missing'}};
const another = {...alert('fifth'), ai_group:{representative_alert_id:'missing'}};
assert.match(scope.render([more, another], new Set()), /2 cảnh báo liên quan đã tải/);
assert.doesNotMatch(scope.render([more], new Set()), /cảnh báo liên quan đã tải/);
console.log('Alert grouping UI checks passed.');
