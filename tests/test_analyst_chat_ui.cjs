// Exercise chat lookup metadata and the explicit continuation button.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
const start = html.indexOf('    let chatMessages=[]');
const end = html.indexOf("    $('chat-input').addEventListener", start);
assert.ok(start >= 0 && end > start);
const elements = {
  'chat-history': {innerHTML: '', scrollTop: 0, scrollHeight: 0,
    addEventListener(type, handler) { this[type] = handler; }},
  'chat-input': {value: ''},
  'chat-form': {requests: 0, requestSubmit() { this.requests++; }},
};
const scope = {
  $: id => elements[id],
  esc: value => String(value ?? '—').replace(/[&<>"']/g, c =>
    ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c])),
};
const code = html.slice(start, end) + `
  this.chatTest = {
    setMessages: value => { chatMessages = value; },
    render: renderChat,
    requested: () => chatRequestedSearch,
    label: chatLookupLabel,
  };`;
vm.runInNewContext(code, scope);

const lookup = {name:'search_alerts', ok:true, total:14, returned:8, has_more:true, next_page:2,
  scope:{rule_id:'100181', keyword:'<unsafe>', page:1, page_size:8,
    snapshot_max_rowid:42, snapshot_generation:0}};
scope.chatTest.setMessages([{role:'assistant', content:'Các cảnh báo được tìm thấy.', lookups:[lookup]}]);
scope.chatTest.render();
assert.match(elements['chat-history'].innerHTML, /14 cảnh báo khớp/);
assert.match(elements['chat-history'].innerHTML, /8 bản ghi gửi cho mô hình/);
assert.match(elements['chat-history'].innerHTML, /Xem trang 2/);
assert.match(elements['chat-history'].innerHTML, /&lt;unsafe&gt;/);
assert.doesNotMatch(elements['chat-history'].innerHTML, /<unsafe>/);

elements['chat-history'].click({target:{closest:()=>({dataset:{chatMessage:'0',chatLookup:'0'}})}});
const request = scope.chatTest.requested();
assert.equal(request.page, 2);
assert.equal(request.rule_id, '100181');
assert.equal(request.snapshot_max_rowid, 42);
assert.equal(request.snapshot_generation, 0);
assert.equal(elements['chat-form'].requests, 1);
assert.match(elements['chat-input'].value, /trang 2/);
assert.match(scope.chatTest.label({...lookup, context_limited:true}), /chưa được gửi/);
console.log('Analyst chat lookup UI checks passed.');
