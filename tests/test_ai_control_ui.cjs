const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
assert.match(html, /id="ai-toggle"/);
assert.match(html, /id="ai-toggle-investigation"/);
const source = html.slice(html.indexOf('    function renderAIControl('),
                          html.indexOf('    function renderCollection('));
const buttons = Object.fromEntries(['ai-toggle', 'ai-toggle-investigation'].map(id => [id, {
  setAttribute(name, value) { this[name] = value; }
}]));
const requests = [];
const scope = {
  aiPaused: null, aiControlBusy: false, $: id => buttons[id],
  api: async (url, options) => { requests.push({url, options}); return {paused: JSON.parse(options.body).paused}; },
  toast() {}, refreshAll() {},
};
vm.runInNewContext(source + '\nthis.renderAIControl=renderAIControl;', scope);

(async () => {
  scope.renderAIControl(false);
  assert.equal(buttons['ai-toggle'].textContent, 'Tạm dừng AI');
  assert.equal(buttons['ai-toggle-investigation'].disabled, false);
  await buttons['ai-toggle'].onclick();
  assert.equal(requests[0].url, '/api/ai-control');
  assert.equal(JSON.parse(requests[0].options.body).paused, true);
  assert.equal(buttons['ai-toggle'].textContent, 'Bật điều tra AI');
  assert.equal(buttons['ai-toggle-investigation']['aria-pressed'], 'true');
  await buttons['ai-toggle-investigation'].onclick();
  assert.equal(JSON.parse(requests[1].options.body).paused, false);
  assert.equal(buttons['ai-toggle'].textContent, 'Tạm dừng AI');
  console.log('AI pause controls passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
