// Small functional render checks using the shipped inline UI, without a browser or backend.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync(require('node:path').join(__dirname,'../web/index.html'),'utf8');
const source = html.slice(html.indexOf('    const aiStages='),html.indexOf('    function renderProgress(){'));
const scope = {
  icon:()=>'',esc:s=>String(s).replaceAll('<','&lt;').replaceAll('>','&gt;'),
  date:String,state:s=>String(s),duration:s=>String(s)
};
vm.runInNewContext(source+'\nthis.render=progressHTML;',scope);
let out=scope.render({ai_status:'running',ai_progress:{model:'qwen3:8b'},investigation:{
  incident_id:'INV-test',node:'collecting',model_calls:2,tool_calls:3,started_at:Date.now()/1000-5,
  limits:{model_calls:4,tool_calls:6,seconds:900}}});
assert.match(out,/Collecting local evidence/);
assert.match(out,/Model calls: 2\/4/);
assert.match(out,/Tool calls: 3\/6/);
assert.doesNotMatch(out,/Stage \d\/6|%/);
out=scope.render({ai_status:'failed',ai_progress:{},investigation:{incident_id:'INV-test',
  node:'failed',error:'<untrusted log text>',started_at:Date.now()/1000,stop_reason:'invalid_report'}});
assert.match(out,/&lt;untrusted log text&gt;/);
assert.match(out,/invalid_report/);
assert.equal(scope.render({ai_status:'skipped'}),'');
assert.match(scope.render({ai_status:'running',ai_progress:{step:2,stage:'investigating'}}),/Stage 2\/6/);
console.log('Investigation UI render checks passed.');
const panels=html.slice(html.indexOf('    function analystPanel('),html.indexOf('    function activityHTML('));
vm.runInNewContext(panels+'\nthis.review=analystPanel;this.hypotheses=hypothesisPanel;',scope);
assert.match(scope.review({summary:{needs_analyst:true,review_reasons:['Need authorization']},report:{analyst_tasks:['Verify owner']},status:'completed'}),/Save analyst assessment/);
assert.match(scope.review({summary:{analyst_review:{decision:'benign',notes:'<untrusted>',created:1}}}),/&lt;untrusted&gt;/);
assert.match(scope.hypotheses({summary:{hypotheses:[{id:'H-001',statement:'Check access',status:'open',supporting:['EV-test'],refuting:[],question:'<verify>'}]}}),/EV-test/);
console.log('Analyst and hypothesis UI render checks passed.');
const responseSource=html.slice(html.indexOf('    function renderResponse('),html.indexOf('    async function loadKnowledge('));
const elements={'response-proposals':{innerHTML:'',querySelectorAll:()=>[]},'response-history':{innerHTML:''}};
scope.alerts=[{id:'alert-1',rule:{description:'SSH brute force'},agent:{name:'host-1'},timestamp:1,
  playbook_proposal:{status:'matched',playbook_id:'PB-SSH-001',playbook_name:'SSH Brute Force Response',
    playbook_source:'ssh_bruteforce.txt',playbook_text:'PLAYBOOK ID: PB-SSH-001\n<script>untrusted</script>'}}];
scope.responseHistory=[];scope.$=id=>elements[id];scope.goInvestigation=()=>{};
vm.runInNewContext(responseSource+'\nthis.renderResponse=renderResponse;',scope);
scope.renderResponse([]);
assert.match(elements['response-proposals'].innerHTML,/PB-SSH-001/);
assert.match(elements['response-proposals'].innerHTML,/&lt;script&gt;untrusted&lt;\/script&gt;/);
assert.match(elements['response-proposals'].innerHTML,/ssh_bruteforce\.txt/);
console.log('Matched playbook UI rendering checks passed.');
