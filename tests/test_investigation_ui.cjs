// Small functional render checks using the shipped inline UI, without a browser or backend.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync(require('node:path').join(__dirname,'../web/index.html'),'utf8');
assert.doesNotMatch(html, /#analyst-queue\s*\{\s*display:\s*none\s*!important;/);
assert.match(html, /if\(name==='investigations'\)loadAnalystQueue\(\)/);
assert.match(html, /\['overview','Tổng quan'\]/);
assert.match(html, /assessmentPanel\(data,linkedAlert\)\+responsePanel\(data,linkedAlert\)/);
assert.match(html, /a\.ai_group\?\.representative_alert_id/);
assert.match(html, /\/investigation'/);
assert.match(html, /101200.*101201.*101202/);
assert.match(html, /search_account_events:'Tìm cảnh báo tạo tài khoản hoặc thay đổi nhóm Linux/);
assert.match(html, /data-view="investigations"[^>]*>.*Điều tra &amp; phản ứng/);
assert.doesNotMatch(html, /data-view="response"/);
assert.match(html, /if\(name==='response'\)name='investigations'/);
assert.match(html, /id="investigation-back"[^>]*>← Trở lại cảnh báo/);
assert.match(html, /history\.replaceState\(\{view:initialView/);
assert.match(html, /addEventListener\('popstate'/);
assert.match(html, /history\.replaceState\(history\.state,'',url\)/);
assert.match(html, /\$\('investigation-back'\)\.hidden=!a/);
assert.match(html, /\$\('investigation-back'\)\.onclick=\(\)=>\{const id=selectedInvestigation;showView\('alerts'\);if\(id\)openAlert\(id\)\}/);
const navigationSource=html.slice(html.indexOf('    function showView('),html.indexOf("    document.querySelectorAll('[data-view]').forEach(b=>b.onclick"));
let activeView='dashboard';const navigationPushes=[];
const navButtons=['dashboard','alerts','logs','investigations','analyst-chat','intel'].map(view=>({dataset:{view},classList:{toggle(_name,active){if(active)activeView=view}}}));
const navigationElements=new Map();
const navigationScope={views:navButtons.map(button=>button.dataset.view),labels:{alerts:'Cảnh báo',investigations:'Điều tra'},
  pageDescriptions:{alerts:'',investigations:''},location:{href:'http://localhost:8100/'},URL,
  history:{pushState(state,_title,url){navigationPushes.push([state.view,String(url)])}},
  document:{body:{classList:{toggle(){}}},querySelector:()=>({dataset:{view:activeView}}),querySelectorAll:()=>navButtons},
  $:id=>{if(!navigationElements.has(id))navigationElements.set(id,{classList:{toggle(){},remove(){}},textContent:''});return navigationElements.get(id)},
  logsWorkspace:{onView(){}},loadAnalystQueue(){},scrollTo(){},setTimeout(){}};
vm.runInNewContext(navigationSource+'\nthis.navigate=showView;',navigationScope);
navigationScope.navigate('alerts');navigationScope.navigate('investigations');navigationScope.navigate('alerts',false);
assert.deepEqual(navigationPushes.map(([view])=>view),['alerts','investigations']);
assert.equal(activeView,'alerts');
const popstateSource=html.match(/    addEventListener\('popstate'.*?;\r?\n/)[0];
let popstateHandler;
navigationScope.addEventListener=(_name,handler)=>{popstateHandler=handler};
navigationScope.URLSearchParams=URLSearchParams;
vm.runInNewContext(popstateSource,navigationScope);
navigationScope.navigate('investigations');
popstateHandler({state:{view:'alerts'}});
assert.equal(activeView,'alerts');
assert.equal(navigationPushes.length,3);
const backSource=html.match(/    \$\('investigation-back'\)\.onclick=.*?;\r?\n/)[0];
const openedAlerts=[];
const backButton={};
const backScope={selectedInvestigation:'alert-1',showView:view=>navigationScope.navigate(view),openAlert:id=>openedAlerts.push(id),$:()=>backButton};
vm.runInNewContext(backSource,backScope);
backScope.selectedInvestigation='alert-2';
backButton.onclick();
assert.deepEqual(openedAlerts,['alert-2']);
assert.match(html, /\['queued','running'\]\.includes\(a\.ai_status\)/);
assert.match(html, /\['completed','failed'\]\.includes\(a\.ai_status\)\?'Điều tra lại'/);
const source = html.slice(html.indexOf('    const aiStages='),html.indexOf('    function renderProgress(){'));
const scope = {
  icon:()=>'',esc:s=>String(s).replaceAll('<','&lt;').replaceAll('>','&gt;'),
  date:String,localTime:String,state:s=>String(s),duration:s=>String(s),reviewReason:s=>s
};
scope.sev=()=> 'medium';scope.severityName=()=> 'Trung bình';scope.logSource=()=> 'Zeek';
const statusSource=html.slice(html.indexOf('    function badge('),html.indexOf('    function backend('));
const rowSource=html.slice(html.indexOf('    function row('),html.indexOf('    function empty('));
const alertSummarySource=html.slice(html.indexOf('    function alertSummary('),html.indexOf('    async function goInvestigation('));
vm.runInNewContext(statusSource+'\n'+rowSource+'\n'+alertSummarySource+'\nthis.alertRow=row;this.alertSummary=alertSummary;',scope);
const groupedAlert={id:'alert-2',rule:{id:'100181',description:'DNS'},agent:{name:'victim'},
  ai_status:'skipped',ai_group:{representative_alert_id:'alert-1',policy:'active_similarity',match:'Cùng domain'},ai_skip_reason:'Đã gộp'};
assert.match(scope.alertRow(groupedAlert),/Đã gộp/);
assert.match(scope.alertSummary(groupedAlert),/Xem cuộc điều tra liên quan/);
assert.match(scope.alertSummary(groupedAlert),/Cùng domain/);
const exactGroupedAlert={...groupedAlert,ai_group:{...groupedAlert.ai_group,policy:'exact_source_event',
  match:'Cùng Agent, thời điểm, nguồn log và nội dung log gốc.'}};
assert.match(scope.alertSummary(exactGroupedAlert),/Cùng Agent, thời điểm, nguồn log và nội dung log gốc/);
assert.match(scope.alertRow({...groupedAlert,ai_group:null}),/Đã bỏ qua/);
vm.runInNewContext(source+'\nthis.render=progressHTML;',scope);
let out=scope.render({ai_status:'running',ai_progress:{model:'qwen3:8b'},investigation:{
  incident_id:'INV-test',node:'collecting',model_calls:2,tool_calls:3,started_at:Date.now()/1000-5,
  limits:{model_calls:4,tool_calls:6,seconds:900}}});
assert.match(out,/Đang thu thập bằng chứng/);
assert.match(out,/Lượt gọi mô hình: 2\/4/);
assert.match(out,/Lượt gọi công cụ: 3\/6/);
assert.doesNotMatch(out,/Stage \d\/6|%/);
out=scope.render({ai_status:'failed',ai_progress:{},investigation:{incident_id:'INV-test',
  node:'failed',error:'<untrusted log text>',started_at:Date.now()/1000,stop_reason:'invalid_report'}});
assert.match(out,/&lt;untrusted log text&gt;/);
assert.match(out,/invalid_report/);
assert.equal(scope.render({ai_status:'skipped'}),'');
assert.match(scope.render({ai_status:'running',ai_progress:{step:2,stage:'investigating'}}),/Giai đoạn 2\/6/);
console.log('Investigation UI render checks passed.');
const summarySource=html.slice(html.indexOf('    function shortAssessment('),html.indexOf('    function analystPanel('));
scope.verdictName=x=>x;
scope.ACTION_LABEL={increase_monitoring:'Tăng giám sát'};
vm.runInNewContext(summarySource+'\nthis.assessment=assessmentPanel;this.shortSummary=shortAssessment;this.assessmentText=assessmentText;this.recordedEvidence=recordedEvidence;this.groundedSuggestions=groundedSuggestions;',scope);
const longId='WAZUH-'+'a'.repeat(64),ref='EV-'+'b'.repeat(24);
assert.equal(scope.shortSummary(`Cảnh báo ${longId} từ 192.168.1.2. Câu thứ hai. Câu thứ ba.`), 'Cảnh báo từ 192.168.1.2. Câu thứ hai.');
const report={verdict:'inconclusive',confidence:null,reasoning:`Cảnh báo ${longId}. Chưa đủ bằng chứng. Câu thứ ba.`,
  findings:[{statement:'Quan sát <đáng ngờ>',evidence_ids:[ref]}],
  hypotheses:[{statement:'Giả thuyết DNS',status:'open',supporting:[ref],refuting:[],question:'Domain nào được truy vấn?'}],
  unknowns:['Chưa rõ câu trả lời DNS'],recommendations:['Xem thêm log DNS'],
  tool_outcomes:[{tool:'search_zeek_dns',status:'empty'},{tool:'summarize_dns_activity',status:'ok',aggregate_evidence_id:ref,dns_summary:{matched_records:12,unique_queries:8,scope:{window_seconds:60}}}]};
const card=scope.assessment({report,summary:{},status:'completed',finding_evidence:[{evidence_id:ref,event_time:'2026-11-17T01:00:00Z',data:{dns:{query:'example.test'}}}]},{});
assert.match(card,/Độ tin cậy: Chưa có/);
assert.doesNotMatch(card,/Phát hiện chính/);
assert.doesNotMatch(card,/Quan sát &lt;đáng ngờ&gt;/);
assert.match(card,/search_zeek_dns: không có kết quả/);
assert.match(card,/Domain nào được truy vấn\?/);
assert.match(card,/Gợi ý bước phản ứng/);
assert.match(card,/Chưa có gợi ý gắn nguồn/);
assert.match(card,/12 bản ghi đã lưu · 8 tên query khác nhau/);
assert.match(card,/Phạm vi thời gian chưa được ghi/);
assert.doesNotMatch(card,/Câu thứ ba/);
assert.doesNotMatch(card,new RegExp(longId));
const skippedTool=scope.assessment({report:{...report,tool_outcomes:[{tool:'search_zeek_dns',status:'skipped',error:'tool_already_used'}]},summary:{}},{});
assert.match(skippedTool,/search_zeek_dns: đã bỏ qua vì tool đã được sử dụng/);
assert.doesNotMatch(skippedTool,/tool_already_used/);
const withoutOutcomes=scope.assessment({report:{...report,hypotheses:[],tool_outcomes:[]},summary:{}},{});
assert.match(withoutOutcomes,/Không có trạng thái công cụ được ghi/);
assert.match(scope.assessment({status:'running',summary:{}},{}),/AI đang thu thập và phân tích bằng chứng/);
assert.match(scope.assessment({status:'failed',summary:{error:'<lỗi>'}},{}),/&lt;lỗi&gt;/);
assert.match(scope.assessmentText('**Kiểm tra** `dns`\n<script>alert(1)</script>'),/<strong>Kiểm tra<\/strong> <code>dns<\/code><br>&lt;script&gt;/);
assert.doesNotMatch(scope.assessmentText('<img src=x onerror=alert(1)>'),/<img/);
const metrics=scope.assessment({status:'completed',summary:{},report:{verdict:'inconclusive',tool_outcomes:[
  {tool:'summarize_dns_activity',status:'ok',dns_summary:{matched_records:25,unique_queries:22,query_types:{A:10,NULL:7},scope:{domain:'<lab.test>',agent_id:'001',since:'03:19Z',until:'03:49Z'}}},
  {tool:'search_zeek_connections',status:'truncated',count:10,total_matched:68},
  {tool:'search_process_events',status:'empty'},
  {tool:'search_auth_events',status:'truncated',count:1,total_matched:12,authentication_summary:{scope:{since:'01:00Z',until:'01:30Z'},groups:[{username:'victim',source_ip:'192.0.2.7',failure_count:11,success_count:0}]}}
]}},{zeek_data:{qtype_name:'NULL'}});
assert.match(metrics,/25 bản ghi đã lưu · 22 tên query khác nhau · NULL: 7, A: 10/);
assert.match(metrics,/&lt;lab\.test&gt;/);assert.doesNotMatch(metrics,/<lab\.test>/);
assert.match(metrics,/03:19Z → 03:49Z/);
assert.match(metrics,/search_zeek_connections: đã trả 10\/68 bản ghi phù hợp/);
assert.match(metrics,/victim · 192\.0\.2\.7: 11 thất bại · 0 thành công/);
assert.match(metrics,/01:00Z → 01:30Z/);
assert.doesNotMatch(scope.recordedEvidence([{tool:'summarize_dns_activity',status:'error'}],{}),/0 bản ghi/);
const grounded={status:'available',incident_id:'INV-1',knowledge_guidance:{playbook_id:'PB-DNS',title:'DNS',source:'dns.txt',passages:[{id:'G1',section:'RESPONSE',text:'Monitor DNS.'}]},
  actions:[{status:'proposed',action:'increase_monitoring',target:'001',reason:'Theo dõi DNS.',guidance_ids:['G1']}]};
const groundedCard=scope.assessment({report:{...report,incident_id:'INV-1'},summary:{},status:'completed'},{grounded_response:grounded});
assert.match(groundedCard,/PB-DNS/);assert.match(groundedCard,/Tăng giám sát<\/b> · 001/);assert.match(groundedCard,/Monitor DNS\./);
assert.doesNotMatch(scope.assessment({report:{...report,incident_id:'INV-other'},summary:{}},{grounded_response:grounded}),/Monitor DNS\./);
const noActionsCard=scope.assessment({report:{...report,incident_id:'INV-1'},summary:{},status:'completed'},
  {grounded_response:{status:'no_actions',incident_id:'INV-1',actions:[]}});
assert.match(noActionsCard,/Playbook đã được tìm thấy/);
assert.match(noActionsCard,/không tự tạo hành động/);
assert.doesNotMatch(scope.assessment({report,summary:{}},{}),/Xem thêm log DNS/);
console.log('Investigation summary card checks passed.');
const panels=html.slice(html.indexOf('    function analystPanel('),html.indexOf('    function activityHTML('));
vm.runInNewContext(panels+'\nthis.review=analystPanel;this.hypotheses=hypothesisPanel;',scope);
assert.match(scope.review({summary:{needs_analyst:true,review_reasons:['Need authorization']},report:{analyst_tasks:['Verify owner']},status:'completed'}),/Lưu đánh giá/);
assert.match(scope.review({summary:{needs_analyst:true,review_reasons:['System check']},report:{analyst_tasks:['Kiểm tra cổng 80','Kiểm tra cổng 53']},status:'completed'}),/Kiểm tra cổng 80.*Kiểm tra cổng 53/);
assert.doesNotMatch(scope.review({summary:{needs_analyst:true},report:{analyst_tasks:[]},status:'completed'}),/Nội dung AI đề xuất xác minh/);
assert.match(scope.review({summary:{analyst_review:{decision:'benign',notes:'<untrusted>',created:1}}}),/&lt;untrusted&gt;/);
assert.match(scope.hypotheses({summary:{hypotheses:[{id:'H-001',statement:'Check access',status:'open',supporting:['EV-test'],refuting:[],question:'<verify>'}]}}),/EV-test/);
console.log('Analyst and hypothesis UI render checks passed.');
const responseSource=html.slice(html.indexOf('    function renderResponse('),html.indexOf('    async function loadKnowledge('));
const elements={'response-history':{innerHTML:''}};
scope.alerts=[{id:'alert-1',rule:{description:'SSH brute force'},agent:{name:'host-1'},timestamp:1,
  investigation_report:{verdict:'malicious'},
  playbook_proposal:{status:'matched',playbook_id:'PB-SSH-001',playbook_name:'SSH Brute Force Response',
    playbook_source:'ssh_bruteforce.txt',playbook_text:'PLAYBOOK ID: PB-SSH-001\n<script>untrusted</script>'}}];
scope.responseHistory=[];scope.$=id=>elements[id];scope.goInvestigation=()=>{};
vm.runInNewContext(responseSource+'\nthis.renderResponse=renderResponse;this.responsePlans=responsePlans;this.planHTML=planHTML;this.loadPlan=loadPlan;',scope);
scope.renderResponse([{action:'block_domain',status:'simulated',timestamp:1,name:'<script>x</script>',
  guidance_ids:['G1'],knowledge_guidance:{playbook_id:'PB-DNS'}}]);
assert.match(elements['response-history'].innerHTML,/Chặn domain/);
assert.match(elements['response-history'].innerHTML,/mô phỏng/);
assert.match(elements['response-history'].innerHTML,/PB-DNS · G1/);
const responsePanelSource=html.slice(html.indexOf('    function responsePanel('),html.indexOf('    function analystPanel('));
vm.runInNewContext(responsePanelSource+'\nthis.responsePanel=responsePanel;',scope);
const responseCard=scope.responsePanel({status:'completed',report:scope.alerts[0].investigation_report},scope.alerts[0]);
assert.match(responseCard,/Kế hoạch phản ứng/);
assert.match(responseCard,/PB-SSH-001|SSH Brute Force Response/);
assert.match(responseCard,/&lt;script&gt;untrusted&lt;\/script&gt;/);
assert.match(responseCard,/ssh_bruteforce\.txt/);
assert.match(responseCard,/AI lập kế hoạch phản ứng/);
assert.match(responseCard,/chỉ thực thi mô phỏng/);
assert.equal(scope.responsePanel({status:'running'},{}),'');
assert.doesNotMatch(scope.responsePanel({status:'failed',report:{}},scope.alerts[0]),/data-plan-create/);
console.log('Integrated playbook and response UI rendering checks passed.');
const evidenceSource=html.slice(html.indexOf('    function localizeSyslogLog('),html.indexOf('    function investigate('));
scope.date=value=>`LOCAL(${value})`;
scope.localTime=value=>`LOCAL(${value})`;
const eventTime='2026-11-20T08:00:00Z',collectedAt='2026-11-20T08:01:00Z';
const rawLog='Nov 20 08:00:00 victim sshd[4752]: pam_unix(sshd:auth): authentication failure';
const originalTimezone=process.env.TZ;
process.env.TZ='Asia/Saigon';
try{
  vm.runInNewContext(evidenceSource+'\nthis.renderEvidence=evidenceHTML;',scope);
  const evidence=scope.renderEvidence({event_time:eventTime,collected_at:collectedAt,evidence_id:'EV-time',
    source_record_id:'source-1',source:'wazuh',evidence_type:'observed',
    data:{event_time:eventTime,full_log:rawLog,rule:{description:'Failed login'}}});
  assert.match(evidence,/LOCAL\(2026-11-20T08:00:00Z\)/);
  assert.match(evidence,/LOCAL\(2026-11-20T08:01:00Z\)/);
  assert.match(evidence,/Nov 20 15:00:00 victim sshd/);
  assert.match(evidence,/Log nguồn nguyên bản \(UTC\)/);
  assert.match(evidence,/Nov 20 08:00:00 victim sshd/);
  assert.match(evidence,/"event_time": "2026-11-20T08:00:00Z"/);
  assert.match(evidence,/"full_log": "Nov 20 08:00:00 victim/);
  const unmatched=scope.renderEvidence({event_time:'2026-11-20T08:10:00Z',evidence_id:'EV-unmatched',
    data:{full_log:rawLog,rule:{description:'Failed login'}}});
  assert.match(unmatched,/Nov 20 08:00:00 victim sshd/);
  assert.doesNotMatch(unmatched,/Log nguồn nguyên bản \(UTC\)/);
}finally{
  if(originalTimezone===undefined)delete process.env.TZ;else process.env.TZ=originalTimezone;
}
const lookupSource=html.slice(html.indexOf('    function chatLookupLabel('),html.indexOf('    function renderChat('));
vm.runInNewContext(lookupSource+'\nthis.lookupLabel=chatLookupLabel;',scope);
assert.match(scope.lookupLabel({ok:true,name:'search_alerts',scope:{since:eventTime,until:collectedAt}}),/từ LOCAL\(2026-11-20T08:00:00Z\)/);
const overviewSource=html.slice(html.indexOf('    function recordedEvidence('),html.indexOf('    function groundedSuggestions('));
vm.runInNewContext(overviewSource+'\nthis.recordedEvidence=recordedEvidence;',scope);
const overview=scope.recordedEvidence([{tool:'summarize_dns_activity',status:'ok',
  dns_summary:{scope:{since:eventTime,until:collectedAt},matched_records:1}}],{zeek_data:{}});
assert.match(overview,/LOCAL\(2026-11-20T08:00:00Z\).*LOCAL\(2026-11-20T08:01:00Z\)/);
const activitySource=html.slice(html.indexOf('    function activityHTML('),html.indexOf('    function evidenceHTML('));
scope.state=value=>value;scope.duration=value=>String(value);scope.toolPurposes={};
vm.runInNewContext(activitySource+'\nthis.activity=activityHTML;',scope);
const activity=scope.activity({kind:'tool',name:'search_auth_events',state:'completed',
  started:1,finished:2,query:{since:eventTime,until:collectedAt}},0);
assert.match(activity,/From LOCAL\(2026-11-20T08:00:00Z\).*To LOCAL\(2026-11-20T08:01:00Z\)/);
console.log('Investigation timestamps use local display; stored evidence JSON remains UTC.');
scope.responsePlans['alert-1']={id:'RP-1',status:'proposed',verdict:'malicious',verdict_source:'model_report',summary:'Plan <b>x</b>',note:'n',
  knowledge_guidance:{playbook_id:'PB-DNS',title:'DNS response',source:'dns.txt',sha256:'abc',passages:[{id:'G1',section:'RESPONSE',text:'Filter the domain <script>x</script>'}]},
  actions:[{id:'A1',action:'block_domain',target:'tunnel.lab.local',reason:'r',evidence_ids:['EV-1'],guidance_ids:['G1'],phase:'containment',impact:'low',reversible:true,mitigation:'M1037',command:'c',rollback:'rb',status:'proposed',policy_reasons:[]},
           {id:'A2',action:'kill_process',target:'<img src=x>',reason:'r',evidence_ids:[],guidance_ids:['G1'],phase:'eradication',impact:'high',reversible:false,mitigation:null,command:'c',rollback:'rb',status:'rejected',policy_reasons:['Mục tiêu không xuất hiện']}]};
const planOut=scope.planHTML('alert-1');
assert.match(planOut,/Chặn domain/);assert.match(planOut,/tunnel\.lab\.local/);
assert.match(planOut,/&lt;img src=x&gt;/);assert.doesNotMatch(planOut,/<img src=x>/);
assert.match(planOut,/data-plan-action="A2" +disabled/);assert.match(planOut,/Cổng chính sách: Mục tiêu không xuất hiện/);
assert.match(planOut,/PB-DNS/);assert.match(planOut,/G1 · RESPONSE/);assert.match(planOut,/&lt;script&gt;x&lt;\/script&gt;/);
assert.match(planOut,/Thực thi hành động đã duyệt \(mô phỏng\)/);
scope.responsePlans['alert-1'].status='executed';
assert.doesNotMatch(scope.planHTML('alert-1'),/data-plan-exec/);
scope.responsePlans['legacy']={...scope.responsePlans['alert-1'],status:'proposed',knowledge_guidance:null};
assert.match(scope.planHTML('legacy'),/Kế hoạch cũ chưa có nguồn hướng dẫn/);
assert.doesNotMatch(scope.planHTML('legacy'),/data-plan-exec/);
console.log('Response plan UI checks passed.');

// A missing plan is different from an unavailable API: never offer to replace
// a saved plan while the lookup is still running or has failed.
(async()=>{
  const planBox={innerHTML:'',querySelectorAll:()=>[]};
  scope.CSS={escape:s=>s};scope.document={querySelector:()=>planBox};
  let finish;
  scope.api=()=>new Promise(resolve=>{finish=resolve});
  const pending=scope.loadPlan('alert-load');
  assert.match(planBox.innerHTML,/Đang tải kế hoạch/);
  assert.doesNotMatch(planBox.innerHTML,/data-plan-create/);
  finish({status:'proposed',actions:[],summary:'Kế hoạch đã lưu'});
  await pending;
  assert.match(planBox.innerHTML,/Kế hoạch đã lưu/);
  scope.api=async()=>{const e=Error('Không kết nối được');e.status=503;throw e};
  await scope.loadPlan('alert-error');
  assert.match(planBox.innerHTML,/Không thể tải kế hoạch/);
  assert.match(planBox.innerHTML,/data-plan-retry/);
  assert.doesNotMatch(planBox.innerHTML,/data-plan-create/);
  scope.api=async()=>{const e=Error('Chưa có kế hoạch');e.status=404;throw e};
  await scope.loadPlan('alert-new');
  assert.match(planBox.innerHTML,/AI lập kế hoạch phản ứng/);
  console.log('Response plan loading checks passed.');
})().catch(e=>{console.error(e);process.exitCode=1});
