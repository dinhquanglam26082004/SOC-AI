const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'web', 'index.html'), 'utf8');
assert.match(html,/\.evidence-highlights \.evidence-grid\{grid-template-columns:repeat\(3,minmax\(0,1fr\)\)/);
const source = html.slice(html.indexOf('    function localizeSyslogLog('), html.indexOf('    function investigate('));
assert.ok(source.includes('function evidenceHTML('));
const scope = {
  esc: value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;'),
  date: value => `LOCAL(${value})`,
};
vm.runInNewContext(source + '\nthis.renderEvidence=evidenceHTML;', scope);
const highlights = card => (card.match(/<dl class="evidence-grid">(.*?)<\/dl>/)?.[1]||'');

const moduleCard = scope.renderEvidence({
  evidence_id: 'EV-module', source_record_id: 'wazuh-module', evidence_type: 'observed',
  event_time: '2026-11-25T15:02:22Z', data: {
    rule: { id: '100200', description: 'Kernel module load' },
    agent: { name: 'ubuntu' }, full_log: 'type=KERN_MODULE name=diamorphine',
    audit: { command: 'insmod', exe: '/usr/bin/kmod', syscall: '313' },
    kernel_module_activity: { module_name: 'diamorphine', command: 'insmod', success: 'yes',
      exit: '0', audit_id: '912', syscall: '313' },
  },
});
assert.match(moduleCard, /Sự kiện quan sát được/);
assert.match(moduleCard, /Nạp kernel module/);
assert.match(moduleCard, /<span class="evidence-kind">Kernel module<\/span>/);
assert.match(moduleCard, /<strong>Nạp kernel module<\/strong><small class="evidence-role">Sự kiện quan sát được<\/small>/);
assert.match(moduleCard, /Tên module<\/dt><dd>diamorphine/);
assert.match(moduleCard, /Kết quả<\/dt><dd class="evidence-result-ok">Thành công/);
assert.match(moduleCard, /Lệnh thực thi<\/dt><dd>insmod/);
assert.match(moduleCard, /Exit code<\/dt><dd>0/);
assert.doesNotMatch((moduleCard.match(/<div class="evidence-highlights">.*?<\/dl>/)||[])[0]||'',/<dt>Lệnh<\/dt>/);
assert.match(moduleCard, /Auditd ghi nhận module diamorphine được nạp thành công/);
assert.ok(moduleCard.indexOf('evidence-lead')<moduleCard.indexOf('evidence-highlights'));
assert.ok(moduleCard.indexOf('evidence-highlights')<moduleCard.indexOf('evidence-meta-grid'));
assert.ok(moduleCard.indexOf('evidence-meta-grid')<moduleCard.indexOf('<details>'));
assert.match(moduleCard, /<details><summary>Log đã lưu/);
assert.match(moduleCard, /EV-module/);
assert.match(moduleCard, /wazuh-module/);
assert.equal((moduleCard.match(/<details>/g)||[]).length,3);
assert.match(moduleCard, /Dữ liệu Evidence \(JSON\)/);
const failedModule = scope.renderEvidence({ evidence_id: 'EV-unload', evidence_type: 'observed',
  data: { rule: { id: '100205' }, kernel_module_activity: { success: 'no', exit: '-1' } } });
assert.match(failedModule, /Thao tác gỡ kernel module/);
assert.match(failedModule, /Log ghi nhận thao tác gỡ module thất bại/);
assert.match(failedModule, /Kết quả<\/dt><dd class="evidence-result-fail">Thất bại/);
assert.doesNotMatch(failedModule, /Tên module<\/dt><dd>diamorphine/);
const unload = scope.renderEvidence({evidence_id:'EV-unload-success',source_record_id:'WAZUH-source',
  evidence_type:'observed',tool:'search_rootkit_evidence',event_time:'2026-11-25T15:05:26Z',data:{
    rule:{id:'100205'},agent:{name:'ubuntu-soc-server'},audit:{id:'42',command:'rmmod',exe:'/usr/bin/kmod'},
    kernel_module_activity:{module_name:'example_module',command:'rmmod',success:'yes',exit:'0',
      syscall:'176',syscall_name:'delete_module',audit_id:'42'}}});
assert.match(unload,/<strong>Gỡ kernel module<\/strong>/);
assert.match(unload,/Auditd ghi nhận module example_module được gỡ thành công/);
assert.match(unload,/Tên module<\/dt><dd>example_module/);
assert.match(unload,/Thao tác<\/dt><dd>Gỡ module/);
assert.match(unload,/Lệnh thực thi<\/dt><dd>rmmod/);
assert.match(unload,/Syscall<\/dt><dd>delete_module \(176\)/);
assert.match(unload,/Exit code<\/dt><dd>0/);
assert.doesNotMatch((unload.match(/<div class="evidence-highlights">.*?<\/dl>/)||[])[0]||'',/<dt>Lệnh<\/dt>/);
assert.match(unload,/Gỡ module thành công không đồng nghĩa hệ thống đã an toàn/);
assert.match(unload,/<dl class="evidence-meta-grid">.*Thời gian sự kiện.*Agent.*Rule.*Công cụ.*<\/dl>/);
assert.equal((unload.match(/<details>/g)||[]).length,3);

const snapshotCard = scope.renderEvidence({ evidence_id: 'EV-snapshot', evidence_type: 'observed',
  event_time: '2026-11-25T15:04:59Z', data: {
    rule: { id: '100206', description: 'Endpoint observation' },
    rootkit_snapshot: { producer: 'soc-ai-rootkit-snapshot-v1', target_pid: 6780,
      finding: 'visible_process', boot_id: 'boot-123', observed_at: '2026-11-25T15:05:00Z',
      interpretation: 'Local kernel-dependent observation.',
      suspects: [{ pid: 6780, proc_visible: true, ps_visible: true,
        recheck_proc_visible: true, recheck_ps_visible: true }] },
  },
});
assert.match(snapshotCard, /Quan sát endpoint/);
assert.match(snapshotCard, /PID mục tiêu<\/dt><dd>6780/);
assert.match(snapshotCard, /Thời điểm quan sát<\/dt><dd>LOCAL\(2026-11-25T15:05:00Z\)/);
assert.match(snapshotCard, /chưa được đối chiếu độc lập/i);
assert.match(snapshotCard, /không tự xác nhận rootkit/);
assert.match(snapshotCard, /Kết quả quan sát<\/dt><dd>Tiến trình hiển thị/);
assert.match(snapshotCard, /\/proc lần 1<\/dt><dd>Có/);
assert.equal((snapshotCard.match(/<details>/g)||[]).length,3);
const discrepancy = scope.renderEvidence({evidence_type:'observed',data:{rootkit_snapshot:{
  producer:'soc-ai-rootkit-snapshot-v1',target_pid:6780,finding:'stable_process_visibility_discrepancy',
  suspects:[{pid:6780,proc_visible:false,recheck_proc_visible:false}]}}});
assert.match(discrepancy,/\/proc lần 1<\/dt><dd>Không/);

const detectorCard = scope.renderEvidence({ evidence_id: 'EV-rootcheck', evidence_type: 'observed',
  data: { rule: { id: '521', description: 'Hidden process warning' },rootkit_evidence_class:'detection',full_log: "Process '6780' hidden from /proc" } });
assert.match(detectorCard, /Cảnh báo tiến trình có thể bị ẩn/);
assert.match(detectorCard, /PID được cảnh báo<\/dt><dd>6780/);
assert.match(detectorCard, /Rootcheck cảnh báo PID 6780/);
const unrelated = scope.renderEvidence({evidence_type:'trigger',data:{rule:{id:'99999'},
  full_log:"Process '6780' hidden from /proc"}});
assert.doesNotMatch(unrelated,/PID được cảnh báo<\/dt>/);
const taintCard = scope.renderEvidence({ evidence_id: 'EV-taint', evidence_type: 'observed',
  data: { rule: { id: '100201', description: 'Kernel taint observation' },
    full_log: 'kernel_taint current=12288 baseline=12288 changed=no',
    rootkit_telemetry_summary: { observation_count: 5, source_record_count: 6,
      first_event_time:'2026-11-25T15:57:29Z',last_event_time:'2026-11-25T16:26:30Z' } } });
assert.match(taintCard, /Trạng thái kernel/);
assert.match(taintCard,/Baseline<\/dt><dd>12288/);
assert.match(taintCard,/Hiện tại<\/dt><dd>12288/);
assert.match(taintCard,/Thay đổi<\/dt><dd>Không/);
assert.match(taintCard,/Out-of-tree module<\/dt><dd>Có/);
assert.match(taintCard,/Unsigned module<\/dt><dd>Có/);
assert.match(taintCard,/Kernel oops<\/dt><dd>Không/);
assert.doesNotMatch(highlights(taintCard),/Số lần quan sát|Số bản ghi nguồn/);
assert.match(taintCard,/5 lần quan sát · 6 bản ghi nguồn · \d{1,2}:\d{2}:\d{2} – \d{1,2}:\d{2}:\d{2}/);
assert.match(taintCard, /Log ghi nhận kernel taint: baseline=12288, current=12288, changed=no/);
const partialTaint=scope.renderEvidence({evidence_type:'observed',data:{rule:{id:'100201'},
  full_log:'kernel_taint current=0 changed=no',rootkit_telemetry_summary:{observation_count:0}}});
assert.match(partialTaint,/Hiện tại<\/dt><dd>0/);
assert.match(partialTaint,/Thay đổi<\/dt><dd>Không/);
assert.match(partialTaint,/Out-of-tree module<\/dt><dd>Không/);
assert.match(partialTaint,/0 lần quan sát/);
assert.doesNotMatch(partialTaint,/<dt>Baseline<\/dt>/);
const oopsTaint=scope.renderEvidence({evidence_type:'observed',data:{rule:{id:'100201'},
  full_log:'kernel_taint current=128 baseline=0 changed=yes'}});
assert.match(oopsTaint,/Out-of-tree module<\/dt><dd>Không/);
assert.match(oopsTaint,/Unsigned module<\/dt><dd>Không/);
assert.match(oopsTaint,/Kernel oops<\/dt><dd>Có/);
assert.match(oopsTaint,/Thay đổi<\/dt><dd>Có/);
const mixedTaintLog=scope.renderEvidence({evidence_type:'observed',data:{rule:{id:'100201'},
  full_log:'other current=99 baseline=99\nkernel_taint current=12288 baseline=12288 changed=no'}});
assert.match(mixedTaintLog,/Hiện tại<\/dt><dd>12288/);
assert.doesNotMatch(mixedTaintLog,/Hiện tại<\/dt><dd>99/);
const emptyModuleTaint = scope.renderEvidence({ evidence_type:'observed', data:{rule:{id:'100201'},
  kernel_module_activity:{},rootkit_telemetry_summary:{kind:'kernel_taint',observation_count:0}}});
assert.match(emptyModuleTaint,/Trạng thái kernel/);
assert.doesNotMatch(emptyModuleTaint,/<span class="evidence-kind">Module kernel<\/span>/);
assert.match(emptyModuleTaint,/0 lần quan sát/);
assert.doesNotMatch(highlights(emptyModuleTaint),/Out-of-tree module|Unsigned module|Kernel oops/);

const dnsCard = scope.renderEvidence({ evidence_id: 'EV-dns', evidence_type: 'observed',
  data: { rule: { id: '100181', description: 'DNS' }, dns: { query: '<bad.test>' },
    src_ip: '192.0.2.1' } });
assert.match(dnsCard, /Query<\/dt><dd>&lt;bad.test&gt;/);
assert.match(dnsCard, /DNS/);
assert.doesNotMatch(dnsCard, /<bad.test>/);

const dos = scope.renderEvidence({evidence_type:'observed',data:{zeek_connection:{proto:'tcp',conn_state:'S0'},
  flow_summary:{flow_observations:0},src_ip:'192.0.2.10',dst_ip:'192.0.2.11',dst_port:443}});
assert.match(dos,/<span class="evidence-kind">Mạng<\/span>/);assert.match(highlights(dos),/Số flow<\/dt><dd>0/);
const flowOnly=scope.renderEvidence({evidence_type:'aggregate',data:{flow_summary:{flow_observations:0}}});
assert.match(flowOnly,/Tổng hợp 0 flow mạng đã lưu/);

const bruteForce = scope.renderEvidence({evidence_type:'aggregate',data:{authentication_summary:{groups:[{
  username:'operator',source_ip:'192.0.2.7',failure_count:3,failure_record_count:11,
  success_count:0,success_record_count:0}]}}});
assert.match(bruteForce,/Tổng hợp dữ liệu/);assert.match(bruteForce,/<span class="evidence-kind">Xác thực<\/span>/);
assert.match(highlights(bruteForce),/Lần thử thất bại xác nhận<\/dt><dd>3/);
assert.match(highlights(bruteForce),/Bản ghi thất bại<\/dt><dd>11/);
assert.match(highlights(bruteForce),/Lần thành công xác nhận<\/dt><dd>0/);

const tunneling = scope.renderEvidence({evidence_type:'observed',data:{dns:{query:'long.lab.test',rcode_name:'NOERROR'},
  zeek_connection:{proto:'udp'},src_ip:'192.0.2.1',dst_ip:'192.0.2.53'}});
assert.match(tunneling,/<span class="evidence-kind">DNS<\/span>/);assert.match(highlights(tunneling),/Query<\/dt><dd>long.lab.test/);
assert.match(highlights(tunneling),/IP nguồn<\/dt><dd>192.0.2.1/);
assert.equal((highlights(tunneling).match(/<dt>/g)||[]).length<=6,true);
const mixed = scope.renderEvidence({evidence_type:'trigger',data:{dns:{query:'mixed.test'},
  http:{method:'POST'},zeek_connection:{proto:'tcp'},src_ip:'192.0.2.2'}});
assert.match(mixed,/Cảnh báo khởi tạo/);
assert.match(mixed,/<span class="evidence-kind">DNS<\/span>/);
assert.match(highlights(mixed),/Query<\/dt><dd>mixed.test/);
assert.match(highlights(mixed),/Method<\/dt><dd>POST/);
assert.match(highlights(mixed),/IP nguồn<\/dt><dd>192.0.2.2/);
assert.equal((highlights(mixed).match(/<dt>/g)||[]).length<=6,true);

const http = scope.renderEvidence({evidence_type:'observed',data:{http:{method:'GET',host:'example.test',status_code:0}}});
assert.match(http,/HTTP/);assert.match(highlights(http),/Status<\/dt><dd>0/);
assert.match(scope.renderEvidence({evidence_type:'observed',data:{http:{status_code:0}}}),/Log HTTP ghi trạng thái 0/);
const process = scope.renderEvidence({evidence_type:'observed',data:{audit:{command:'iodine',exe:'/usr/bin/iodine'}}});
assert.match(process,/<span class="evidence-kind">Tiến trình<\/span>/);assert.match(highlights(process),/Tệp thực thi<\/dt><dd>\/usr\/bin\/iodine/);

const fim = scope.renderEvidence({evidence_type:'observed',data:{file_path:'/etc/demo.conf',
  file_change:{event:'modified',sha256_before:'old',sha256_after:'new',audit:{user:{name:'operator'}}}}});
assert.match(fim,/<span class="evidence-kind">Thay đổi tệp<\/span>/);assert.match(highlights(fim),/Tệp<\/dt><dd>\/etc\/demo.conf/);
assert.match(highlights(fim),/Người thực hiện<\/dt><dd>operator/);
const fileRead = scope.renderEvidence({evidence_type:'observed',tool:'search_file_access',data:{file_path:'/tmp/demo.txt'}});
assert.doesNotMatch(fileRead,/<span class="evidence-kind">Thay đổi tệp<\/span>/);

const unknown = scope.renderEvidence({evidence_type:'observed',evidence_id:'EV-unknown',source_record_id:'source-unknown',
  data:{username:'user',src_ip:'192.0.2.1',summary_truncated:true}});
assert.match(unknown,/Chưa phân loại/);assert.match(highlights(unknown),/Người dùng<\/dt><dd>user/);
assert.match(unknown,/JSON dưới đây không mặc nhiên là log nguồn đầy đủ/);
assert.equal((unknown.match(/<details>/g)||[]).length,3);
assert.match(unknown,/"source_record_id": "source-unknown"/);
const fullId='EV-'+'a'.repeat(64),sourceId='WAZUH-'+'b'.repeat(64);
const longIds=scope.renderEvidence({evidence_type:'observed',evidence_id:fullId,source_record_id:sourceId,data:{}});
assert.match(longIds,new RegExp(`class="evidence-id" tabindex="0" title="${fullId}">${fullId}<\\/code>`));
assert.match(longIds,new RegExp(`title="${sourceId}">${sourceId}<\\/code>`));
assert.match(html,/\.evidence-id\{[^}]*text-overflow:ellipsis/);
for(const card of [moduleCard,failedModule,unload,snapshotCard,discrepancy,detectorCard,taintCard,
  emptyModuleTaint,dnsCard,dos,bruteForce,tunneling,mixed,http,process,fim,fileRead,unknown]){
  assert.equal((card.match(/<details>/g)||[]).length,3);
}
console.log('Evidence cards keep three details sections and distinct roles, data types and source IDs.');
