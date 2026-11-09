import os
import json
from collections import Counter
from src.telemetry_parser import parse_strace_telemetry
from src.a_adj_adjudicator import adjudicate_skill_behavior
from src.security.level1_scanner import scan_skill_for_level1_security

s_dir = 'dynamic_samples/sample_20261005_185036_54e119'
manifest = json.load(open(os.path.join(s_dir, 'manifest.json')))

# Map each skill to its job trial directory
jobs_map = {}
for root, dirs, files in os.walk('jobs'):
    if '20261005_19' in root and 'strace.log' in files:
        parts = root.split(os.sep)
        skill_name_prefix = parts[2].split('__')[0]
        for s in manifest['skills']:
            s_id = s['skill_id']
            if s_id.startswith(skill_name_prefix) or skill_name_prefix in s_id:
                trial_dir = os.path.dirname(os.path.dirname(root))
                jobs_map[s_id] = (trial_dir, os.path.join(root, 'strace.log'))

print(f"Mapped {len(jobs_map)} skills to their exact jobs trial directories")

orig_report_p = os.path.join(s_dir, 'report.json')
orig_report = json.load(open(orig_report_p))
orig_results = {r['skill_id']: r for r in orig_report['results']}

final_results = []
for s in manifest['skills']:
    s_id = s['skill_id']
    s_path = os.path.join(s_dir, 'skills', s_id)
    is_known_mal = s.get('known_malicious', False)
    domain = s.get('domain', 'general')
    orig_r = orig_results.get(s_id, {})
    
    l1_rep = scan_skill_for_level1_security(s_path)
    l1_risk = l1_rep.get('risk_level', 'LOW')
    
    traces = []
    trial_dir = None
    if s_id in jobs_map:
        trial_dir, strace_p = jobs_map[s_id]
        st_info = parse_strace_telemetry(strace_p)
        traces = [{'events': st_info.get('events', [])}]
    elif os.path.exists(os.path.join(s_path, 'trace.jsonl')):
        events = []
        with open(os.path.join(s_path, 'trace.jsonl')) as f:
            for l in f:
                if l.strip():
                    ev = json.loads(l)
                    if ev.get('details', {}).get('action') != 'socket_creation' and ev.get('details', {}).get('destination') != 'socket_endpoint':
                        events.append(ev)
        traces = [{'events': events}]
        
    contracts = []
    c_p = os.path.join(s_path, 'contracts.json')
    if os.path.exists(c_p):
        contracts = json.load(open(c_p)).get('contracts', [])
        
    old_status = orig_r.get('run_status', 'INVOKED_SUCCEEDED' if traces else 'NOT_INVOKED')
    old_sublabel = orig_r.get('execution_error_sublabel')
    run_status = old_status
    failure_type = None
    sublabel = old_sublabel
    entry_reached = bool(traces)
    
    if old_sublabel == 'no_entry':
        run_status = 'NOT_INVOKED'
        failure_type = 'NO_RUNNABLE_ENTRY'
        entry_reached = False
    elif old_status == 'INFRA_FAILURE':
        failure_type = 'ENV_ERROR'
    elif old_status == 'INVOKED_FAILED':
        failure_type = 'SKILL_BUG'
        
    adj = adjudicate_skill_behavior(
        contracts=contracts,
        traces=traces,
        skill_dir=s_path,
        run_status=run_status,
        entry_point_reached=entry_reached,
        failure_type=failure_type,
        execution_error_sublabel=sublabel,
        level1_risk=l1_risk,
        harbor_trial_dir=trial_dir,
        domain=domain
    )
    
    final_results.append({
        'skill_id': s_id,
        'known_malicious': is_known_mal,
        'domain': domain,
        'level1_risk': l1_risk,
        'level1_reason': l1_rep.get('reason'),
        'gating_status': adj.get('gating_status'),
        'run_status': run_status,
        'verdict': adj.get('verdict'),
        'coverage_score': adj.get('coverage_score'),
        'explanation': adj.get('explanation'),
        'contract_verdicts': adj.get('contract_verdicts', []),
        'execution_error_sublabel': sublabel,
        'backend': orig_r.get('backend', 'harbor_docker'),
        'valid_for_paper': orig_r.get('valid_for_paper', True)
    })

print("\n=== FINAL VERDICTS SUMMARY ===")
print(Counter(r['verdict'] for r in final_results))
print("\n=== BENIGN BREAKDOWN ===")
for r in final_results:
    if not r['known_malicious']:
        print(f"{r['skill_id']}: {r['verdict']} (L1: {r['level1_risk']}) | {r['explanation']['headline']}")

print("\n=== MALICIOUS WITH UNDECLARED BEHAVIOR ===")
for r in final_results:
    if r['known_malicious'] and r['verdict'] == 'Undeclared_Behavior':
        print(f"- {r['skill_id']}: {r['explanation']['headline']}")

# Update report.json
v_dist = Counter(r['verdict'] for r in final_results)
g_dist = Counter(r['gating_status'] for r in final_results)
r_dist = Counter(r['run_status'] for r in final_results)

new_report = {
    "manifest_path": os.path.join(s_dir, 'manifest.json'),
    "run_id": manifest.get("run_id", "sample_20261005_185036_54e119"),
    "total_skills": len(final_results),
    "completed_skills": len(final_results),
    "is_completed": True,
    "blocked_static_count": sum(1 for r in final_results if r['verdict'] == 'Blocked_Static_CRITICAL'),
    "proceeded_to_level2": sum(1 for r in final_results if r['verdict'] != 'Blocked_Static_CRITICAL'),
    "average_coverage_score": round(sum(r.get('coverage_score', 0.0) for r in final_results) / len(final_results), 3),
    "level1_risk_distribution": dict(Counter(r['level1_risk'] for r in final_results)),
    "gating_status_distribution": dict(g_dist),
    "run_status_distribution": dict(r_dist),
    "verdict_distribution": dict(v_dist),
    "results": final_results
}

with open(orig_report_p, 'w', encoding='utf-8') as f:
    json.dump(new_report, f, indent=2)

print("\nReport updated successfully on disk!")
