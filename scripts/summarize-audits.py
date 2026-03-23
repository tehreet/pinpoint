#!/usr/bin/env python3
import json, os, glob

results = []
for f in sorted(glob.glob("/tmp/pinpoint-audits/*.json")):
    org = os.path.basename(f).replace('.json','')
    try:
        d = json.load(open(f))
        t = max(d['references']['total'], 1)
        triggers = d.get('dangerous_triggers', [])
        crit = len([x for x in triggers if x['risk'] == 'critical'])
        high = len([x for x in triggers if x['risk'] == 'high'])
        med = len([x for x in triggers if x['risk'] == 'medium'])
        results.append({
            'org': org,
            'repos': d['repos']['total'],
            'with_workflows': d['repos']['with_workflows'],
            'total_refs': d['references']['total'],
            'sha_pinned': d['references']['sha_pinned'],
            'tag_pinned': d['references']['tag_pinned'],
            'branch_pinned': d['references']['branch_pinned'],
            'sha_pct': round(100 * d['references']['sha_pinned'] / t, 1),
            'tag_pct': round(100 * d['references']['tag_pinned'] / t, 1),
            'branch_pct': round(100 * d['references']['branch_pinned'] / t, 1),
            'triggers_total': len(triggers),
            'triggers_critical': crit,
            'triggers_high': high,
            'triggers_medium': med,
            'trigger_details': [{'repo': x['repo'], 'file': x['workflow_file'], 'risk': x['risk']} for x in triggers]
        })
    except Exception as e:
        print(f"SKIP {org}: {e}")

# Sort by SHA pinning rate
results.sort(key=lambda x: x['sha_pct'])

# Print summary table
print(f"{'Org':<25} {'Repos':>5} {'Refs':>6} {'SHA%':>6} {'Tag%':>6} {'Br%':>5} {'Triggers':>8} {'Crit':>5}")
print("-" * 90)
for r in results:
    trig_str = f"{r['triggers_total']}" if r['triggers_total'] > 0 else "-"
    crit_str = f"{r['triggers_critical']}" if r['triggers_critical'] > 0 else ""
    print(f"{r['org']:<25} {r['repos']:>5} {r['total_refs']:>6} {r['sha_pct']:>5.1f}% {r['tag_pct']:>5.1f}% {r['branch_pct']:>4.1f}% {trig_str:>8} {crit_str:>5}")

print(f"\n\nTotal orgs: {len(results)}")
print(f"Orgs with >0 dangerous triggers: {len([r for r in results if r['triggers_total'] > 0])}")
print(f"Orgs with CRITICAL triggers: {len([r for r in results if r['triggers_critical'] > 0])}")
print(f"Total CRITICAL triggers found: {sum(r['triggers_critical'] for r in results)}")

# Dump as JSON for the artifact
with open('/tmp/pinpoint-audits/summary.json', 'w') as f:
    json.dump(results, f, indent=2)
print(f"\nJSON written to /tmp/pinpoint-audits/summary.json")

# Highlight the irony orgs
print("\n\n=== THE IRONY REPORT ===")
print("Organizations that published analysis of the Trivy supply chain attack:")
irony = ['aquasecurity', 'step-security', 'crowdstrike', 'snyk', 'SocketDev', 'wiz-sec', 'paloaltonetworks', 'endorlabs']
for org in irony:
    r = next((x for x in results if x['org'] == org), None)
    if r:
        print(f"\n  {r['org']}: {r['sha_pct']}% SHA-pinned, {r['triggers_total']} dangerous triggers ({r['triggers_critical']} critical)")
        for t in r['trigger_details']:
            if t['risk'] == 'critical':
                print(f"    CRITICAL: {t['repo']}/{t['file']}")
