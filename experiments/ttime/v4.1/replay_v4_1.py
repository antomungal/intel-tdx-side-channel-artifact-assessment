# Author: Antonio Muñoz - NICS Lab - UMA
"""Re-run original T-Time decoders on locally retained v4.1 synthetic traces."""
import argparse,csv,hashlib,json,tempfile
from pathlib import Path
from run_v4 import original,oracle,METHODS,levenshtein

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--output',default='results')
    args=ap.parse_args()
    out=Path(args.output)
    manifest=json.loads((out/'manifest.json').read_text())
    trace=out/'trace_replay.jsonl'
    assert trace.exists(),'No retained traces; run with --retain-traces'
    assert hashlib.sha256(trace.read_bytes()).hexdigest()==manifest['trace_replay_sha256'],'Trace file SHA-256 mismatch'
    expected={}
    with (out/'trials.csv').open(newline='') as f:
        for row in csv.DictReader(f):
            expected[(row['condition'],row['level'],row['trial'],row['method'])]=row
    checked=0;failures=[];trace_count=0
    with trace.open() as f:
        for line in f:
            record=json.loads(line);trace_count+=1
            bits=record['reference_bits'];g1=record['g1'];g2=record['g2'];keys=record['keys']
            with tempfile.TemporaryDirectory() as wd:
                for method in METHODS:
                    try:
                        got=original(g1,g2,wd) if method=='original' else oracle(g1,g2,keys,wd,method=='label_oracle_iqr')
                        error=''
                    except Exception as exc:
                        got=None;error=str(exc)
                    saved=record['predictions'][method]
                    row=expected[(record['condition'],str(record['level']),str(record['trial']),method)]
                    ok=(got==saved['recovered'] and error==saved['error'] and int(row['exact_recovery'])==int(got==bits) and (got is None or int(row['edit_distance'])==levenshtein(bits,got)))
                    if not ok:failures.append({'condition':record['condition'],'level':record['level'],'trial':record['trial'],'method':method})
                    checked+=1
    report={'trace_count':trace_count,'method_outputs_checked':checked,'expected_rows':len(expected),'failures':failures,'all_matched':not failures and checked==len(expected)}
    (out/'replay_report.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))
    if not report['all_matched']:raise SystemExit(1)
if __name__=='__main__':main()
