# Author: Antonio Muñoz - NICS Lab - UMA
"""T-Time v4: cryptographically valid RSA exponents, synthetic timing observations.
Third-party original/ scripts are preserved without modification.
"""
import argparse, csv, hashlib, json, random, statistics, subprocess, sys, tempfile, os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

ROOT=Path(__file__).resolve().parent
LOW,HIGH=19400,20500
METHODS=('original','label_oracle_unfiltered','label_oracle_iqr')

UPSTREAM_SHA256 = {
    'pattern_second.py': '01ab296dbbf084af1c2dc0e33eee85b41879b28c5e32c376dfceed6af32a1223',
    'pattern_third.py': '98b55ffc08d3e319bb7b20fb902c68221ab0e19cfeb0c121104d582c1d8cb1b4',
}

def run_original(name, wd):
    if name not in UPSTREAM_SHA256:
        raise ValueError(f'Unrecognized upstream script: {name}')

    upstream_dir = os.environ.get('TTIME_ORIGINAL_DIR')
    if upstream_dir:
        script = Path(upstream_dir).expanduser().resolve() / name
    else:
        script = ROOT / 'original' / name

    if not script.is_file():
        raise FileNotFoundError(f'Upstream decoder not found: {script}')

    actual_hash = hashlib.sha256(script.read_bytes()).hexdigest()
    if actual_hash != UPSTREAM_SHA256[name]:
        raise RuntimeError(
            f'Upstream decoder SHA-256 mismatch: {name}; '
            f'expected={UPSTREAM_SHA256[name]}, actual={actual_hash}'
        )

    p = subprocess.run(
        [sys.executable, str(script)],
        cwd=wd,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if p.returncode:
        raise RuntimeError(f'{name}: {p.stderr[-1000:]}')

def original(g1,g2,wd):
    p=Path(wd)
    lines=['--- Experiment 1 ---']+[f'[{k}] time diff : {v}' for k,v in g1]
    lines+=['--- Experiment 2 ---']+[f'[{k}] time diff : {v}' for k,v in g2]
    (p/'output_pattern_case2.txt').write_text('\n'.join(lines)+'\n')
    run_original('pattern_second.py',wd)
    run_original('pattern_third.py',wd)
    return (p/'result.txt').read_text().strip()

def oracle(g1,g2,keys,wd,iqr):
    values=sorted(v for _,v in g1+g2)
    hi=values[3*len(values)//4]+(values[3*len(values)//4]-values[len(values)//4]) if iqr and values else float('inf')
    a,b=dict(g1),dict(g2); retained=[]
    for key in keys:
        vs=[d[key] for d in (a,b) if key in d and 0<=d[key]<=hi]
        if vs: retained.append((key,sum(vs)/len(vs),len(vs)))
    (Path(wd)/'output_pattern_average.txt').write_text(''.join(f'[{k}] time diff : {v:.2f}  ({n} samples)\n' for k,v,n in retained))
    run_original('pattern_third.py',wd)
    return (Path(wd)/'result.txt').read_text().strip()

def encode(bits,rng):
    return [(f'B{k:05d}_{j}',(HIGH if bit=='1' else LOW)+rng.randint(-30,30)) for k,bit in enumerate(bits) for j in range(4 if bit=='1' else 2)]

def perturb(g1,g2,keys,rng,kind,level):
    g1,g2=list(g1),list(g2)
    if kind=='deletion_second':g2=[x for x in g2 if rng.random()>=level]
    elif kind=='deletion_independent':
        g1=[x for x in g1 if rng.random()>=level];g2=[x for x in g2 if rng.random()>=level]
    elif kind=='deletion_shared':
        lost={k for k in keys if rng.random()<level};g1=[x for x in g1 if x[0] not in lost];g2=[x for x in g2 if x[0] not in lost]
    elif kind in ('prefix_second','prefix_both','random_second','random_both'):
        for target in ([2] if kind.endswith('second') else [1,2]):
            group=g1 if target==1 else g2
            for j in range(int(level)):
                pos=0 if kind.startswith('prefix') else rng.randrange(len(group)+1)
                group.insert(pos,(f'EXTRA_g{target}_{j}',rng.choice((LOW,HIGH))+rng.randint(-30,30)))
    elif kind!='baseline':raise ValueError(kind)
    return g1,g2

def levenshtein(a,b):
    row=list(range(len(b)+1))
    for i,x in enumerate(a,1):
        nxt=[i]
        for j,y in enumerate(b,1):nxt.append(min(nxt[-1]+1,row[j]+1,row[j-1]+(x!=y)))
        row=nxt
    return row[-1]

def bitstring(n,width):return format(n,f'0{width}b')

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--seed',type=int,default=20261030)
    ap.add_argument('--repeats',type=int,default=5)
    ap.add_argument('--window',type=int,default=64)
    ap.add_argument('--full-baseline',action='store_true',help='Also reconstruct entire private exponent with no perturbations')
    ap.add_argument('--output',default='results')
    ap.add_argument('--retain-traces',action='store_true',help='Save all synthetic inputs and reconstructed bitstrings. SENSITIVE: may expose RSA private exponent.')
    args=ap.parse_args()
    if args.repeats<1 or args.window<1:ap.error('repeats and window must be positive')
    out=Path(args.output).resolve();out.mkdir(parents=True,exist_ok=True)
    if args.retain_traces:
        try: os.chmod(out,0o700)
        except OSError: pass
        print('WARNING: retained synthetic traces and bitstrings may disclose the RSA private exponent. Keep this folder private.',file=sys.stderr)
    # cryptography uses a cryptographically secure backend for key generation.
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    numbers=key.private_numbers(); d=numbers.d;n=numbers.public_numbers.n;e=numbers.public_numbers.e
    full=bitstring(d,n.bit_length())
    assert pow(pow(42,e,n),d,n)==42
    msg=b'T-Time v4 RSA private-key reconstruction check'
    signature=key.sign(msg,padding.PKCS1v15(),hashes.SHA256())
    key.public_key().verify(signature,msg,padding.PKCS1v15(),hashes.SHA256())
    # RSA key generation is nondeterministic. Seed applies ONLY to selection/perturbations.
    rng=random.Random(args.seed)
    conditions=[('baseline',0)]+[(k,p) for k in ('deletion_second','deletion_independent','deletion_shared') for p in (0.01,0.05,0.10,0.20)]
    conditions += [(k,v) for k in ('prefix_second','prefix_both','random_second','random_both') for v in (1,2,5)]
    fields=['condition','level','trial','method','window_start','reference_length','recovered_length','exact_recovery','edit_distance','normalized_edit_distance','hamming_ber','execution_error']
    rows=[]; traces=[]
    trace_file=(out/'trace_replay.jsonl').open('w') if args.retain_traces else None
    if trace_file is not None:
        try: os.chmod(out/'trace_replay.jsonl',0o600)
        except OSError: pass
    def evaluate(bits,kind,level,trial,start):
        base=encode(bits,rng); keys=[k for k,_ in base]
        g2=[(k,v+rng.randint(-20,20)) for k,v in base]
        g1,g2=perturb(base,g2,keys,rng,'baseline' if kind=='full_baseline' else kind,level)
        predictions={}
        with tempfile.TemporaryDirectory() as wd:
            for method in METHODS:
                pred=None;error=''
                try:pred=original(g1,g2,wd) if method=='original' else oracle(g1,g2,keys,wd,method=='label_oracle_iqr')
                except Exception as exc:error=str(exc)
                predictions[method]={'recovered':pred,'error':error}
                dist=levenshtein(bits,pred) if pred is not None else None
                rows.append(dict(condition=kind,level=level,trial=trial,method=method,window_start=start,
                    reference_length=len(bits),recovered_length=len(pred) if pred is not None else '',
                    exact_recovery=int(pred==bits) if pred is not None else 0,
                    edit_distance=dist if dist is not None else '',normalized_edit_distance=dist/len(bits) if dist is not None else '',
                    hamming_ber=(sum(x!=y for x,y in zip(bits,pred))/len(bits) if pred is not None and len(pred)==len(bits) else ''),execution_error=error))
                if (kind=='baseline' and trial==0) or kind=='full_baseline':
                    traces.append({'condition':kind,'method':method,'reference_sha256':hashlib.sha256(bits.encode()).hexdigest(),'reference_length':len(bits),'recovered_length':len(pred) if pred is not None else None,'exact':pred==bits,'error':error})
        if trace_file is not None:
            trace_file.write(json.dumps({'condition':kind,'level':level,'trial':trial,'window_start':start,'reference_bits':bits,'g1':g1,'g2':g2,'keys':keys,'predictions':predictions},separators=(',',':'))+'\n')
            trace_file.flush()
    for kind,level in conditions:
        for trial in range(args.repeats):
            start=rng.randrange(len(full)-args.window+1) if args.window<len(full) else 0
            evaluate(full[start:start+args.window],kind,level,trial,start)
        print(kind,level,'done',flush=True)
    if args.full_baseline:
        evaluate(full,'full_baseline',0,0,0)
    if trace_file is not None: trace_file.close()
    with (out/'trials.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
    summary=[]
    for kind,level in conditions+([('full_baseline',0)] if args.full_baseline else []):
        for method in METHODS:
            rs=[r for r in rows if r['condition']==kind and r['level']==level and r['method']==method]
            summary.append({'condition':kind,'level':level,'method':method,'n':len(rs),'exact_recovery_rate':statistics.mean(r['exact_recovery'] for r in rs),'errors':sum(bool(r['execution_error']) for r in rs),'mean_normalized_edit_distance':statistics.mean(r['normalized_edit_distance'] for r in rs if r['normalized_edit_distance']!='') if any(r['normalized_edit_distance']!='' for r in rs) else ''})
    with (out/'summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(summary[0]));w.writeheader();w.writerows(summary)
    full_result=next((x for x in traces if x['condition']=='full_baseline' and x['method']=='original'),None)
    # Never store private key, factors or full exponent in the output manifest.
    manifest={'author':'Antonio Muñoz - NICS Lab - UMA','key_size':2048,'public_exponent':e,
      'public_modulus_sha256':hashlib.sha256(n.to_bytes((n.bit_length()+7)//8,'big')).hexdigest(),
      'crypto_backend':'cryptography','signature_verified':True,'modular_RSA_check':True,
      'seed_for_perturbations_only':args.seed,'repeats':args.repeats,'window':args.window,
      'conditions':len(conditions),'trial_method_rows':len(rows),'full_baseline_enabled':args.full_baseline,
      'full_baseline_original_exact':full_result['exact'] if full_result else None,
      'original_script_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'original').glob('*.py'))},
      'retained_traces':bool(args.retain_traces),'trace_count':len(conditions)*args.repeats+int(args.full_baseline) if args.retain_traces else 0,
      'interpretation':'Cryptographically valid RSA exponent with SYNTHETIC observation encoding; NOT Intel TDX acquisition.'}
    if args.retain_traces:
        manifest['trace_replay_sha256']=hashlib.sha256((out/'trace_replay.jsonl').read_bytes()).hexdigest()
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2))
    (out/'baseline_replay.json').write_text(json.dumps(traces,indent=2))
    print(json.dumps({'rows':len(rows),'summary_rows':len(summary),'full_baseline_exact':manifest['full_baseline_original_exact'],'output':str(out)},indent=2))

if __name__=='__main__':main()
