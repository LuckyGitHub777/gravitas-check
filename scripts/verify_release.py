"""Public distribution verification: no network, account secrets or old source history."""
from __future__ import annotations
import base64, hashlib, re, subprocess, sys
from html.parser import HTMLParser
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SITE='https://luckygithub777.github.io/gravitas-check/'
FILES={'.nojekyll','LICENSE','README.md','SECURITY.md','gravitas.md',
       'index.html','llms.txt','PUBLICATION-PROVENANCE.md',
       'scripts/verify_release.py','scripts/test_file_read_race.cjs','.github/workflows/verify.yml'}
class Parser(HTMLParser):
    def __init__(self):
        super().__init__();self.scripts=[];self.typ=None;self.buf=[];self.csp='';self.canonical=[];self.remote=[]
        self.styles=[];self.in_style=False;self.style_buf=[];self.style_attrs=[]
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if 'style' in a:self.style_attrs.append(tag)
        if tag=='style':self.in_style=True;self.style_buf=[]
        if tag=='script':
            self.typ=(a.get('type') or '').lower();self.buf=[]
            if a.get('src'):self.remote.append('script')
        elif tag=='meta' and (a.get('http-equiv') or '').lower()=='content-security-policy':
            self.csp=a.get('content') or ''
        elif tag=='link':
            rel=(a.get('rel') or '').lower();href=a.get('href') or ''
            if rel=='canonical':self.canonical.append(href)
            if rel in {'stylesheet','modulepreload','preload'} and href.startswith(('http:','https:')):self.remote.append('link')
    def handle_data(self,data):
        if self.typ is not None:self.buf.append(data)
        if self.in_style:self.style_buf.append(data)
    def handle_endtag(self,tag):
        if tag=='style' and self.in_style:
            self.styles.append(''.join(self.style_buf));self.in_style=False;self.style_buf=[]
        if tag=='script' and self.typ is not None:
            self.scripts.append((self.typ,''.join(self.buf)));self.typ=None;self.buf=[]
def check():
    ls=subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode('utf-8').strip('\0').split('\0')
    assert set(ls)==FILES,'file boundary changed'
    assert not any((ROOT/x).is_symlink() for x in FILES),'symlink introduced'
    assert (ROOT/'.nojekyll').stat().st_size==0,'unexpected .nojekyll'
    lic=(ROOT/'LICENSE').read_text(encoding='utf-8')
    assert lic.startswith('Copyright (c) 2026 Gravitas Engine. All rights reserved.'),'license changed'
    assert 'You may not republish' in lic,'proprietary terms changed'
    for path in FILES- {'.nojekyll'}:
        s=(ROOT/path).read_text(encoding='utf-8')
        assert not re.search(r'(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})',s),'token pattern'
        assert not re.search(r'[A-Za-z]:[\\/]Users[\\/]|/(?:home|Users)/[^/\s]+/',s),'workstation path'
        assert not re.search(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',s),'email-like data'
    html=(ROOT/'index.html').read_text(encoding='utf-8');p=Parser();p.feed(html)
    assert p.canonical==[SITE],'canonical domain/path mismatch'
    assert not p.remote,'unexpected hosted runtime dependency'
    assert all(x in p.csp for x in ("connect-src 'none'","form-action 'none'","object-src 'none'")),'CSP boundary'
    runtime=[s for typ,s in p.scripts if typ in ('','text/javascript','application/javascript','module')]
    assert len(runtime)==1,'unexpected executable scripts'
    digest=base64.b64encode(hashlib.sha256(runtime[0].encode('utf-8')).digest()).decode('ascii')
    assert "'sha256-"+digest+"'" in p.csp,'CSP inline script hash invalid'
    assert "'unsafe-inline'" not in p.csp and not p.style_attrs,'inline style policy or attributes'
    assert len(p.styles)==3,'unexpected style block count'
    for style in p.styles:
        digest=base64.b64encode(hashlib.sha256(style.encode('utf-8')).digest()).decode('ascii')
        assert "style-src " in p.csp and "'sha256-"+digest+"'" in p.csp,'CSP inline style hash invalid'
    assert len(re.findall(r"'sha256-[A-Za-z0-9+/=]+'",p.csp))==1+len(p.styles),'unreviewed CSP hash count'
    assert 'style.cssText' not in runtime[0] and "ta.className = 'copy-fallback';" in runtime[0],'unsafe copy fallback inline style'
    assert '.copy-fallback{' in ''.join(p.styles),'missing copy fallback CSS'
    assert SITE+'gravitas.md' in html,'protocol URL mismatch'
    assert SITE in (ROOT/'README.md').read_text(encoding='utf-8'),'README URL mismatch'
    assert SITE+'gravitas.md' in (ROOT/'llms.txt').read_text(encoding='utf-8'),'AI reference URL mismatch'
    assert not re.search(r'(?:\bfetch\s*\(|\bXMLHttpRequest\b|\bsendBeacon\b|\bWebSocket\b|\bEventSource\b|\blocalStorage\b|\bindexedDB\b|\binnerHTML\b|\bouterHTML\b)',runtime[0]),'unexpected remote/storage/HTML call'
    # Clearing an input must erase previous in-memory report/prompt content and its rendered result.
    assert 'function runCheck() {' in runtime[0] and 'const doc = parse(raw);' in runtime[0], 'runCheck boundary missing'
    blank = runtime[0].split('function runCheck() {', 1)[1].split('const doc = parse(raw);', 1)[0]
    assert 'if (!clean(raw)) {' in blank, 'blank input guard missing'
    for required in ("current = null;", "currentText = '';", "rewriteResult = null;", "'rail'", "'profile'", "'moves'", "'flags'", "'claims'", "'actionKv'", "'structKv'", "'outline'", "'#avgScore'", "'#rewriteStatus'", "'#reportStatus'"):
        assert required in blank, 'blank input does not clear prior report'
    assert "$('#specimen').focus(); runCheck();" in runtime[0], 'clear control does not run reset'
    # Edited content must invalidate stale reports, prompts and visible findings.
    assert "$('#specimen').addEventListener('input', () => {" in runtime[0], 'unsaved input invalidation missing'
    edited = runtime[0].split("$('#specimen').addEventListener('input', () => {", 1)[1].split("\n  });", 1)[0]
    for required in ("current = null;", "currentText = '';", "rewriteResult = null;",
                     "'rail'", "'profile'", "'moves'", "'flags'", "'claims'", "'actionKv'",
                     "'structKv'", "'outline'", "'#reportStatus'", "'#rewriteStatus'"):
        assert required in edited, 'editing the source can retain stale output'
    return runtime[0]
if __name__=='__main__':
    try:
        js=check()
        if len(sys.argv)==3 and sys.argv[1]=='--emit-runtime':Path(sys.argv[2]).write_text(js,encoding='utf-8')
        elif len(sys.argv)!=1:raise ValueError('usage --emit-runtime PATH')
        print('PASS: public release tree, rights, privacy patterns, local runtime and CSP hash')
    except (AssertionError,ValueError,UnicodeError,OSError,subprocess.CalledProcessError):
        print('SAFE STOP: public release boundary failed',file=sys.stderr);sys.exit(1)
