const BASE='http://127.0.0.1:8100'; let p=0,f=0; const ok=(n,c,e='')=>{c?(p++,console.log('  PASS  '+n)):(f++,console.log('  FAIL  '+n+(e?' :: '+e:'')))};
const str=x=>JSON.stringify(x);
const EICAR='X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
const eml=['From: "PayPal Support" <support@paypa1-secure.com>\r\nTo: v@x.org\r\nReturn-Path: <bounce@evil-mailer.com>\r\nReply-To: scam@other-domain.net\r\nSubject: Verify your account\r\nReceived: from mail.evil-mailer.com (unknown [93.184.216.34]) by mx.test with ESMTP; Mon, 10 Nov 2026 10:00:00 +0000\r\nReceived: from mail.evil-mailer.com (unknown [93.184.216.34]) by mx2.test with ESMTP; Mon, 10 Nov 2026 09:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="BOUND"\r\n\r\n',
'--BOUND\r\nContent-Type: text/html\r\n\r\n<p>verify now http://203.0.113.5/login.php</p>\r\n',
`--BOUND\r\nContent-Type: application/octet-stream; name="eicar.bin"\r\nContent-Disposition: attachment; filename="eicar.bin"\r\n\r\n${EICAR}\r\n--BOUND--\r\n`].join('');

const login=await fetch(BASE+'/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({user:'admin',pass:'TestSmoke-123456'})});
const lj=await login.json(); const cookie=(login.headers.get('set-cookie')||'').split(';')[0]; const csrf=lj.csrf||'';
ok('login 200 + csrf',login.ok&&!!cookie&&!!csrf,str(lj).slice(0,120));
const H={'x-csrf':csrf,'cookie':cookie};

const h=await fetch(BASE+'/api/health').then(r=>r.json());
ok('health ok',h.ok===true,str(h).slice(0,100));

// single analyze
const fd=new FormData(); fd.append('files',new Blob([eml],{type:'text/plain'}),'phish.eml');
const a=await fetch(BASE+'/api/analyze',{method:'POST',headers:H,body:fd}); const aj=await a.json();
const r=aj.results?.[0]||{};
ok('analyze 200',a.ok,str(aj).slice(0,150));
ok('verdict malicious_or_phishing',r.verdict==='malicious_or_phishing','verdict='+r.verdict);
ok('score < 50',typeof r.score==='number'&&r.score<50,'score='+r.score);
ok('url ip-host malicious',r.urls?.[0]?.verdict==='malicious'&&String(r.urls?.[0]?.url).includes('203.0.113.5'),str(r.urls).slice(0,150));
ok('EICAR attachment malicious',r.attachments?.some(x=>x.verdict==='malicious'&&x.name==='eicar.bin'),str(r.attachments).slice(0,150));
ok('findings have U-/A- ids',Array.isArray(r.findings)&&r.findings.some(x=>String(x.id||'').startsWith('U-'))&&r.findings.some(x=>String(x.id||'').startsWith('A-')),str(r.findings?.map(x=>x.id)).slice(0,150));
ok('headerAnalysis H- checks',r.headerAnalysis?.checks?.length>0&&r.headerAnalysis.checks.some(x=>String(x.id||'').startsWith('H-')),str(r.headerAnalysis?.checks?.map(x=>x.id)).slice(0,150));
ok('routing hops',r.routing?.hops?.length>=2,str(r.routing).slice(0,120));
ok('auth object',r.auth&&'spf' in r.auth&&'dkim' in r.auth&&'dmarc' in r.auth,str(r.auth).slice(0,120));
ok('ipInfo confidence number',Array.isArray(r.ipInfo)&&typeof r.ipInfo[0]?.confidence==='number',str(r.ipInfo).slice(0,150));
ok('originIPs present',Array.isArray(r.originIPs)&&r.originIPs.includes('93.184.216.34'),str(r.originIPs));
ok('ioc counts',r.ioc&&Object.keys(r.ioc.counts||{}).length>0,str(r.ioc?.counts));
ok('custody.caseId',!!r.custody?.caseId,str(r.custody));
const id=r.custody?.caseId;

// message body endpoint (M8)
ok('message meta in result',r.messages?.[0]?.body?.hasHtml===true,str(r.messages?.[0]).slice(0,150));
if(id){
  const mr=await fetch(BASE+`/api/case/${id}/message/0`,{headers:H});
  const mj=await mr.json().catch(()=>({}));
  ok('message body endpoint 200',mr.ok&&mj.index===0,str(mj).slice(0,150));
  ok('message body has html + text',mj.hasHtml===true&&mj.hasText===true&&String(mj.html).includes('verify now'),str(mj).slice(0,200));
  ok('message body sanitised',!String(mj.html).includes('<script')&&!/onclick/i.test(String(mj.html)),String(mj.html).slice(0,120));
  const mr2=await fetch(BASE+`/api/case/${id}/message/99`,{headers:H});
  ok('message index out of range -> 404',mr2.status===404,'status='+mr2.status);
  const mr3=await fetch(BASE+`/api/case/nosuchcase/message/0`,{headers:H});
  ok('unknown case -> 404',mr3.status===404,'status='+mr3.status);
  const mr4=await fetch(BASE+`/api/case/${id}/message/0`);
  ok('message endpoint requires auth -> 401',mr4.status===401,'status='+mr4.status);
}

// multi-file batch (loop refactor)
const fd2=new FormData();
fd2.append('files',new Blob([eml],'a1.eml'.length?{type:'text/plain'}:{}),'b1.eml');
fd2.append('files',new Blob([eml],{type:'text/plain'}),'b2.eml');
fd2.append('files',new Blob([eml],{type:'text/plain'}),'b3.eml');
const a2=await fetch(BASE+'/api/analyze',{method:'POST',headers:H,body:fd2}); const aj2=await a2.json();
ok('batch 3 files -> 3 results',aj2.results?.length===3&&!aj2.errors?.length,str(aj2.errors));

// error paths
const a3=await fetch(BASE+'/api/analyze',{method:'POST',headers:H,body:new FormData()});
ok('analyze empty -> 400',a3.status===400,'status='+a3.status);

// exports
if(id){
  const cs=await fetch(BASE+`/api/cases?limit=10`,{headers:H}).then(r=>r.json());
  ok('cases list has case',cs.cases?.length>0,str(cs).slice(0,100));
  const rj=await fetch(BASE+`/api/report/${id}?format=json`,{headers:H}).then(r=>r.json());
  ok('report json has auth',rj.case?.auth||rj.auth,str(rj).slice(0,100));
  const rcsv=await fetch(BASE+`/api/report/${id}?format=csv`,{headers:H}).then(r=>r.text());
  ok('report csv has columns',rcsv.includes('spf')||rcsv.toLowerCase().includes('spf'),rcsv.slice(0,120));
}

console.log(`\n${p}/${p+f} PASS`); process.exit(f?1:0);
