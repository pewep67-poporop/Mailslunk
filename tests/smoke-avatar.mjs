const BASE='http://127.0.0.1:8100'; let p=0,f=0; const ok=(n,c,e='')=>{c?(p++,console.log('  PASS  '+n)):(f++,console.log('  FAIL  '+n+(e?' :: '+e:'')))};
const PNG=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==','base64');
const JPG=Buffer.concat([Buffer.from([0xFF,0xD8,0xFF,0xE0]),Buffer.alloc(100,0x41)]);

const login=await fetch(BASE+'/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({user:'admin',pass:'TestSmoke-123456'})});
const lj=await login.json(); const cookie=(login.headers.get('set-cookie')||'').split(';')[0]; const csrf=lj.csrf||'';
ok('login 200',login.ok&&!!cookie,JSON.stringify(lj).slice(0,100));
const H={'x-csrf':csrf,'cookie':cookie};

let pr=await fetch(BASE+'/api/profile',{headers:H}).then(r=>r.json());
ok('profile before: hasAvatar flag present',typeof pr.hasAvatar==='boolean',JSON.stringify(pr).slice(0,150));

const up=(blob,name,headers=H)=>{const fd=new FormData();fd.append('avatar',blob,name);return fetch(BASE+'/api/profile/avatar',{method:'POST',headers,body:fd});};

let r=await up(new Blob([PNG],{type:'image/png'}),'tiny.png');
let j=await r.json().catch(()=>({}));
ok('upload PNG -> 200 ok',r.ok&&j.ok===true,JSON.stringify(j).slice(0,150));
ok('upload PNG returns avatarUpdated',typeof j.avatarUpdated==='string'&&j.avatarUpdated.length>10,JSON.stringify(j).slice(0,150));

pr=await fetch(BASE+'/api/profile',{headers:H}).then(r=>r.json());
ok('profile after: hasAvatar=true',pr.hasAvatar===true&&typeof pr.avatarUpdated==='string',JSON.stringify(pr).slice(0,150));
const stamp=pr.avatarUpdated;

const img=await fetch(BASE+'/api/profile/avatar',{headers:H});
const ib=Buffer.from(await img.arrayBuffer());
ok('GET avatar 200 image/png',img.ok&&(img.headers.get('content-type')||'').includes('image/png'),String(img.headers.get('content-type')));
ok('GET avatar bytes identical',ib.equals(PNG),ib.length+' vs '+PNG.length);
ok('GET avatar cache header',(img.headers.get('cache-control')||'').includes('private'),String(img.headers.get('cache-control')));

r=await up(new Blob([JPG],{type:'image/jpeg'}),'photo.jpg');
j=await r.json().catch(()=>({}));
ok('upload JPEG -> 200',r.ok&&j.ok===true,JSON.stringify(j).slice(0,150));

r=await up(new Blob([Buffer.from('this is not an image')],{type:'image/png'}),'fake.png');
j=await r.json().catch(()=>({}));
ok('fake image -> 400 bad_avatar',r.status===400&&j.error==='bad_avatar','status='+r.status+' '+JSON.stringify(j));
ok('fake did not overwrite avatar',Buffer.from(await (await fetch(BASE+'/api/profile/avatar',{headers:H})).arrayBuffer()).equals(JPG));

r=await up(new Blob([Buffer.alloc(0)],{type:'image/png'}),'empty.png');
j=await r.json().catch(()=>({}));
ok('empty file -> 400 bad_avatar',r.status===400&&j.error==='bad_avatar','status='+r.status);

const big=Buffer.concat([PNG,Buffer.alloc(2*1024*1024+16,0x00)]);
r=await up(new Blob([big],{type:'image/png'}),'big.png');
j=await r.json().catch(()=>({}));
ok('>2MB -> 413 avatar_too_large',r.status===413&&j.error==='avatar_too_large','status='+r.status+' '+JSON.stringify(j));

r=await up(new Blob([PNG],{type:'image/png'}),'anon.png',{});  // no session/csrf
ok('no auth -> 401',r.status===401,'status='+r.status);

console.log(`\n${p}/${p+f} PASS stamp=${stamp}`); process.exit(f?1:0);
