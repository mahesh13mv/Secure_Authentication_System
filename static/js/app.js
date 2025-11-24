// static/js/app.js
async function api(path, opts={}){
  const res = await fetch(path, opts);
  try{ return await res.json(); }catch(e){ return {} }
}

// register
const registerBtn = document.getElementById('registerBtn');
if(registerBtn){
  registerBtn.addEventListener('click', async ()=>{
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const msg = document.getElementById('msg');
    const res = await api('/api/auth/register', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ email, password }) });
    if(res.error) msg.innerText = res.error; else msg.innerText = 'Registered successfully. Go to login.';
  });
}

// login
const loginBtn = document.getElementById('loginBtn');
if(loginBtn){
  loginBtn.addEventListener('click', async ()=>{
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const msg = document.getElementById('msg');
    const res = await api('/api/auth/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ email, password }) });
    if(res.error) { msg.innerText = res.error; return; }
    if(res.mfa_required){ msg.innerText = 'MFA required. Short token: ' + res.token; return; }
    if(res.token){ localStorage.setItem('token', res.token); window.location='/dashboard'; }
  });
}

// MFA setup
const genQr = document.getElementById('genQr');
if(genQr){
  genQr.addEventListener('click', async ()=>{
    const token = document.getElementById('token').value;
    const msg = document.getElementById('msg');
    const res = await api('/api/auth/mfa/setup', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ token }) });
    if(res.error) { msg.innerText = res.error; return; }
    // show QR by requesting the /mfa/qr endpoint
    try{
      const payload = JSON.parse(atob(token.split('.')[1]));
      const img = document.createElement('img');
      img.src = '/api/auth/mfa/qr/' + payload.id;
      img.style.maxWidth = '240px';
      document.getElementById('qr').innerHTML = '';
      document.getElementById('qr').appendChild(img);
      msg.innerText = 'Scan QR with authenticator and enter code to verify.';
    }catch(e){
      msg.innerText = 'Invalid token or error generating QR.';
    }
  });
}

const verifyBtn = document.getElementById('verify');
if(verifyBtn){
  verifyBtn.addEventListener('click', async ()=>{
    const token = document.getElementById('token').value;
    const code = document.getElementById('code').value;
    const msg = document.getElementById('msg');
    const res = await api('/api/auth/mfa/verify', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ token, code }) });
    if(res.error) { msg.innerText = res.error; return; }
    localStorage.setItem('token', res.token);
    window.location = '/dashboard';
  });
}

// dashboard
const info = document.getElementById('info');
if(info){
  const token = localStorage.getItem('token');
  if(!token){ info.innerText = 'Not logged in'; }
  else{
    fetch('/api/auth/me', { headers: { 'Authorization': 'Bearer ' + token } }).then(r=>r.json()).then(res=>{
      if(res.error) { info.innerText = res.error; return; }
      info.innerText = JSON.stringify(res.user, null, 2);
    });
  }
}

const logout = document.getElementById('logout');
if(logout) logout.addEventListener('click', ()=>{ localStorage.removeItem('token'); window.location = '/'; });
