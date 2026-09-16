const signup = location.pathname === '/signup' || location.pathname === '/signup/' || location.pathname === '/signup.html' || new URLSearchParams(location.search).get('mode') === 'signup';
const byId = id => document.getElementById(id);
const defaultLabel = signup ? 'Send my setup link' : 'Send login link';
if (signup) {
  document.body.classList.remove('returning');
  document.title = 'Get started — Cadence.';
  // The welcome introduction is the page heading in this layout.
  const title = document.createElement('h2');
  title.id = 'form-title';
  title.textContent = 'Start with your email.';
  byId('form-title').replaceWith(title);
  byId('formEyebrow').textContent = 'Your first step';
  byId('formDescription').textContent = 'We’ll email you a secure link to get started. No password to create or remember.';
  byId('go').textContent = defaultLabel;
  byId('emailHint').textContent = 'Next: your profile, students and teaching term.';
  byId('switchMode').replaceChildren(document.createTextNode('Already use Cadence? '));
  const loginLink = document.createElement('a');
  loginLink.href = '/login.html';
  loginLink.textContent = 'Log in';
  byId('switchMode').append(loginLink);
}

// Preserve the existing return-from-Mail/session check, including home-screen use.
let recheckingSession = false;
async function recheckSessionOnReturn() {
  if (document.hidden || recheckingSession) return;
  recheckingSession = true;
  try {
    const res = await fetch('/api/me', {cache:'no-store'});
    if (res.ok) { location.href = '/'; return; }
  } catch { /* Keep the form available when offline. */ }
  finally { recheckingSession = false; }
}
document.addEventListener('visibilitychange', recheckSessionOnReturn);
window.addEventListener('pageshow', recheckSessionOnReturn);
window.addEventListener('focus', recheckSessionOnReturn);

let sentEmail = '';
let busy = false;
let retryAt = 0;
let cooldown;
function updateCooldown() {
  const remaining = Math.max(0, Math.ceil((retryAt - Date.now()) / 1000));
  byId('resend').disabled = busy || remaining > 0;
  byId('resend').textContent = busy ? 'Sending…' : remaining ? `Send again in ${remaining}s` : 'Send another link';
  if (!remaining) clearInterval(cooldown);
}
function startCooldown() {
  retryAt = Date.now() + 60000;
  clearInterval(cooldown);
  updateCooldown();
  cooldown = setInterval(updateCooldown, 1000);
}
async function requestLink(email, isResend = false) {
  if (busy) return;
  busy = true;
  const error = byId(isResend ? 'resendError' : 'err');
  error.textContent = '';
  byId('email').removeAttribute('aria-invalid');
  byId('go').disabled = true;
  byId('go').textContent = 'Sending…';
  byId('changeEmail').disabled = true;
  updateCooldown();
  try {
    const res = await fetch('/api/login', {
      method:'POST', headers:{'content-type':'application/json'},
      body:JSON.stringify({email, intent:signup ? 'signup' : 'login'}),
      signal:AbortSignal.timeout(20000)
    });
    let data;
    try { data = await res.json(); } catch { throw new Error('invalid-response'); }
    if (!res.ok) {
      error.textContent = data.error || 'Something went wrong. Please try again.';
      if (res.status === 400) byId('email').setAttribute('aria-invalid','true');
      if (res.status === 429 && isResend) startCooldown();
      return;
    }
    sentEmail = email;
    byId('sentMessage').replaceChildren(document.createTextNode(signup ? 'We’ve sent your setup link to ' : 'We’ve sent your login link to '));
    const address = document.createElement('span');
    address.className = 'sent-email';
    address.textContent = email;
    byId('sentMessage').append(address, document.createTextNode('. Open the email and select Continue to Cadence.'));
    byId('formPanel').hidden = true;
    byId('sentPanel').hidden = false;
    byId('sentTitle').textContent = isResend ? 'A fresh link is on its way.' : 'Check your inbox.';
    byId('sentTitle').focus();
    byId('resendError').textContent = '';
    startCooldown();
  } catch (err) {
    error.textContent = err.name === 'TimeoutError' ? 'This is taking longer than expected. Check your inbox before trying again.' : 'Couldn’t reach the server. Check your connection and try again.';
  } finally {
    busy = false;
    byId('go').disabled = false;
    byId('go').textContent = defaultLabel;
    byId('changeEmail').disabled = false;
    updateCooldown();
  }
}
byId('loginForm').addEventListener('submit', e => {
  e.preventDefault();
  const email = byId('email').value.trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    byId('err').textContent = 'Enter a valid email address.';
    byId('email').setAttribute('aria-invalid','true');
    byId('email').focus();
    return;
  }
  requestLink(email);
});
byId('resend').addEventListener('click', () => { if (Date.now() >= retryAt) requestLink(sentEmail, true); });
byId('changeEmail').addEventListener('click', () => {
  byId('sentPanel').hidden = true;
  byId('formPanel').hidden = false;
  byId('err').textContent = '';
  byId('email').focus();
});
