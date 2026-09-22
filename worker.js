/* ==================================================================
   Small helpers
================================================================== */

function json(obj, status = 200) {
  return new Response(typeof obj === "string" ? obj : JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}
function isValidJSON(s) {
  try { JSON.parse(s); return true; } catch (e) { return false; }
}
function slugify(name) {
  return name.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "") || "teacher";
}
function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return match ? decodeURIComponent(match[1]) : null;
}

const MIN_LESSON_MINUTES = 30;
const MAX_LESSON_MINUTES = 90;
const LESSON_STEP_MINUTES = 15;
function validLessonMinutes(value) {
  const minutes = Number(value);
  return Number.isInteger(minutes) && minutes >= MIN_LESSON_MINUTES &&
    minutes <= MAX_LESSON_MINUTES && minutes % LESSON_STEP_MINUTES === 0;
}
function replyLessonMinutes(reply) {
  if (validLessonMinutes(reply?.lessonMinutes)) return Number(reply.lessonMinutes);
  const legacy = Number(reply?.lesson);
  if (Number.isInteger(legacy) && legacy >= 1) {
    return Math.min(MAX_LESSON_MINUTES, Math.max(MIN_LESSON_MINUTES, legacy * 30));
  }
  return 60;
}

/* ==================================================================
   Sessions — a signed cookie, not a database-backed session table.
   Needs a SESSION_SECRET set as an encrypted variable on the Worker
   (Settings → Variables and Secrets) — any long random string, known
   only to Cloudflare, never committed to the repo.
================================================================== */

async function sign(value, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function makeSessionCookie(teacherId, env) {
  const account = await accountPreferences(env, teacherId);
  const payload = teacherId + "." + (Date.now() + 1000 * 60 * 60 * 24 * 30) + "." + account.session_version;
  const sig = await sign(payload, env.SESSION_SECRET);
  return payload + "." + sig;
}
async function verifySessionCookie(cookieVal, env) {
  if (!cookieVal) return null;
  const parts = cookieVal.split(".");
  if (parts.length !== 3 && parts.length !== 4) return null;
  const [teacherId, expiry] = parts;
  const sig = parts[parts.length - 1];
  const expected = await sign(parts.slice(0, -1).join("."), env.SESSION_SECRET);
  if (expected !== sig) return null;
  if (!Number.isFinite(Number(expiry)) || Date.now() > Number(expiry)) return null;
  const teacher = await env.DB.prepare("SELECT id FROM teachers WHERE id = ?").bind(Number(teacherId)).first();
  if (!teacher) return null;
  const account = await accountPreferences(env, Number(teacherId));
  if ((parts.length === 4 ? Number(parts[2]) : 0) !== account.session_version) return null;
  return Number(teacherId);
}
async function requireSession(request, env) {
  return await verifySessionCookie(getCookie(request, "session"), env);
}

// Separate from scheduling state: profile edits and session revocation must
// never replace student replies. Safe, additive setup for existing databases.
async function accountPreferences(env, teacherId) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS account_preferences (teacher_id INTEGER PRIMARY KEY, studio TEXT NOT NULL DEFAULT '', session_version INTEGER NOT NULL DEFAULT 0)").run();
  return await env.DB.prepare("SELECT studio, session_version FROM account_preferences WHERE teacher_id = ?").bind(teacherId).first() || { studio: "", session_version: 0 };
}

async function handleLogoutAll(request, env) {
  const teacherId = await requireSession(request, env);
  if (!teacherId) return json({ error: "not logged in" }, 401);
  await env.DB.batch([
    env.DB.prepare("INSERT INTO account_preferences (teacher_id, session_version) VALUES (?, 1) ON CONFLICT(teacher_id) DO UPDATE SET session_version = session_version + 1").bind(teacherId),
    env.DB.prepare("DELETE FROM login_tokens WHERE teacher_id = ?").bind(teacherId),
  ]);
  return handleLogout();
}

async function handleExport(request, env) {
  const teacherId = await requireSession(request, env);
  if (!teacherId) return json({ error: "not logged in" }, 401);
  const profile = await env.DB.prepare("SELECT name, instrument, slug, email FROM teachers WHERE id = ?").bind(teacherId).first();
  const account = await accountPreferences(env, teacherId);
  const row = await env.DB.prepare("SELECT data FROM app_state WHERE id = ?").bind(teacherId).first();
  return new Response(JSON.stringify({ format: "cadence-account-export", version: 1, exportedAt: new Date().toISOString(), profile: { ...profile, studio: account.studio }, state: row ? JSON.parse(row.data) : null }, null, 2), {
    headers: { "content-type": "application/json", "cache-control": "no-store", "content-disposition": 'attachment; filename="cadence-data.json"' }
  });
}

/* ==================================================================
   Auth routes
================================================================== */

function authJSON(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: {
    "content-type": "application/json", "cache-control": "no-store"
  }});
}
function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
async function handleLoginRequest(request, env, url) {
  let body;
  try { body = await request.json(); } catch { return authJSON({error:"Enter a valid email address."},400); }
  const email = typeof body?.email === "string" ? body.email.trim().toLowerCase() : "";
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return authJSON({error:"Enter a valid email address."},400);
  }
  let origin;
  try {
    const base = new URL(env.APP_ORIGIN);
    if (base.protocol !== "https:" || base.username || base.password) throw new Error();
    origin = base.origin;
  } catch { return authJSON({error:"Email login isn't ready yet. Please try again later."},503); }
  if (!env.RESEND_API_KEY || !env.EMAIL_FROM || !env.SESSION_SECRET) {
    return authJSON({error:"Email login isn't ready yet. Please try again later."},503);
  }
  if (request.headers.get("Origin") && request.headers.get("Origin") !== origin) {
    return authJSON({error:"Please request your link from the Cadence login page."},403);
  }
  await env.DB.prepare("INSERT OR IGNORE INTO teachers (email) VALUES (?)").bind(email).run();
  const teacher = await env.DB.prepare("SELECT id FROM teachers WHERE email = ?").bind(email).first();
  const token = randomToken();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
  // Atomic per-address cooldown, including attempts where delivery fails.
  const cutoff = new Date(Date.now() + 14 * 60 * 1000).toISOString();
  const inserted = await env.DB.prepare(`INSERT INTO login_tokens (token, teacher_id, expires_at, used)
    SELECT ?, ?, ?, 0 WHERE NOT EXISTS
    (SELECT 1 FROM login_tokens WHERE teacher_id = ? AND expires_at > ?)`)
    .bind(token, teacher.id, expiresAt, teacher.id, cutoff).run();
  if (!inserted.meta.changes) return authJSON({error:"Please wait a minute before requesting another link."},429);
  const link = origin + "/api/verify?token=" + encodeURIComponent(token);
  const safeLink = escapeHTML(link);
  const isSignup = body?.intent === "signup";
  const emailHeading = isSignup ? "Welcome to Cadence" : "Your login link";
  const emailIntro = isSignup ? "Your teaching space starts here. Continue to set up your profile, students and teaching term." : "Ready to organise your lessons? Continue to your teaching space.";
  try {
    const response = await fetch("https://api.resend.com/emails", {
      method:"POST",
      headers:{"Authorization":"Bearer " + env.RESEND_API_KEY,"Content-Type":"application/json"},
      signal:AbortSignal.timeout(15000),
      body:JSON.stringify({
        from:env.EMAIL_FROM, to:[email], subject:isSignup ? "Get started with Cadence" : "Your Cadence login link",
        text:emailHeading + "\n\n" + emailIntro + "\n\nOpen this link, then select Continue to Cadence:\n" + link +
          "\n\nThis link expires in 15 minutes and can only be used once. If you didn't request it, you can ignore this email.",
        html:'<!doctype html><html><body style="margin:0;background:#F2EFE7;color:#211C17;font-family:Arial,sans-serif;padding:32px 16px">' +
          '<div style="max-width:440px;margin:auto;background:#fff;border:1px solid #DCD5C6;border-radius:12px;padding:28px">' +
          '<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 6px">' +
          '<tr>' +
          '<td width="40" height="40" style="width:40px;height:40px;background-color:#6E1423;border-radius:9px" valign="middle">' +
					'<table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center"><tr>' +
					'<td width="6" height="22" style="width:6px;height:22px;line-height:22px;font-size:0;background-color:#F2EFE7;border-radius:2px">&nbsp;</td>' +
					'<td width="6" style="width:6px;font-size:0;line-height:0">&nbsp;</td>' +
					'<td width="12" height="22" style="width:12px;height:22px;line-height:22px;font-size:0;background-color:#F2EFE7;border-radius:3px">&nbsp;</td>' +
					'</tr></table>' +
					'</td>' +
					'<td width="10" style="width:10px;font-size:0;line-height:0">&nbsp;</td>' +
					'<td style="font-family:Georgia,serif;font-size:30px;font-weight:bold;color:#6E1423" valign="middle">Cadence.</td>' +
					'</tr></table>' +
          '<h1 style="font-size:21px;margin-top:28px">' + emailHeading + '</h1><p style="line-height:1.6">' + emailIntro + '</p>' +
          '<p style="margin:28px 0"><a href="' + safeLink + '" style="display:inline-block;background:#6E1423;color:white;text-decoration:none;padding:14px 22px;border-radius:7px;font-weight:bold">Continue to Cadence</a></p>' +
          '<p style="font-size:13px;line-height:1.6;color:#6B6157">This link expires in 15 minutes and can only be used once. If you didn’t request it, you can ignore this email.</p>' +
          '<p style="font-size:12px;line-height:1.6;word-break:break-all">Button not working? Open this link:<br><a href="' + safeLink + '">' + safeLink + '</a></p></div></body></html>'
      })
    });
    if (!response.ok) throw new Error("Email delivery rejected");
  } catch {
    await env.DB.prepare("UPDATE login_tokens SET used = 1 WHERE token = ?").bind(token).run();
    return authJSON({error:"We couldn't send your email. Please wait a minute and try again."},502);
  }
  return authJSON({ok:true});
}

async function handleVerify(request, url, env) {
  const headers = {"cache-control":"no-store", "referrer-policy":"strict-origin", "content-type":"text/html; charset=utf-8",
    "content-security-policy":"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"};
  const page = (body, status = 200) => new Response('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Log in — Cadence.</title><body style="background:#F2EFE7;color:#211C17;font:16px Arial,sans-serif;margin:0;padding:48px 24px"><main style="max-width:420px;margin:auto"><h1 style="font-family:Georgia,serif;color:#6E1423">Cadence.</h1>' + body + '</main></body></html>',{status,headers});
  let token = url.searchParams.get("token");
  if (request.method === "POST") {
    if (request.headers.get("Origin") && request.headers.get("Origin") !== url.origin) return page("Please open your email link again.",403);
    try { token = (await request.formData()).get("token"); } catch { token = null; }
  }
  const invalid = () => page('<p>This link has expired or has already been used.</p><p><a href="/login.html">Request a new login link</a></p>',400);
  if (typeof token !== "string" || !/^[A-Za-z0-9_-]{32}$/.test(token)) return invalid();
  const row = await env.DB.prepare("SELECT teacher_id, expires_at, used FROM login_tokens WHERE token = ?").bind(token).first();
  if (!row || row.used || new Date(row.expires_at).getTime() <= Date.now()) return invalid();
  // GET previews do not consume the token: mail scanners can safely open this page.
  if (request.method === "GET") return page('<p>Your secure link is ready. Continue to your teaching space.</p><form method="post" action="/api/verify"><input type="hidden" name="token" value="' + token + '"><button style="background:#6E1423;color:#fff;border:0;border-radius:7px;padding:14px 20px;font:inherit;cursor:pointer">Continue to Cadence</button></form>');
  const teacher = await env.DB.prepare("SELECT onboarded FROM teachers WHERE id = ?").bind(row.teacher_id).first();
  if (!teacher) return invalid();
  const cookieVal = await makeSessionCookie(row.teacher_id, env);
  // Only one concurrent request can redeem a token.
  const claimed = await env.DB.prepare("UPDATE login_tokens SET used = 1 WHERE token = ? AND used = 0 AND expires_at > ?")
    .bind(token,new Date().toISOString()).run();
  if (!claimed.meta.changes) return invalid();
  return new Response(null, {status:303,headers:{
    "Location":teacher.onboarded ? "/admin.html" : "/onboarding.html",
    "Cache-Control":"no-store", "Referrer-Policy":"no-referrer",
    "Set-Cookie":"session=" + cookieVal + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000"
  }});
}

function handleLogout() {
  const headers = new Headers();
  headers.append(
    "Set-Cookie",
    "session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
  );
  return new Response(null, { status: 204, headers });
}

async function handleMe(request, env) {
  const teacherId = await requireSession(request, env);
  if (!teacherId) return json({ error: "not logged in" }, 401);
  const t = await env.DB.prepare("SELECT name, instrument, slug, email FROM teachers WHERE id = ?").bind(teacherId).first();
  return json({ ...t, studio: (await accountPreferences(env, teacherId)).studio });
}

// Editing name/instrument from the Profile screen deliberately never
// touches the slug — that's baked into every student link already handed
// out, and silently changing it would break links a teacher has shared.
async function handleProfile(request, env) {
  const teacherId = await requireSession(request, env);
  if (!teacherId) return json({ error: "not logged in" }, 401);
  let body;
  try { body = JSON.parse(await request.text()); } catch (e) { return json({ error: "invalid json" }, 400); }
  if (!body || typeof body.name !== "string" || typeof body.instrument !== "string") return json({ error: "Enter both your name and instrument" }, 400);
  const name = (body.name || "").trim();
  const instrument = (body.instrument || "").trim();
  const studio = typeof body.studio === "string" ? body.studio.trim() : "";
  if (studio.length > 160) return json({ error: "Studio name must be 160 characters or fewer" }, 400);
  if (!name || !instrument) return json({ error: "Enter both your name and instrument" }, 400);
  await env.DB.batch([
    env.DB.prepare("UPDATE teachers SET name = ?, instrument = ? WHERE id = ?").bind(name, instrument, teacherId),
    env.DB.prepare("INSERT INTO account_preferences (teacher_id, studio) VALUES (?, ?) ON CONFLICT(teacher_id) DO UPDATE SET studio = excluded.studio").bind(teacherId, studio),
  ]);
  return json({ ok: true });
}

async function handleDeleteAccount(request, env) {
  const teacherId = await requireSession(request, env);
  if (!teacherId) return json({ error: "not logged in" }, 401);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM app_state WHERE id = ?").bind(teacherId),
    env.DB.prepare("DELETE FROM login_tokens WHERE teacher_id = ?").bind(teacherId),
    env.DB.prepare("DELETE FROM account_preferences WHERE teacher_id = ?").bind(teacherId),
    env.DB.prepare("DELETE FROM teachers WHERE id = ?").bind(teacherId),
  ]);
  const headers = new Headers({ "content-type": "application/json" });
  headers.append("Set-Cookie", "session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

async function handleOnboarding(request, env) {
  const teacherId = await requireSession(request, env);
  if (!teacherId) return json({ error: "not logged in" }, 401);
  let body;
  try { body = JSON.parse(await request.text()); } catch (e) { return json({ error: "invalid json" }, 400); }
  const name = (body.name || "").trim();
  const instrument = (body.instrument || "").trim();
  const students = Array.isArray(body.students) ? body.students.filter(s => s && s.name) : [];
  const termRangesIn = Array.isArray(body.termRanges) ? body.termRanges.filter(t => t && t.start && t.end) : [];
  const schedulingMode = body.schedulingMode === "rolling" ? "rolling" : "terms";
  if (!name || !instrument || !students.length) return json({ error: "Fill in your name, instrument and at least one student" }, 400);

  let slugBase = slugify(name), slug = slugBase, n = 2;
  while (true) {
    const clash = await env.DB.prepare("SELECT id FROM teachers WHERE slug = ? AND id != ?").bind(slug, teacherId).first();
    if (!clash) break;
    slug = slugBase + "-" + n; n++;
  }

  await env.DB.prepare("UPDATE teachers SET name = ?, instrument = ?, slug = ?, onboarded = 1 WHERE id = ?")
    .bind(name, instrument, slug, teacherId).run();

  // A teacher who chose rolling weeks sent an intentionally empty
  // termRanges array — that's a real choice, not a missing-data case, so
  // it must not fall back to the default term dates the way a genuinely
  // empty submission from the term-dates form would.
  const termRanges = schedulingMode === "rolling"
    ? []
    : (termRangesIn.length ? termRangesIn.map(t => ({ start: t.start, end: t.end })) : [{ start: "2026-09-14", end: "2026-12-04" }]); // defensive fallback — the onboarding form always sends real dates

  const initialState = {
    tab: "week",
    students: students.map((s, i) => ({
      id: "s" + i + "-" + Date.now(), name: s.name, course: "", allocated: Number(s.allocated) || 0,
    })),
    week: 1,
    weeksCompleted: 0,
    termRanges,
    settings: {
      includeWeekends: false,
      dayStartHour: 9,
      dayEndHour: 19,
      priorityOrder: ["days", "preference", "gaps"],
      schedulingMode,
      cancellationWindowHours: 24,
    },
    rounds: {},
    log: [],
    draft: { date: new Date().toISOString().slice(0, 10), hours: 1 },
  };
  await env.DB.prepare(
    `INSERT INTO app_state (id, data, updated_at) VALUES (?, ?, datetime('now'))
     ON CONFLICT(id) DO NOTHING`
  ).bind(teacherId, JSON.stringify(initialState)).run();

  return json({ ok: true, slug });
}

/* ==================================================================
   Admin state — same JSON-blob pattern as before, just keyed by the
   logged-in teacher's id instead of a fixed row.
================================================================== */

function revisionOf(state) {
  return Number.isSafeInteger(state?._revision) ? state._revision : 0;
}
function publicAdminState(state) {
  const copy = JSON.parse(JSON.stringify(state || {}));
  copy._revision = revisionOf(state);
  delete copy._replyHistory;
  for (const rnd of Object.values(copy.rounds || {})) {
    for (const [id, reply] of Object.entries(rnd.replies || {})) {
      if (reply.status === "clear") delete rnd.replies[id];
    }
  }
  return copy;
}
async function handleState(request, env, teacherId) {
  const row = await env.DB.prepare("SELECT data FROM app_state WHERE id = ?").bind(teacherId).first();
  const current = row ? JSON.parse(row.data) : {};
  const revision = revisionOf(current);
  if (request.method === "GET") {
    const response = json(publicAdminState(current));
    response.headers.set("x-cadence-state-protocol", "2");
    return response;
  }
  if (request.method !== "POST") return json({error:"Method not allowed"},405);
  // Old browser builds do not send this precondition: they must never write.
  if (request.headers.get("if-match") == null) return json({error:"Reload Cadence before saving."},428);
  if (request.headers.get("if-match") !== '"' + revision + '"') {
    return json({error:"The saved data has changed. Reload the latest version."},409);
  }
  let next;
  try { next = await request.json(); } catch { return json({error:"Invalid JSON"},400); }
  if (!next || Array.isArray(next) || !Array.isArray(next.students) ||
      !next.rounds || typeof next.rounds !== "object" || Array.isArray(next.rounds)) {
    return json({error:"Invalid state"},400);
  }
  const history = Array.isArray(current._replyHistory) ? current._replyHistory.slice() : [];
  for (const [week, rnd] of Object.entries(next.rounds)) {
    if (!rnd || !Array.isArray(rnd.offered) || !rnd.replies || typeof rnd.replies !== "object") {
      return json({error:"Invalid round"},400);
    }
    // Only explicit teacher-entered replies come from the admin payload.
    const incoming = rnd.replies;
    rnd.replies = Object.fromEntries(Object.entries(incoming).filter(([,r]) => r && r.source === "admin"));
    const previousRound = current.rounds?.[week];
    if (previousRound && previousRound.weekStart === rnd.weekStart) {
      for (const [id, reply] of Object.entries(previousRound.replies || {})) {
        if (reply.source === "admin") continue;
        if (reply.status === "clear" && rnd.replies[id]?.source === "admin") continue;
        rnd.replies[id] = reply;
        // Teachers can still adjust lesson duration, but not student availability.
        const lessonMinutes = Number(incoming[id]?.lessonMinutes);
        if (reply.status !== "clear" && validLessonMinutes(lessonMinutes) && lessonMinutes !== replyLessonMinutes(reply)) {
          rnd.replies[id] = {...reply, lessonMinutes};
          delete rnd.replies[id].lesson;
          history.push({week,studentId:id,action:"teacher-duration",at:new Date().toISOString(),previous:reply,reply:rnd.replies[id]});
        }
      }
    }
  }
  // Retain replies removed by an intentional week/year reset for diagnosis.
  for (const [week, rnd] of Object.entries(current.rounds || {})) {
    if (!next.rounds[week] || next.rounds[week].weekStart !== rnd.weekStart) {
      for (const [id, reply] of Object.entries(rnd.replies || {})) {
        if (reply.source !== "admin") history.push({week,weekStart:rnd.weekStart,studentId:id,action:"round-reset",at:new Date().toISOString(),previous:reply});
      }
    }
  }
  next._replyHistory = history;
  next._revision = revision + 1;
  const encoded = JSON.stringify(next);
  const result = row
    ? await env.DB.prepare("UPDATE app_state SET data = ?, updated_at = datetime('now') WHERE id = ? AND data = ?").bind(encoded,teacherId,row.data).run()
    : await env.DB.prepare("INSERT INTO app_state (id,data,updated_at) VALUES (?,?,datetime('now')) ON CONFLICT(id) DO NOTHING").bind(teacherId,encoded).run();
  if (result.meta.changes !== 1) return json({error:"Another save arrived first. Reload the latest version."},409);
  return json({ok:true,revision:next._revision});
}

/* ==================================================================
   Public student routes — looked up by slug, not by session
================================================================== */

async function handleRound(url, env) {
  const slug = url.searchParams.get("slug") || "";
  const weekParam = url.searchParams.get("week");
  const teacher = await env.DB.prepare("SELECT id, name, instrument FROM teachers WHERE slug = ?").bind(slug).first();
  if (!teacher) return json({ weekNo: null, weekStart: null, offered: [], students: [], teacherName: null, instrument: null });

  const row = await env.DB.prepare("SELECT data FROM app_state WHERE id = ?").bind(teacher.id).first();
  const state = row ? JSON.parse(row.data) : null;
  const weekNo = weekParam ? Number(weekParam) : (state ? state.week : 1);
  const rnd = state && state.rounds ? state.rounds[String(weekNo)] : null;
  const replies = (rnd && rnd.replies) || {};
  return json({
    weekNo,
    weekStart: rnd ? rnd.weekStart : null,
    offered: (rnd && rnd.offered) || [],
    includeWeekends: rnd ? !!rnd.includeWeekends : false,
    dayStartHour: rnd && rnd.dayStartHour != null ? rnd.dayStartHour : 9,
    dayEndHour: rnd && rnd.dayEndHour != null ? rnd.dayEndHour : 19,
    accent: ["oxblood", "midnight", "forest", "plum", "slate"].includes(state?.settings?.accent) ? state.settings.accent : "oxblood",
    teacherName: teacher.name,
    studio: (await accountPreferences(env, teacher.id)).studio,
    instrument: teacher.instrument,
    students: ((state && state.students) || []).map((s) => {
      const r = replies[s.id]?.status === "clear" ? null : replies[s.id];
      return { id: s.id, name: s.name, status: r ? r.status : null, avail: r ? r.avail : [], lessonMinutes: replyLessonMinutes(r) };
    }),
  });
}

function replyNotificationHTML({ heading, intro, detail, progress, link }) {
  const safeHeading = escapeHTML(heading);
  const safeIntro = escapeHTML(intro);
  const safeDetail = escapeHTML(detail);
  const safeProgress = escapeHTML(progress);
  const safeLink = escapeHTML(link);
  return '<!doctype html><html><body style="margin:0;background:#F2EFE7;color:#211C17;font-family:Arial,sans-serif;padding:32px 16px">' +
    '<div style="max-width:440px;margin:auto;background:#fff;border:1px solid #DCD5C6;border-radius:12px;padding:28px">' +
    '<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 6px"><tr>' +
    '<td width="40" height="40" style="width:40px;height:40px;background-color:#6E1423;border-radius:9px" valign="middle">' +
    '<table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center"><tr>' +
    '<td width="6" height="22" style="width:6px;height:22px;line-height:22px;font-size:0;background-color:#F2EFE7;border-radius:2px">&nbsp;</td>' +
    '<td width="6" style="width:6px;font-size:0;line-height:0">&nbsp;</td>' +
    '<td width="12" height="22" style="width:12px;height:22px;line-height:22px;font-size:0;background-color:#F2EFE7;border-radius:3px">&nbsp;</td>' +
    '</tr></table></td><td width="10" style="width:10px;line-height:0;font-size:0">&nbsp;</td>' +
    '<td style="font-family:Georgia,serif;font-size:30px;font-weight:bold;color:#6E1423" valign="middle">Cadence.</td>' +
    '</tr></table>' +
    '<h1 style="font-size:21px;margin:28px 0 10px;line-height:1.3">' + safeHeading + '</h1>' +
    '<p style="line-height:1.6;margin:0 0 20px">' + safeIntro + '</p>' +
    '<div style="background:#F2EFE7;border:1px solid #DCD5C6;border-radius:8px;padding:14px 16px">' +
    '<p style="font-size:12px;font-weight:bold;letter-spacing:.04em;text-transform:uppercase;color:#6E1423;margin:0 0 6px">' + safeProgress + '</p>' +
    '<p style="font-size:14px;line-height:1.5;margin:0;color:#211C17">' + safeDetail + '</p></div>' +
    (link ? '<p style="margin:28px 0 4px"><a href="' + safeLink + '" style="display:inline-block;background:#6E1423;color:#fff;text-decoration:none;padding:14px 22px;border-radius:7px;font-weight:bold">View replies</a></p>' : '') +
    '<p style="font-size:12px;line-height:1.6;color:#6B6157;margin:25px 0 0">You’re receiving this because email notifications are enabled in Cadence Settings.</p>' +
    '</div></body></html>';
}

async function sendReplyNotifications(env, teacher, state, round, student, status, previous, week, firstComplete) {
  const prefs = state.settings?.emailNotifications || {};
  const submission = prefs.onSubmission === true;
  const completion = firstComplete && prefs.allSubmitted === true;
  if ((!submission && !completion) || !teacher.email || !env.RESEND_API_KEY || !env.EMAIL_FROM) return;
  const total = (state.students || []).length;
  const replies = round.replies || {};
  const count = (state.students || []).filter(s =>
    (s.id === student.id ? status : replies[s.id]?.status) &&
    (s.id === student.id ? status : replies[s.id]?.status) !== "clear").length;
  const weekLabel = round.weekStart ? `Week ${week} (${round.weekStart})` : `Week ${week}`;
  const names = (state.students || []).filter(s =>
    (s.id === student.id ? status : replies[s.id]?.status) &&
    (s.id === student.id ? status : replies[s.id]?.status) !== "clear").map(s => s.name);
  const base = (() => { try { return new URL(env.APP_ORIGIN).origin; } catch { return ""; } })();
  const link = base ? base + "/admin.html" : "";
  const messages = [];
  if (submission) messages.push({
    subject: `${student.name} submitted availability · Cadence`,
    text: `${student.name} ${previous && previous.status !== "clear" ? "updated their response" : "submitted a response"} for ${weekLabel}.\nResponse: ${status === "in" ? "Available" : status === "skip" ? "Skipping this week" : "No availability"}.\n${count} of ${total} students have responded.${link ? "\n\nView replies: " + link : ""}`,
    html: replyNotificationHTML({
      heading: previous && previous.status !== "clear" ? `${student.name} updated their response` : `${student.name} has replied`,
      intro: `${student.name} submitted their response for ${weekLabel}.`,
      progress: `${count} of ${total} students responded`,
      detail: `Response: ${status === "in" ? "Available" : status === "skip" ? "Skipping this week" : "No availability"}`,
      link,
    }),
  });
  if (completion) messages.push({
    subject: `All students have submitted · ${weekLabel} · Cadence`,
    text: `All ${total} students have responded for ${weekLabel}.\n\n${names.join(", ")}${link ? "\n\nView replies: " + link : ""}`,
    html: replyNotificationHTML({
      heading: "Everyone has replied",
      intro: `All students have submitted their responses for ${weekLabel}.`,
      progress: `${total} of ${total} students responded`,
      detail: names.join(", "),
      link,
    }),
  });
  await Promise.all(messages.map(async message => {
    try {
      const response = await fetch("https://api.resend.com/emails", {
        method: "POST", headers: { Authorization: "Bearer " + env.RESEND_API_KEY, "Content-Type": "application/json" },
        body: JSON.stringify({ from: env.EMAIL_FROM, to: [teacher.email], ...message }),
      });
      if (!response.ok) console.error("Cadence reply notification failed", response.status);
    } catch (error) { console.error("Cadence reply notification failed", error); }
  }));
}

async function handleReply(request, env, ctx) {
  let body;
  try { body = await request.json(); } catch { return json({error:"Invalid JSON"},400); }
  const {slug,week,studentId,status,avail,lessonMinutes,lesson} = body || {};
  if (typeof slug !== "string" || typeof studentId !== "string" ||
      !Number.isSafeInteger(Number(week)) || Number(week) < 1 ||
      !["in","skip","none","clear"].includes(status) || !Array.isArray(avail)) return json({error:"Invalid reply"},400);
  const teacher = await env.DB.prepare("SELECT id, email FROM teachers WHERE slug = ?").bind(slug).first();
  if (!teacher) return json({error:"Unknown studio"},404);
  const wk = String(Number(week));
  for (let attempt = 0; attempt < 6; attempt++) {
    const row = await env.DB.prepare("SELECT data FROM app_state WHERE id = ?").bind(teacher.id).first();
    if (!row) return json({error:"Schedule not found. Reload the page."},409);
    const state = JSON.parse(row.data);
    const rnd = state.rounds?.[wk];
    if (!rnd || rnd.notTeaching || !(state.students || []).some(s => s.id === studentId)) {
      return json({error:"This schedule has changed. Reload the page."},409);
    }
    const offered = new Set(rnd.offered || []);
    if (status === "in" && (!avail.length || avail.some(k => typeof k !== "string" || !offered.has(k)))) {
      return json({error:"The offered times have changed. Reload before submitting."},409);
    }
    const previous = rnd.replies?.[studentId] || null;
    const requestedMinutes = validLessonMinutes(lessonMinutes)
      ? Number(lessonMinutes)
      : (Number.isInteger(Number(lesson)) ? Math.min(MAX_LESSON_MINUTES, Number(lesson) * 30) : null);
    const durationMinutes = validLessonMinutes(requestedMinutes) ? requestedMinutes : replyLessonMinutes(previous);
    const at = new Date().toISOString();
    // Clear is a server-side tombstone, so an older admin cannot resurrect it.
    const reply = {status,avail:status === "in" ? [...new Set(avail)] : [],lessonMinutes:durationMinutes,source:"student",updatedAt:at};
    const event = {week:wk,weekStart:rnd.weekStart,studentId,action:status,at,previous,reply};
    // Bind JSON paths; never interpolate user data into SQL.
    const path = '$.rounds.' + JSON.stringify(wk) + '.replies.' + JSON.stringify(studentId);
    const result = await env.DB.prepare(
      "UPDATE app_state SET data = json_insert(json_set(data, ?, json(?), '$._revision', ?, '$._replyHistory', json(COALESCE(json_extract(data, '$._replyHistory'), '[]'))), '$._replyHistory[#]', json(?)), updated_at = datetime('now') WHERE id = ? AND data = ?"
    ).bind(path,JSON.stringify(reply),revisionOf(state)+1,JSON.stringify(event),teacher.id,row.data).run();
    if (result.meta.changes === 1) {
      if (status !== "clear") {
        const student = state.students.find(s => s.id === studentId);
        const allBefore = state.students.length > 0 && state.students.every(s =>
          rnd.replies?.[s.id]?.status && rnd.replies[s.id].status !== "clear");
        const allAfter = state.students.every(s => s.id === studentId ||
          (rnd.replies?.[s.id]?.status && rnd.replies[s.id].status !== "clear"));
        ctx.waitUntil(sendReplyNotifications(env, teacher, state, rnd, student, status, previous, wk, !allBefore && allAfter));
      }
      return json({ok:true,updatedAt:at});
    }
    // A concurrent reply/admin save won. Re-read and retry the individual reply.
  }
  return json({error:"The schedule is busy. Please submit again."},409);
}

/* ==================================================================
   Routing
================================================================== */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Keep www on the same host as emailed links and the host-only session cookie.
    if (env.APP_ORIGIN) {
      const canonical = new URL(env.APP_ORIGIN);
      if (url.hostname === "www." + canonical.hostname) {
        const destination = new URL(url.pathname + url.search, canonical.origin);
        return new Response(null, {status:307, headers:{
          "Location":destination.href, "Cache-Control":"no-store"
        }});
      }
    }

    // Public entry pages share authentication, but explain each journey separately.
    // Keep the student index and /s/... routes independent from the welcome page.
    if (["GET", "HEAD"].includes(request.method) &&
        ["/", "/welcome", "/welcome.html", "/login", "/login.html", "/signup", "/signup/", "/signup.html"].includes(path)) {
      const teacherId = await requireSession(request, env);
      const teacher = teacherId
        ? await env.DB.prepare("SELECT onboarded FROM teachers WHERE id = ?").bind(teacherId).first()
        : null;
      if (teacher) {
        const destination = teacher.onboarded ? "/admin.html" : "/onboarding.html";
        return new Response(null, {status:302, headers:{
          "Location":new URL(destination, url).href, "Cache-Control":"no-store"
        }});
      }
      const asset = ["/", "/welcome", "/welcome.html"].includes(path) ? "/welcome.html" : "/login.html";
      const res = await env.ASSETS.fetch(new Request(new URL(asset, url), request));
      const headers = new Headers(res.headers);
      headers.set("Cache-Control", "no-store");
      return new Response(request.method === "HEAD" ? null : res.body, {status:res.status, headers});
    }

    if (path === "/api/login" && request.method === "POST") return handleLoginRequest(request, env, url);
    if (path === "/api/verify" && ["GET", "POST"].includes(request.method)) return handleVerify(request, url, env);
    if (path === "/api/logout" && request.method === "POST") return handleLogout();
    if (path === "/api/logout-all" && request.method === "POST") return handleLogoutAll(request, env);
    if (path === "/api/export" && request.method === "GET") return handleExport(request, env);
    if (path === "/api/me" && request.method === "GET") return handleMe(request, env);
    if (path === "/api/profile" && request.method === "POST") return handleProfile(request, env);
    if (path === "/api/account" && request.method === "DELETE") return handleDeleteAccount(request, env);
    if (path === "/api/onboarding" && request.method === "POST") return handleOnboarding(request, env);

    if (path === "/api/state") {
      const teacherId = await requireSession(request, env);
      if (!teacherId) return json({ error: "not logged in" }, 401);
      return handleState(request, env, teacherId);
    }

    if (path === "/api/round" && request.method === "GET") return handleRound(url, env);
    if (path === "/api/reply" && request.method === "POST") return handleReply(request, env, ctx);

    // Protected pages — the Worker checks the session before deciding
    // whether to hand back the real page or send them to log in.
    // Cache-Control: no-store on both of these matters specifically for
    // sign-out — it's what stops the browser from serving a frozen
    // bfcache snapshot of the logged-in page when someone hits Back
    // after signing out. Without it, requireSession above still runs
    // correctly on every real navigation, but the browser can skip that
    // navigation entirely and show the old page from memory instead.
    if (path === "/admin.html" || path === "/admin") {
      const teacherId = await requireSession(request, env);
      if (!teacherId) return Response.redirect(url.origin + "/login.html", 302);
      const res = await env.ASSETS.fetch(new Request(new URL("/admin.html", url), request));
      const headers = new Headers(res.headers);
      headers.set("Cache-Control", "no-store");
      return new Response(res.body, { status: res.status, headers });
    }
    if (path === "/onboarding.html" || path === "/onboarding") {
      const teacherId = await requireSession(request, env);
      if (!teacherId) return Response.redirect(url.origin + "/login.html", 302);
      const res = await env.ASSETS.fetch(new Request(new URL("/onboarding.html", url), request));
      const headers = new Headers(res.headers);
      headers.set("Cache-Control", "no-store");
      return new Response(res.body, { status: res.status, headers });
    }

    // Student links: /s/<slug>/<week> — always the same page underneath
    // (slug and week are read client-side from the URL for the app
    // itself), but the raw HTML is rewritten per request so a pasted link
    // unfurls with the teacher's name, the specific week, and a branded
    // image, rather than the bare static <title> every link would
    // otherwise share.
    if (path.startsWith("/s/")) {
      const parts = path.split("/").filter(Boolean); // ["s", slug, week]
      const slug = parts[1] || "";
      const week = parts[2] || "";
      const teacher = slug
        ? await env.DB.prepare("SELECT name, instrument FROM teachers WHERE slug = ?").bind(slug).first()
        : null;

      const assetResponse = await env.ASSETS.fetch(new Request(new URL("/index.html", url), request));
      let html = await assetResponse.text();

      const title = teacher
        ? "Week " + week + " \u2014 " + teacher.instrument + " Lessons with " + teacher.name
        : "Cadence. \u2014 Week " + week;
      const description = teacher
        ? "Let " + teacher.name + " know your availability for week " + week + "."
        : "Give your teacher your availability for week " + week + ".";
      const ogImage = url.origin + "/og-image.png";

      html = html
        .replace(/<title>.*?<\/title>/, "<title>" + escapeHTML(title) + "</title>")
        .replace(
          "</head>",
          '<meta property="og:type" content="website">\n' +
          '<meta property="og:title" content="' + escapeHTML(title) + '">\n' +
          '<meta property="og:description" content="' + escapeHTML(description) + '">\n' +
          '<meta property="og:image" content="' + ogImage + '">\n' +
          '<meta property="og:url" content="' + escapeHTML(url.origin + path) + '">\n' +
          '<meta name="twitter:card" content="summary_large_image">\n' +
          '<meta name="twitter:title" content="' + escapeHTML(title) + '">\n' +
          '<meta name="twitter:description" content="' + escapeHTML(description) + '">\n' +
          '<meta name="twitter:image" content="' + ogImage + '">\n' +
          "</head>"
        );

      return new Response(html, { headers: { "content-type": "text/html;charset=UTF-8" } });
    }


    return env.ASSETS.fetch(request);
  },
};
