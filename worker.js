/* ==================================================================
   Small helpers
================================================================== */

function json(obj, status = 200) {
  return new Response(typeof obj === "string" ? obj : JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
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
  const payload = teacherId + "." + (Date.now() + 1000 * 60 * 60 * 24 * 30); // 30 days
  const sig = await sign(payload, env.SESSION_SECRET);
  return payload + "." + sig;
}
async function verifySessionCookie(cookieVal, env) {
  if (!cookieVal) return null;
  const parts = cookieVal.split(".");
  if (parts.length !== 3) return null;
  const [teacherId, expiry, sig] = parts;
  const expected = await sign(teacherId + "." + expiry, env.SESSION_SECRET);
  if (expected !== sig) return null;
  if (Date.now() > Number(expiry)) return null;
  return Number(teacherId);
}
async function requireSession(request, env) {
  return await verifySessionCookie(getCookie(request, "session"), env);
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
  try {
    const response = await fetch("https://api.resend.com/emails", {
      method:"POST",
      headers:{"Authorization":"Bearer " + env.RESEND_API_KEY,"Content-Type":"application/json"},
      signal:AbortSignal.timeout(15000),
      body:JSON.stringify({
        from:env.EMAIL_FROM, to:[email], subject:"Your Cadence login link",
        text:"Log in to Cadence\n\nOpen this link, then select Continue to Cadence:\n" + link +
          "\n\nThis link expires in 15 minutes and can only be used once. If you didn't request it, you can ignore this email.",
        html:'<!doctype html><html><body style="margin:0;background:#F2EFE7;color:#211C17;font-family:Arial,sans-serif;padding:32px 16px">' +
          '<div style="max-width:440px;margin:auto;background:#fff;border:1px solid #DCD5C6;border-radius:12px;padding:28px">' +
          '<div style="font-family:Georgia,serif;font-size:30px;font-weight:bold;color:#6E1423">Cadence.</div>' +
          '<h1 style="font-size:21px;margin-top:28px">Your login link</h1><p style="line-height:1.6">Ready to organise your lessons? Tap below to continue.</p>' +
          '<p style="margin:28px 0"><a href="' + safeLink + '" style="display:inline-block;background:#6E1423;color:white;text-decoration:none;padding:14px 22px;border-radius:7px;font-weight:bold">Log in to Cadence</a></p>' +
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
  if (request.method === "GET") return page('<p>Your login link is ready.</p><form method="post" action="/api/verify"><input type="hidden" name="token" value="' + token + '"><button style="background:#6E1423;color:#fff;border:0;border-radius:7px;padding:14px 20px;font:inherit;cursor:pointer">Continue to Cadence</button></form>');
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
  return json(t || {});
}

// Editing name/instrument from the Profile screen deliberately never
// touches the slug — that's baked into every student link already handed
// out, and silently changing it would break links a teacher has shared.
async function handleProfile(request, env) {
  const teacherId = await requireSession(request, env);
  if (!teacherId) return json({ error: "not logged in" }, 401);
  let body;
  try { body = JSON.parse(await request.text()); } catch (e) { return json({ error: "invalid json" }, 400); }
  const name = (body.name || "").trim();
  const instrument = (body.instrument || "").trim();
  if (!name || !instrument) return json({ error: "Enter both your name and instrument" }, 400);
  await env.DB.prepare("UPDATE teachers SET name = ?, instrument = ? WHERE id = ?").bind(name, instrument, teacherId).run();
  return json({ ok: true });
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
  if (!name || !instrument || !students.length) return json({ error: "Fill in your name, instrument and at least one student" }, 400);

  let slugBase = slugify(name), slug = slugBase, n = 2;
  while (true) {
    const clash = await env.DB.prepare("SELECT id FROM teachers WHERE slug = ? AND id != ?").bind(slug, teacherId).first();
    if (!clash) break;
    slug = slugBase + "-" + n; n++;
  }

  await env.DB.prepare("UPDATE teachers SET name = ?, instrument = ?, slug = ?, onboarded = 1 WHERE id = ?")
    .bind(name, instrument, slug, teacherId).run();

  const termRanges = termRangesIn.length
    ? termRangesIn.map(t => ({ start: t.start, end: t.end }))
    : [{ start: "2026-09-14", end: "2026-12-04" }]; // defensive fallback — the onboarding form always sends real dates

  const initialState = {
    tab: "week",
    students: students.map((s, i) => ({
      id: "s" + i + "-" + Date.now(), name: s.name, course: "", allocated: Number(s.allocated) || 0,
    })),
    week: 1,
    weeksCompleted: 0,
    termRanges,
    rounds: {},
    log: [],
    draft: { date: new Date().toISOString().slice(0, 10), hours: 1 },
  };
  await env.DB.prepare(
    `INSERT INTO app_state (id, data, updated_at) VALUES (?, ?, datetime('now'))
     ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`
  ).bind(teacherId, JSON.stringify(initialState)).run();

  return json({ ok: true, slug });
}

/* ==================================================================
   Admin state — same JSON-blob pattern as before, just keyed by the
   logged-in teacher's id instead of a fixed row.
================================================================== */

async function handleState(request, env, teacherId) {
  if (request.method === "GET") {
    const row = await env.DB.prepare("SELECT data FROM app_state WHERE id = ?").bind(teacherId).first();
    return json(row ? row.data : "null");
  }
  if (request.method === "POST") {
    const body = await request.text();
    if (!isValidJSON(body)) return json({ error: "invalid json" }, 400);
    await env.DB.prepare(
      `INSERT INTO app_state (id, data, updated_at) VALUES (?, ?, datetime('now'))
       ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`
    ).bind(teacherId, body).run();
    return json({ ok: true });
  }
  return new Response("Method not allowed", { status: 405 });
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
    teacherName: teacher.name,
    instrument: teacher.instrument,
    students: ((state && state.students) || []).map((s) => {
      const r = replies[s.id];
      return { id: s.id, name: s.name, status: r ? r.status : null, avail: r ? r.avail : [], lesson: r ? (r.lesson || 2) : 2 };
    }),
  });
}

async function handleReply(request, env) {
  let body;
  try { body = JSON.parse(await request.text()); } catch (e) { return json({ error: "invalid json" }, 400); }
  const { slug, week, studentId, status, avail, lesson } = body || {};
  if (!slug || !week || !studentId || !["in", "skip", "none", "clear"].includes(status) || !Array.isArray(avail)) {
    return json({ error: "invalid reply" }, 400);
  }
  const teacher = await env.DB.prepare("SELECT id FROM teachers WHERE slug = ?").bind(slug).first();
  if (!teacher) return json({ error: "unknown studio" }, 404);

  const row = await env.DB.prepare("SELECT data FROM app_state WHERE id = ?").bind(teacher.id).first();
  const state = row ? JSON.parse(row.data) : {};
  state.rounds = state.rounds || {};
  const wk = String(week);
  state.rounds[wk] = state.rounds[wk] || { weekStart: null, offered: [], replies: {}, plan: null, result: null, chosen: 0 };
  state.rounds[wk].replies = state.rounds[wk].replies || {};

  // If status is "clear", delete the reply entirely instead of storing a cleared response
  if (status === "clear") {
    delete state.rounds[wk].replies[studentId];
  } else {
    const prevLesson = (state.rounds[wk].replies[studentId] && state.rounds[wk].replies[studentId].lesson) || 2;
    const requestedLesson = Number(lesson);
    const validLesson = Number.isInteger(requestedLesson) && requestedLesson >= 1 && requestedLesson <= 4 ? requestedLesson : prevLesson;
    state.rounds[wk].replies[studentId] = { status, avail, lesson: validLesson };
  }

  await env.DB.prepare(
    `INSERT INTO app_state (id, data, updated_at) VALUES (?, ?, datetime('now'))
     ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`
  ).bind(teacher.id, JSON.stringify(state)).run();
  return json({ ok: true });
}

/* ==================================================================
   Routing
================================================================== */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/api/login" && request.method === "POST") return handleLoginRequest(request, env, url);
    if (path === "/api/verify" && ["GET", "POST"].includes(request.method)) return handleVerify(request, url, env);
    if (path === "/api/logout" && request.method === "POST") return handleLogout();
    if (path === "/api/me" && request.method === "GET") return handleMe(request, env);
    if (path === "/api/profile" && request.method === "POST") return handleProfile(request, env);
    if (path === "/api/onboarding" && request.method === "POST") return handleOnboarding(request, env);

    if (path === "/api/state") {
      const teacherId = await requireSession(request, env);
      if (!teacherId) return json({ error: "not logged in" }, 401);
      return handleState(request, env, teacherId);
    }

    if (path === "/api/round" && request.method === "GET") return handleRound(url, env);
    if (path === "/api/reply" && request.method === "POST") return handleReply(request, env);

    // Protected pages — the Worker checks the session before deciding
    // whether to hand back the real page or send them to log in.
    if (path === "/admin.html" || path === "/admin") {
      const teacherId = await requireSession(request, env);
      if (!teacherId) return Response.redirect(url.origin + "/login.html", 302);
      return env.ASSETS.fetch(new Request(new URL("/admin.html", url), request));
    }
    if (path === "/onboarding.html" || path === "/onboarding") {
      const teacherId = await requireSession(request, env);
      if (!teacherId) return Response.redirect(url.origin + "/login.html", 302);
      return env.ASSETS.fetch(new Request(new URL("/onboarding.html", url), request));
    }

    // Student links: /s/<slug>/<week> — always the same page, slug and
    // week both read client-side from the URL
    if (path.startsWith("/s/")) {
      return env.ASSETS.fetch(new Request(new URL("/index.html", url), request));
    }

    if (path === "/") return Response.redirect(url.origin + "/login.html", 302);

    return env.ASSETS.fetch(request);
  },
};
