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

async function handleLoginRequest(request, env, url) {
  let body;
  try { body = JSON.parse(await request.text()); } catch (e) { return json({ error: "invalid json" }, 400); }
  const email = (body.email || "").trim().toLowerCase();
  if (!email || !email.includes("@")) return json({ error: "Enter a valid email" }, 400);

  let row = await env.DB.prepare("SELECT id FROM teachers WHERE email = ?").bind(email).first();
  let teacherId;
  if (row) {
    teacherId = row.id;
  } else {
    await env.DB.prepare("INSERT INTO teachers (email) VALUES (?)").bind(email).run();
    const created = await env.DB.prepare("SELECT id FROM teachers WHERE email = ?").bind(email).first();
    teacherId = created.id;
  }

  const token = randomToken();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
  await env.DB.prepare("INSERT INTO login_tokens (token, teacher_id, expires_at, used) VALUES (?, ?, ?, 0)")
    .bind(token, teacherId, expiresAt).run();

  const link = url.origin + "/api/verify?token=" + token;

  // No email provider wired up yet — the link is handed straight back so
  // the whole flow can be tested today. Swap this for a real email send
  // (e.g. via Resend) once that's set up; nothing else needs to change.
  return json({ ok: true, link });
}

async function handleVerify(url, env) {
  const token = url.searchParams.get("token");
  if (!token) return new Response("Missing token", { status: 400 });
  const row = await env.DB.prepare("SELECT teacher_id, expires_at, used FROM login_tokens WHERE token = ?").bind(token).first();
  if (!row || row.used || new Date(row.expires_at) < new Date()) {
    return new Response("This link has expired or already been used. Request a new one from the login page.", { status: 400 });
  }

  const teacher = await env.DB.prepare("SELECT onboarded FROM teachers WHERE id = ?").bind(row.teacher_id).first();
  const cookieVal = await makeSessionCookie(row.teacher_id, env);
  const dest = teacher && teacher.onboarded ? "/admin.html" : "/onboarding.html";

  // Only burn the token once the session is actually built — an earlier
  // failure (a missing secret, say) shouldn't waste a one-time link.
  await env.DB.prepare("UPDATE login_tokens SET used = 1 WHERE token = ?").bind(token).run();

  const headers = new Headers();
  headers.set("Location", dest);
  headers.append("Set-Cookie", "session=" + cookieVal + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000");
  return new Response(null, { status: 302, headers });
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
      return { id: s.id, name: s.name, status: r ? r.status : null, avail: r ? r.avail : [] };
    }),
  });
}

async function handleReply(request, env) {
  let body;
  try { body = JSON.parse(await request.text()); } catch (e) { return json({ error: "invalid json" }, 400); }
  const { slug, week, studentId, status, avail } = body || {};
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
    state.rounds[wk].replies[studentId] = { status, avail, lesson: prevLesson };
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
    if (path === "/api/verify" && request.method === "GET") return handleVerify(url, env);
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
