function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
}

function generateToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
}

function getTokenFromCookie(cookieHeader) {
  if (!cookieHeader) return null;
  const match = cookieHeader.match(/gate_token=([a-f0-9]{64})/);
  return match ? match[1] : null;
}

function isAdminAuthed(request, env) {
  const u = request.headers.get('X-Admin-Username') || '';
  const p = request.headers.get('X-Admin-Password') || '';
  const adminUser = env.ADMIN_USERNAME || 'Hosen Toufiq Riyad';
  const adminPass = env.ADMIN_PASSWORD || 'Hosen Toufiq Riyad';
  return u === adminUser && p === adminPass;
}

async function isValidToken(db, token) {
  if (!token) return false;
  const { results } = await db
    .prepare('SELECT id FROM gate_members WHERE token = ? AND is_active = 1')
    .bind(token)
    .all();
  return results.length > 0;
}

async function getGateOpen(db) {
  const { results } = await db.prepare('SELECT is_open FROM gate_config WHERE id = 1').all();
  return results[0]?.is_open === 1;
}

async function serveHtml(env, request, filename) {
  const url = new URL(request.url);
  url.pathname = '/' + filename;
  return env.ASSETS.fetch(new Request(url.toString()));
}

async function serveSite(env, request) {
  let resp = await env.ASSETS.fetch(request);
  if (resp.status === 404) {
    const url = new URL(request.url);
    url.pathname = '/';
    resp = await env.ASSETS.fetch(new Request(url.toString()));
  }
  return resp;
}

// ── Gate API handlers ─────────────────────────────────────────────────────────

async function handleGetStatus(db) {
  const isOpen = await getGateOpen(db);
  return json({ isOpen });
}

async function handleToggleGate(request, db, env) {
  if (!isAdminAuthed(request, env)) return json({ error: 'Unauthorized' }, 401);
  const body = await request.json();
  await db.prepare('UPDATE gate_config SET is_open = ? WHERE id = 1').bind(body.isOpen ? 1 : 0).run();
  return json({ isOpen: !!body.isOpen });
}

async function handleRequestAccess(request, db) {
  const isOpen = await getGateOpen(db);
  if (!isOpen) return json({ error: 'Site is not open for visitors right now.' }, 403);

  const body = await request.json();
  const name = (body.name || '').trim();
  if (!name) return json({ error: 'Name is required.' }, 400);

  // Check if name is in the admin-approved list (case-insensitive)
  const { results: allowed } = await db
    .prepare('SELECT id FROM allowed_names WHERE LOWER(name) = LOWER(?)')
    .bind(name)
    .all();

  if (allowed.length === 0) {
    return json({ error: 'This name is not on the access list. Please check with the admin.' }, 403);
  }

  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || null;
  const userAgent = request.headers.get('User-Agent') || null;
  const fingerprint = body.fingerprint || null;
  const deviceInfo = body.deviceInfo || null;
  const token = generateToken();

  await db
    .prepare('INSERT INTO gate_members (name, ip, fingerprint, device_info, user_agent, token) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(name, ip, fingerprint, deviceInfo, userAgent, token)
    .run();

  const cookie = `gate_token=${token}; Path=/; SameSite=Lax; Secure; Max-Age=31536000`;
  return json({ token, name }, 200, { 'Set-Cookie': cookie });
}

async function handleCheckToken(request, db) {
  const body = await request.json();
  const valid = await isValidToken(db, body.token || '');
  const isOpen = await getGateOpen(db);
  return json({ hasAccess: valid, gateIsOpen: isOpen });
}

async function handleListMembers(request, db, env) {
  if (!isAdminAuthed(request, env)) return json({ error: 'Unauthorized' }, 401);
  const { results } = await db.prepare('SELECT * FROM gate_members ORDER BY granted_at DESC').all();
  return json({ members: results });
}

async function handleDeleteMember(request, db, env, id) {
  if (!isAdminAuthed(request, env)) return json({ error: 'Unauthorized' }, 401);
  await db.prepare('UPDATE gate_members SET is_active = 0 WHERE id = ?').bind(parseInt(id, 10)).run();
  return json({ success: true });
}

async function handleListAllowedNames(request, db, env) {
  if (!isAdminAuthed(request, env)) return json({ error: 'Unauthorized' }, 401);
  const { results } = await db.prepare('SELECT * FROM allowed_names ORDER BY created_at DESC').all();
  return json({ names: results });
}

async function handleAddAllowedName(request, db, env) {
  if (!isAdminAuthed(request, env)) return json({ error: 'Unauthorized' }, 401);
  const body = await request.json();
  const name = (body.name || '').trim();
  if (!name) return json({ error: 'Name is required.' }, 400);
  try {
    const { results } = await db
      .prepare('INSERT INTO allowed_names (name) VALUES (?) RETURNING *')
      .bind(name)
      .all();
    return json({ name: results[0] }, 201);
  } catch (e) {
    return json({ error: 'Name already exists.' }, 409);
  }
}

async function handleDeleteAllowedName(request, db, env, id) {
  if (!isAdminAuthed(request, env)) return json({ error: 'Unauthorized' }, 401);
  await db.prepare('DELETE FROM allowed_names WHERE id = ?').bind(parseInt(id, 10)).run();
  return json({ success: true });
}

async function handleAdminLogin(request, env) {
  const body = await request.json();
  const adminUser = env.ADMIN_USERNAME || 'Hosen Toufiq Riyad';
  const adminPass = env.ADMIN_PASSWORD || 'Hosen Toufiq Riyad';
  if (body.username === adminUser && body.password === adminPass) {
    return json({ ok: true });
  }
  return json({ ok: false, error: 'Invalid credentials.' }, 401);
}

// ── Main handler ─────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;
    const { method } = request;

    if (method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Username, X-Admin-Password',
        },
      });
    }

    // ── Admin panel ───────────────────────────────────────────────────────────
    if (pathname === '/gate-admin' || pathname === '/gate-admin/') {
      return serveHtml(env, request, 'gate-admin.html');
    }
    // Redirect old /admin link → unified /gate-admin
    if (pathname === '/admin' || pathname === '/admin/') {
      return Response.redirect(new URL('/gate-admin', request.url).toString(), 301);
    }

    // ── Gate API ──────────────────────────────────────────────────────────────
    if (pathname.startsWith('/gate-api/')) {
      const db = env.DB;

      // Public
      if (pathname === '/gate-api/status' && method === 'GET')  return handleGetStatus(db);
      if (pathname === '/gate-api/access' && method === 'POST') return handleRequestAccess(request, db);
      if (pathname === '/gate-api/check'  && method === 'POST') return handleCheckToken(request, db);
      if (pathname === '/gate-api/login'  && method === 'POST') return handleAdminLogin(request, env);

      // Admin-protected
      if (pathname === '/gate-api/toggle'         && method === 'POST')   return handleToggleGate(request, db, env);
      if (pathname === '/gate-api/members'         && method === 'GET')    return handleListMembers(request, db, env);
      if (pathname === '/gate-api/allowed-names'   && method === 'GET')    return handleListAllowedNames(request, db, env);
      if (pathname === '/gate-api/allowed-names'   && method === 'POST')   return handleAddAllowedName(request, db, env);

      const delMember = pathname.match(/^\/gate-api\/members\/(\d+)$/);
      if (delMember && method === 'DELETE') return handleDeleteMember(request, db, env, delMember[1]);

      const delName = pathname.match(/^\/gate-api\/allowed-names\/(\d+)$/);
      if (delName && method === 'DELETE') return handleDeleteAllowedName(request, db, env, delName[1]);

      return json({ error: 'Not found' }, 404);
    }

    // ── Static assets — always pass through ──────────────────────────────────
    if (
      pathname.startsWith('/assets/') ||
      pathname === '/favicon.svg' ||
      pathname === '/icon-192.png' ||
      pathname === '/icon-512.png' ||
      pathname === '/manifest.webmanifest'
    ) {
      return env.ASSETS.fetch(request);
    }

    // ── Gate check for all other routes ──────────────────────────────────────
    const db = env.DB;
    const token = getTokenFromCookie(request.headers.get('Cookie'));
    const valid = await isValidToken(db, token);
    if (valid) return serveSite(env, request);

    const isOpen = await getGateOpen(db);
    if (!isOpen) return serveHtml(env, request, 'gate-closed.html');
    return serveHtml(env, request, 'gate-enter.html');
  },
};
