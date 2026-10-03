async function hashPassword(password, salt) {
  const data = new TextEncoder().encode(salt + password);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function hashToken(token) {
  const data = new TextEncoder().encode(token);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" }
  });
}

function getBearerToken(request) {
  const value = request.headers.get("Authorization") || "";
  return value.startsWith("Bearer ") ? value.slice(7).trim() : "";
}

async function requireSession(request, env) {
  const token = getBearerToken(request);
  if (!token) return null;

  const tokenHash = await hashToken(token);
  const session = await env.DB.prepare(
    `SELECT
       s.id,
       s.admin_id,
       s.shop_id,
       s.expires_at,
       a.username,
       a.role,
       a.status,
       a.display_name
     FROM sessions s
     JOIN admins a ON a.id = s.admin_id
     WHERE s.token_hash = ?
       AND a.status = 'active'
       AND datetime(s.expires_at) > datetime('now')
     LIMIT 1`
  ).bind(tokenHash).first();

  if (!session) return null;

  await env.DB.prepare(
    "UPDATE sessions SET last_seen_at = CURRENT_TIMESTAMP WHERE id = ?"
  ).bind(session.id).run();

  return session;
}

function mapStaff(row) {
  return {
    id: row.id,
    legacyId: row.legacy_id,
    name: row.name,
    phone: row.phone || "",
    bank: row.bank_name || "",
    account: row.bank_account || "",
    status: row.status || "정직원",
    sequenceNo: row.sequence_no ?? null,
    notes: row.notes || ""
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/db/health") {
      try {
        const result = await env.DB.prepare(
          "SELECT COUNT(*) AS table_count FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).first();

        return json({
          ok: true,
          database: "massage-db",
          tableCount: Number(result?.table_count || 0),
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        return json(
          {
            ok: false,
            error: error instanceof Error ? error.message : String(error)
          },
          500
        );
      }
    }

    if (url.pathname === "/api/auth/login" && request.method === "POST") {
      try {
        const body = await request.json();
        const username = String(body?.username || "").trim();
        const password = String(body?.password || "");

        if (!username || !password) {
          return json({ ok: false, error: "missing_credentials" }, 400);
        }

        // A username is unique within a shop, not globally. Check all active
        // matching usernames so one shop's account cannot mask another shop's account.
        const adminRows = await env.DB.prepare(
          `SELECT
             a.id,
             a.shop_id,
             a.username,
             a.password_hash,
             a.display_name,
             a.role,
             a.status,
             a.valid_until,
             s.shop_name
           FROM admins a
           JOIN shops s ON s.id = a.shop_id
           WHERE a.username = ?
             AND a.status = 'active'`
        ).bind(username).all();

        let admin = null;
        for (const candidate of (adminRows.results || [])) {
          const [salt, storedHash] = String(candidate.password_hash || "").split(":");
          if (!salt || !storedHash) continue;
          const passwordHash = await hashPassword(password, salt);
          if (passwordHash === storedHash) {
            admin = candidate;
            break;
          }
        }

        if (!admin) {
          return json({ ok: false, error: "invalid_credentials" }, 401);
        }

        const today = new Date().toISOString().slice(0, 10);
        if (admin.valid_until && today > admin.valid_until) {
          return json({
            ok: false,
            error: "expired",
            validUntil: admin.valid_until
          }, 403);
        }

        const token = crypto.randomUUID() + "-" + crypto.randomUUID();
        const tokenHash = await hashToken(token);
        const sessionId = crypto.randomUUID();

        // Keep session creation simple and isolated so a stale/expired session
        // cannot prevent a valid account from logging in.
        await env.DB.prepare(
          "DELETE FROM sessions WHERE admin_id = ? AND datetime(expires_at) <= datetime('now')"
        ).bind(admin.id).run();

        await env.DB.prepare(
          "INSERT INTO sessions (id, admin_id, shop_id, token_hash, expires_at, last_seen_at) VALUES (?, ?, ?, ?, datetime('now', '+7 days'), CURRENT_TIMESTAMP)"
        ).bind(sessionId, admin.id, admin.shop_id, tokenHash).run();

        await env.DB.prepare(
          "UPDATE admins SET last_login_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        ).bind(admin.id).run();

        return json({
          ok: true,
          token,
          expiresInDays: 7,
          admin: {
            id: admin.id,
            shopId: admin.shop_id,
            username: admin.username,
            type: admin.role === "super" ? "super" : "normal",
            role: admin.role,
            shopName: admin.shop_name,
            displayName: admin.display_name || admin.shop_name,
            validUntil: admin.valid_until || null
          }
        });
      } catch (error) {
        return json(
          {
            ok: false,
            error: error instanceof Error ? error.message : String(error)
          },
          500
        );
      }
    }

    if (url.pathname === "/api/auth/logout" && request.method === "POST") {
      try {
        const token = getBearerToken(request);
        if (token) {
          const tokenHash = await hashToken(token);
          await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?")
            .bind(tokenHash)
            .run();
        }
        return json({ ok: true });
      } catch (error) {
        return json({ ok: false, error: error instanceof Error ? error.message : String(error) }, 500);
      }
    }

    if (url.pathname === "/api/auth/me" && request.method === "GET") {
      const session = await requireSession(request, env);
      if (!session) return json({ ok: false, error: "unauthorized" }, 401);
      return json({
        ok: true,
        admin: {
          id: session.admin_id,
          shopId: session.shop_id,
          username: session.username,
          type: session.role === "super" ? "super" : "normal",
          role: session.role,
          displayName: session.display_name || session.username
        }
      });
    }

    if (url.pathname === "/api/staff") {
      const session = await requireSession(request, env);
      if (!session) return json({ ok: false, error: "unauthorized" }, 401);

      try {
        if (request.method === "GET") {
          const result = await env.DB.prepare(
            `SELECT id, legacy_id, name, phone, bank_name, bank_account, status, sequence_no, notes
             FROM staff
             WHERE shop_id = ?
             ORDER BY CASE WHEN sequence_no IS NULL THEN 999999 ELSE sequence_no END, name`
          ).bind(session.shop_id).all();

          return json({
            ok: true,
            staff: (result.results || []).map(mapStaff)
          });
        }

        if (request.method === "POST") {
          const body = await request.json();
          const staff = Array.isArray(body?.staff) ? body.staff : [body];

          if (!staff.length) return json({ ok: true, staff: [] });

          const statements = [];
          for (const member of staff) {
            const legacyId = Number(member?.legacyId ?? member?.id);
            const name = String(member?.name || "").trim();
            if (!Number.isFinite(legacyId) || !name) continue;

            statements.push(
              env.DB.prepare(
                `INSERT INTO staff
                  (shop_id, legacy_id, name, phone, bank_name, bank_account, status, sequence_no, notes)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(shop_id, legacy_id) DO UPDATE SET
                   name = excluded.name,
                   phone = excluded.phone,
                   bank_name = excluded.bank_name,
                   bank_account = excluded.bank_account,
                   status = excluded.status,
                   sequence_no = excluded.sequence_no,
                   notes = excluded.notes,
                   updated_at = CURRENT_TIMESTAMP`
              ).bind(
                session.shop_id,
                legacyId,
                name,
                String(member?.phone || ""),
                String(member?.bank || ""),
                String(member?.account || ""),
                String(member?.status || "정직원"),
                member?.sequenceNo == null || member?.sequenceNo === "" ? null : Number(member.sequenceNo),
                String(member?.notes || "")
              )
            );
          }

          if (statements.length) await env.DB.batch(statements);

          const result = await env.DB.prepare(
            "SELECT id, legacy_id, name, phone, bank_name, bank_account, status, sequence_no, notes FROM staff WHERE shop_id = ? ORDER BY CASE WHEN sequence_no IS NULL THEN 999999 ELSE sequence_no END, name"
          ).bind(session.shop_id).all();

          return json({ ok: true, staff: (result.results || []).map(mapStaff) });
        }

        return json({ ok: false, error: "method_not_allowed" }, 405);
      } catch (error) {
        return json({ ok: false, error: error instanceof Error ? error.message : String(error) }, 500);
      }
    }

    if (url.pathname === "/api/staff/item" && (request.method === "PUT" || request.method === "DELETE")) {
      const session = await requireSession(request, env);
      if (!session) return json({ ok: false, error: "unauthorized" }, 401);

      try {
        const body = await request.json();
        const legacyId = Number(body?.legacyId ?? body?.id);
        if (!Number.isFinite(legacyId)) return json({ ok: false, error: "invalid_staff_id" }, 400);

        if (request.method === "DELETE") {
          await env.DB.prepare(
            "DELETE FROM staff WHERE shop_id = ? AND legacy_id = ?"
          ).bind(session.shop_id, legacyId).run();
          return json({ ok: true });
        }

        const name = String(body?.name || "").trim();
        if (!name) return json({ ok: false, error: "name_required" }, 400);

        await env.DB.prepare(
          `UPDATE staff
           SET name = ?, phone = ?, bank_name = ?, bank_account = ?, status = ?,
               sequence_no = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
           WHERE shop_id = ? AND legacy_id = ?`
        ).bind(
          name,
          String(body?.phone || ""),
          String(body?.bank || ""),
          String(body?.account || ""),
          String(body?.status || "정직원"),
          body?.sequenceNo == null || body?.sequenceNo === "" ? null : Number(body.sequenceNo),
          String(body?.notes || ""),
          session.shop_id,
          legacyId
        ).run();

        return json({ ok: true });
      } catch (error) {
        return json({ ok: false, error: error instanceof Error ? error.message : String(error) }, 500);
      }
    }

    return env.ASSETS.fetch(request);
  }
};
