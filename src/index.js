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

function json(data, status = 200, request = null) {
  const origin = request?.headers.get("Origin") || "";
  const headers = {
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": origin || "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization"
  };
  return Response.json(data, { status, headers });
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
       a.display_name,
       a.email,
       a.phone,
       a.google_maps_url,
       a.language,
       a.valid_until
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

    if (request.method === "OPTIONS" && url.pathname.startsWith("/api/")) {
      const origin = request.headers.get("Origin") || "*";
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Max-Age": "86400"
        }
      });
    }

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
        }, 200, request);
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
          return json({ ok: false, error: "missing_credentials" }, 400, request);
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
             a.phone,
             a.google_maps_url,
             a.language,
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
          return json({ ok: false, error: "invalid_credentials" }, 401, request);
        }

        const today = new Date().toISOString().slice(0, 10);
        if (admin.valid_until && today > admin.valid_until) {
          return json({
            ok: false,
            error: "expired",
            validUntil: admin.valid_until
          }, 403, request);
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
            // New normal admins store the entered shop name in display_name.
            // Fall back to the tenant shop name for existing accounts.
            shopName: admin.display_name || admin.shop_name,
            displayName: admin.display_name || admin.shop_name,
            validUntil: admin.valid_until || null,
            phone: admin.phone || "",
            googleMapsUrl: admin.google_maps_url || "",
            language: admin.language || "ko",
            email: admin.email || ""
          }
        }, 200, request);
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

    if (url.pathname === "/api/admin/profile" && request.method === "PUT") {
      const session = await requireSession(request, env);
      if (!session) return json({ ok:false, error:"unauthorized" }, 401, request);

      try {
        const body = await request.json();
        const password = String(body?.password || "");
        const shopName = String(body?.shopName || "").trim();
        const email = String(body?.email || "").trim();
        const phone = String(body?.phone || "").trim();
        const googleMapsUrl = String(body?.googleMapsUrl || "").trim();
        const languageValue = String(body?.language || "");
        const language = ["ko","en","th","vi","zh-CN","zh-TW","id"].includes(languageValue) ? languageValue : "ko";

        if (!shopName) return json({ ok:false, error:"shop_name_required" }, 400, request);
        if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ ok:false, error:"invalid_email" }, 400, request);
        if (password && password.length < 4) return json({ ok:false, error:"invalid_password" }, 400, request);

        const updates = ["display_name = ?", "email = ?", "phone = ?", "google_maps_url = ?", "language = ?", "updated_at = CURRENT_TIMESTAMP"];
        const binds = [shopName, email, phone, googleMapsUrl, language];

        if (password) {
          const salt = crypto.randomUUID();
          const passwordHash = await hashPassword(password, salt);
          updates.push("password_hash = ?");
          binds.push(salt + ":" + passwordHash);
        }

        binds.push(session.admin_id, session.shop_id);
        await env.DB.prepare("UPDATE admins SET " + updates.join(", ") + " WHERE id = ? AND shop_id = ?").bind(...binds).run();
        await env.DB.prepare("UPDATE shops SET shop_name = ?, email = ?, google_maps_url = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(shopName, email, googleMapsUrl, session.shop_id).run();

        const updated = await env.DB.prepare(
          "SELECT a.id, a.shop_id, a.username, a.display_name, a.role, a.email, a.phone, a.google_maps_url, a.language, a.status, a.valid_until, a.updated_at, s.shop_name FROM admins a LEFT JOIN shops s ON s.id = a.shop_id WHERE a.id = ? AND a.shop_id = ? LIMIT 1"
        ).bind(session.admin_id, session.shop_id).first();

        return json({ ok:true, admin:{
          id:updated.id, shopId:updated.shop_id, username:updated.username,
          type:updated.role === "super" ? "super" : "normal", role:updated.role,
          shopName:updated.display_name || updated.shop_name || "", displayName:updated.display_name || updated.shop_name || "",
          email:updated.email || "", phone:updated.phone || "", googleMapsUrl:updated.google_maps_url || "",
          language:updated.language || "ko", validUntil:updated.valid_until || null, updatedAt:updated.updated_at
        }}, 200, request);
      } catch (error) {
        return json({ ok:false, error:error instanceof Error ? error.message : String(error) }, 500, request);
      }
    }

    if (url.pathname === "/api/admins" && (request.method === "GET" || request.method === "POST")) {
      const session = await requireSession(request, env);
      if (!session) return json({ ok: false, error: "unauthorized" }, 401, request);
      if (session.role !== "super") return json({ ok: false, error: "forbidden" }, 403, request);

      try {
        if (request.method === "GET") {
          const result = await env.DB.prepare(
            `SELECT a.id, a.shop_id, a.username, a.display_name, a.role, a.email, a.phone, a.google_maps_url,
                    a.language, a.status, a.valid_until, a.created_at, a.updated_at,
                    s.shop_name
             FROM admins a
             LEFT JOIN shops s ON s.id = a.shop_id
             WHERE a.status = 'active'
             ORDER BY a.id`
          ).all();

          return json({
            ok: true,
            admins: (result.results || []).map(a => ({
              id: a.id,
              shopId: a.shop_id,
              username: a.username,
              displayName: a.display_name || "",
              shopName: a.shop_name || a.display_name || "",
              role: a.role,
              type: a.role === "super" ? "super" : "normal",
              email: a.email || "",
              phone: a.phone || "",
              googleMapsUrl: a.google_maps_url || "",
              language: a.language || "ko",
              status: a.status,
              validUntil: a.valid_until || null,
              createdAt: a.created_at,
              updatedAt: a.updated_at
            }))
          }, 200, request);
        }

        const body = await request.json();
        const username = String(body?.username || "").trim();
        const password = String(body?.password || "");
        const type = body?.type === "super" ? "super" : "normal";
        const displayName = String(body?.shopName || body?.displayName || "").trim();
        const email = String(body?.email || "").trim();
        const phone = String(body?.phone || "").trim();
        const googleMapsUrl = String(body?.googleMapsUrl || "").trim();
        const languageValue = String(body?.language || "");
        const language = ["ko","en","th","vi","zh-CN","zh-TW","id"].includes(languageValue) ? languageValue : "ko";
        const validUntil = type === "super" ? null : String(body?.validUntil || "").trim();

        if (!username || !password) {
          return json({ ok: false, error: "missing_credentials" }, 400, request);
        }
        if (type === "normal" && !validUntil) {
          return json({ ok: false, error: "valid_until_required" }, 400, request);
        }

        const duplicate = await env.DB.prepare(
          "SELECT id FROM admins WHERE username = ? LIMIT 1"
        ).bind(username).first();
        if (duplicate) return json({ ok: false, error: "username_exists" }, 409, request);

        const id = crypto.randomUUID();
        const salt = crypto.randomUUID();
        const passwordHash = await hashPassword(password, salt);

        await env.DB.prepare(
          `INSERT INTO admins
            (shop_id, username, password_hash, display_name, role, email, phone, google_maps_url, language, status, valid_until, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`
        ).bind(
          session.shop_id,
          username,
          salt + ":" + passwordHash,
          displayName || username,
          type,
          email,
          phone,
          googleMapsUrl,
          language,
          validUntil
        ).run();

        const created = await env.DB.prepare(
          `SELECT id, username, display_name, role, email, phone, google_maps_url, language, status, valid_until, created_at, updated_at
           FROM admins WHERE shop_id = ? AND username = ? LIMIT 1`
        ).bind(session.shop_id, username).first();

        return json({
          ok: true,
          admin: {
            id: created.id,
            username: created.username,
            displayName: created.display_name || "",
            role: created.role,
            type: created.role === "super" ? "super" : "normal",
            email: created.email || "",
            phone: created.phone || "",
            googleMapsUrl: created.google_maps_url || "",
            language: created.language || "ko",
            status: created.status,
            validUntil: created.valid_until || null,
            createdAt: created.created_at,
            updatedAt: created.updated_at
          }
        }, 201, request);
      } catch (error) {
        return json({ ok: false, error: error instanceof Error ? error.message : String(error) }, 500, request);
      }
    }

    if (url.pathname === "/api/admins/item" && (request.method === "PUT" || request.method === "DELETE")) {
      const session = await requireSession(request, env);
      if (!session) return json({ ok:false, error:"unauthorized" }, 401, request);
      if (session.role !== "super") return json({ ok:false, error:"forbidden" }, 403, request);
      try {
        const body = await request.json();
        const id = String(body?.id || "").trim();
        if (!id) return json({ ok:false, error:"invalid_admin_id" }, 400, request);

        const target = await env.DB.prepare(
          "SELECT id, username, role FROM admins WHERE id = ? AND shop_id = ? LIMIT 1"
        ).bind(id, session.shop_id).first();
        if (!target) return json({ ok:false, error:"admin_not_found" }, 404, request);

        if (request.method === "DELETE") {
          if (target.id === session.admin_id) return json({ ok:false, error:"cannot_delete_current_admin" }, 400, request);
          await env.DB.prepare("DELETE FROM sessions WHERE admin_id = ?").bind(id).run();
          const deleted = await env.DB.prepare(
            "DELETE FROM admins WHERE id = ? AND shop_id = ?"
          ).bind(id, session.shop_id).run();
          if (Number(deleted?.meta?.changes || 0) !== 1) {
            return json({ ok:false, error:"admin_delete_not_applied" }, 404, request);
          }
          return json({ ok:true, deletedId:String(id) }, 200, request);
        }

        const username = String(body?.username || "").trim();
        const password = String(body?.password || "");
        const type = body?.type === "super" ? "super" : "normal";
        const dbRole = type === "super" ? "super" : "manager";
        const shopName = String(body?.shopName || "").trim();
        const email = String(body?.email || "").trim();
        const phone = String(body?.phone || "").trim();
        const googleMapsUrl = String(body?.googleMapsUrl || "").trim();
        const languageValue = String(body?.language || "");
        const language = ["ko","en","th","vi","zh-CN","zh-TW","id"].includes(languageValue) ? languageValue : "ko";
        const validUntil = type === "super" ? null : String(body?.validUntil || "").trim();
        if (!username || !shopName) return json({ ok:false, error:"required_fields" }, 400, request);
        if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return json({ ok:false, error:"invalid_email" }, 400, request);
        }
        if (type === "normal" && !/^\d{4}-\d{2}-\d{2}$/.test(validUntil)) {
          return json({ ok:false, error:"invalid_valid_until" }, 400, request);
        }

        const duplicate = await env.DB.prepare(
          "SELECT id FROM admins WHERE username = ? AND id <> ? LIMIT 1"
        ).bind(username, id).first();
        if (duplicate) return json({ ok:false, error:"username_exists" }, 409, request);

        let sql = `UPDATE admins SET username = ?, display_name = ?, role = ?, email = ?, phone = ?, google_maps_url = ?, language = ?, valid_until = ?, updated_at = CURRENT_TIMESTAMP`;
        const binds = [username, shopName, dbRole, email, phone, googleMapsUrl, language, validUntil];
        if (password) {
          const salt = crypto.randomUUID();
          const passwordHash = await hashPassword(password, salt);
          sql += ", password_hash = ?";
          binds.push(salt + ":" + passwordHash);
        }
        sql += " WHERE id = ? AND shop_id = ?";
        binds.push(id, session.shop_id);

        const adminUpdate = await env.DB.prepare(sql).bind(...binds).run();
        if (Number(adminUpdate?.meta?.changes || 0) !== 1) {
          return json({ ok:false, error:"admin_update_not_applied" }, 404, request);
        }

        const shopExists = await env.DB.prepare(
          "SELECT id FROM shops WHERE id = ? LIMIT 1"
        ).bind(session.shop_id).first();
        if (!shopExists) {
          return json({ ok:false, error:"shop_not_found" }, 500, request);
        }

        await env.DB.prepare(
          "UPDATE shops SET shop_name = ?, email = ?, google_maps_url = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        ).bind(shopName, email, googleMapsUrl, session.shop_id).run();

        const updated = await env.DB.prepare(
          `SELECT id, username, display_name, role, email, phone, google_maps_url, language, status, valid_until, created_at, updated_at
           FROM admins WHERE id = ? AND shop_id = ? LIMIT 1`
        ).bind(id, session.shop_id).first();
        if (!updated) {
          return json({ ok:false, error:"admin_update_readback_failed" }, 500, request);
        }

        return json({ ok:true, admin:{
          id:String(updated.id), username:updated.username, displayName:updated.display_name || "",
          role:updated.role, type:updated.role === "super" ? "super" : "normal",
          email:updated.email || "", phone:updated.phone || "", googleMapsUrl:updated.google_maps_url || "",
          language:updated.language || "ko", status:updated.status, validUntil:updated.valid_until || null,
          createdAt:updated.created_at, updatedAt:updated.updated_at
        }}, 200, request);
      } catch (error) {
        return json({ ok:false, error:error instanceof Error ? error.message : String(error) }, 500, request);
      }
    }

    if (url.pathname === "/api/auth/register" && request.method === "POST") {
      try {
        const body = await request.json();
        const username = String(body?.username || "").trim();
        const password = String(body?.password || "");
        const shopName = String(body?.shopName || "").trim();
        const email = String(body?.email || "").trim();
        const phone = String(body?.phone || "").trim();
        const googleMapsUrl = String(body?.googleMapsUrl || "").trim();
        const languageValue = String(body?.language || "");
        const language = ["ko","en","th","vi","zh-CN","zh-TW","id"].includes(languageValue) ? languageValue : "ko";
        if (!username || !password || !shopName) return json({ ok:false, error:"required_fields" }, 400, request);
        if (username.length < 3 || username.length > 50) return json({ ok:false, error:"invalid_username" }, 400, request);
        if (password.length < 4) return json({ ok:false, error:"invalid_password" }, 400, request);
        if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ ok:false, error:"invalid_email" }, 400, request);
        const duplicate = await env.DB.prepare("SELECT id FROM admins WHERE username = ? LIMIT 1").bind(username).first();
        if (duplicate) return json({ ok:false, error:"username_exists" }, 409, request);
        const shopId = crypto.randomUUID();
        const salt = crypto.randomUUID();
        const passwordHash = await hashPassword(password, salt);
        const validFrom = new Date().toISOString().slice(0,10);
        const end = new Date(); end.setDate(end.getDate() + 7);
        const validUntil = end.toISOString().slice(0,10);
        await env.DB.batch([
          env.DB.prepare(`INSERT INTO shops (id, shop_name, email, address, google_maps_url, valid_until, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`).bind(shopId, shopName, email, "", googleMapsUrl, validUntil),
          env.DB.prepare(`INSERT INTO admins
            (shop_id, username, password_hash, display_name, role, email, phone, google_maps_url, language, status, valid_until, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'manager', ?, ?, ?, ?, 'active', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`).bind(
              shopId, username, salt + ":" + passwordHash, shopName, email, phone, googleMapsUrl, language, validUntil)
        ]);
        return json({ ok:true, admin:{ username, shopName, displayName:shopName, email, phone, googleMapsUrl, language, validFrom, validUntil, type:"normal", role:"manager" } }, 201, request);
      } catch (error) {
        return json({ ok:false, error:error instanceof Error ? error.message : String(error) }, 500, request);
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
        return json({ ok: true }, 200, request);
      } catch (error) {
        return json({ ok: false, error: error instanceof Error ? error.message : String(error) }, 500, request);
      }
    }

    if (url.pathname === "/api/auth/me" && request.method === "GET") {
      const session = await requireSession(request, env);
      if (!session) return json({ ok: false, error: "unauthorized" }, 401, request);
      return json({
        ok: true,
        admin: {
          id: session.admin_id,
          shopId: session.shop_id,
          username: session.username,
          type: session.role === "super" ? "super" : "normal",
          role: session.role,
          shopName: session.display_name || session.username,
          displayName: session.display_name || session.username,
          email: session.email || "",
          phone: session.phone || "",
          googleMapsUrl: session.google_maps_url || "",
          language: session.language || "ko",
          validUntil: session.valid_until || null
        }
      }, 200, request);
    }

    if (url.pathname === "/api/app-data" && (request.method === "GET" || request.method === "PUT" || request.method === "DELETE")) {
      const session = await requireSession(request, env);
      if (!session) return json({ ok: false, error: "unauthorized" }, 401, request);

      try {
        if (request.method === "GET") {
          const result = await env.DB.prepare(
            "SELECT data_key, data_json, updated_at FROM app_data WHERE shop_id = ? ORDER BY data_key"
          ).bind(session.shop_id).all();

          const data = {};
          for (const row of (result.results || [])) {
            data[row.data_key] = row.data_json;
          }

          return json({ ok: true, data }, 200, request);
        }

        const body = await request.json();
        const dataKey = String(body?.key || "").trim();
        if (!dataKey || dataKey.length > 200) {
          return json({ ok: false, error: "invalid_data_key" }, 400, request);
        }

        if (request.method === "DELETE") {
          await env.DB.prepare(
            "DELETE FROM app_data WHERE shop_id = ? AND data_key = ?"
          ).bind(session.shop_id, dataKey).run();
          return json({ ok: true }, 200, request);
        }

        const dataJson = typeof body?.value === "string"
          ? body.value
          : JSON.stringify(body?.value ?? null);

        if (dataJson.length > 1900000) {
          return json({ ok: false, error: "data_too_large" }, 413, request);
        }

        await env.DB.prepare(
          `INSERT INTO app_data (shop_id, data_key, data_json, updated_at)
           VALUES (?, ?, ?, CURRENT_TIMESTAMP)
           ON CONFLICT(shop_id, data_key) DO UPDATE SET
             data_json = excluded.data_json,
             updated_at = CURRENT_TIMESTAMP`
        ).bind(session.shop_id, dataKey, dataJson).run();

        return json({ ok: true, key: dataKey }, 200, request);
      } catch (error) {
        return json({ ok: false, error: error instanceof Error ? error.message : String(error) }, 500, request);
      }
    }

    if (url.pathname === "/api/staff") {
      const session = await requireSession(request, env);
      if (!session) return json({ ok: false, error: "unauthorized" }, 401, request);

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
          }, 200, request);
        }

        if (request.method === "POST") {
          const body = await request.json();
          const staff = Array.isArray(body?.staff) ? body.staff : [body];

          if (!staff.length) return json({ ok: true, staff: [] }, 200, request);

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

          return json({ ok: true, staff: (result.results || []).map(mapStaff) }, 200, request);
        }

        return json({ ok: false, error: "method_not_allowed" }, 405, request);
      } catch (error) {
        return json({ ok: false, error: error instanceof Error ? error.message : String(error) }, 500, request);
      }
    }

    if (url.pathname === "/api/staff/item" && (request.method === "PUT" || request.method === "DELETE")) {
      const session = await requireSession(request, env);
      if (!session) return json({ ok: false, error: "unauthorized" }, 401, request);

      try {
        const body = await request.json();
        const legacyId = Number(body?.legacyId ?? body?.id);
        if (!Number.isFinite(legacyId)) return json({ ok: false, error: "invalid_staff_id" }, 400, request);

        if (request.method === "DELETE") {
          await env.DB.prepare(
            "DELETE FROM staff WHERE shop_id = ? AND legacy_id = ?"
          ).bind(session.shop_id, legacyId).run();
          return json({ ok: true }, 200, request);
        }

        const name = String(body?.name || "").trim();
        if (!name) return json({ ok: false, error: "name_required" }, 400, request);

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

        return json({ ok: true }, 200, request);
      } catch (error) {
        return json({ ok: false, error: error instanceof Error ? error.message : String(error) }, 500, request);
      }
    }

    return env.ASSETS.fetch(request);
  }
};
