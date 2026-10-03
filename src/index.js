async function hashPassword(password, salt) {
  const data = new TextEncoder().encode(salt + password);
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

        const admin = await env.DB.prepare(
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
           LIMIT 1`
        ).bind(username).first();

        if (!admin || admin.status !== "active") {
          return json({ ok: false, error: "invalid_credentials" }, 401);
        }

        const [salt, storedHash] = String(admin.password_hash || "").split(":");
        if (!salt || !storedHash) {
          return json({ ok: false, error: "invalid_credentials" }, 401);
        }

        const passwordHash = await hashPassword(password, salt);
        if (passwordHash !== storedHash) {
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

        await env.DB.prepare(
          "UPDATE admins SET last_login_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        ).bind(admin.id).run();

        return json({
          ok: true,
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

    return env.ASSETS.fetch(request);
  }
};
