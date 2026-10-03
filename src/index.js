export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/db/health") {
      try {
        const result = await env.DB.prepare(
          "SELECT COUNT(*) AS table_count FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).first();

        return Response.json({
          ok: true,
          database: "massage-db",
          tableCount: Number(result?.table_count || 0),
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        return Response.json(
          {
            ok: false,
            error: error instanceof Error ? error.message : String(error)
          },
          { status: 500 }
        );
      }
    }

    return env.ASSETS.fetch(request);
  }
};
