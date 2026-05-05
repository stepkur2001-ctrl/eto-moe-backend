cellSizeMeters) > 0
      ? Number(req.query.cellSizeMeters)
      : DEFAULT_CELL_SIZE_METERS;

    if (
      !Number.isFinite(minLat) ||
      !Number.isFinite(maxLat) ||
      !Number.isFinite(minLon) ||
      !Number.isFinite(maxLon)
    ) {
      return res.status(400).json({
        ok: false,
        error: 'viewport bounds are invalid'
      });
    }

    const range = boundsToGridRange(
      minLat,
      maxLat,
      minLon,
      maxLon,
      safeCellSize
    );

    const result = await pool.query(
      `
        select
          u.telegram_id,
          u.username,
          u.first_name,
          count(*) as owned_in_viewport
        from global_cell_ownership gco
        join users u on u.id = gco.owner_user_id
        where gco.grid_x between $1 and $2
          and gco.grid_y between $3 and $4
        group by u.id, u.telegram_id, u.username, u.first_name
        order by owned_in_viewport desc, u.telegram_id asc
        limit $5
      `,
      [range.minGridX, range.maxGridX, range.minGridY, range.maxGridY, limit]
    );

    return res.json({
      ok: true,
      players: result.rows.map((row, index) => ({
        rank: index + 1,
        telegramId: row.telegram_id != null ? Number(row.telegram_id) : null,
        username: row.username ?? null,
        firstName: row.first_name ?? null,
        ownedInViewport: Number(row.owned_in_viewport || 0)
      }))
    });
  } catch (error) {
    console.error('viewport leaderboard error:', error);

    return res.status(500).json({
      ok: false,
      error: error.message
    });
  }
});

// =========================================================
// БЛОК 9. СТАРТ СЕРВЕРА
// =========================================================
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
