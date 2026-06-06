'use strict';
/**
 * pg-store.js — Bóveda de persistencia y copias de seguridad en PostgreSQL.
 *
 * Render reinicia el disco /tmp en cada deploy, por lo que la base SQLite es
 * efímera. Este módulo guarda TODO el estado (catálogo, cursos, módulos,
 * alumnos, dominios) y las copias de seguridad semanales en una base
 * PostgreSQL externa que SÍ sobrevive a los redeploys.
 *
 * Funcionamiento:
 *   - Si NO existe DATABASE_URL, todas las funciones son no-op (modo local).
 *   - Al arrancar, server.js rehidrata SQLite desde PostgreSQL.
 *   - Tras cada cambio, server.js vuelca el estado a PostgreSQL.
 *   - Una vez por semana se genera una copia de seguridad y se guarda en PG.
 *
 * Tablas:
 *   live_state (key, payload jsonb, updated_at)   — estado actual rehidratable
 *   backups    (id, created_at, label, kind, ...) — copias de seguridad
 *   pg_config  (key, value)                       — marcadores (ej. última copia)
 */

const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL || '';
let Pool = null;
let pool = null;
let ready = false;
let initPromise = null;

function isEnabled() {
    return !!DATABASE_URL;
}

function _makePool() {
    if (!Pool) {
        // Carga perezosa: si pg no está instalado en local, no rompe el arranque.
        Pool = require('pg').Pool;
    }
    // SSL solo para conexiones externas de Render (host con dominio .render.com).
    // La conexión interna (host corto sin dominio) no requiere SSL.
    const useSSL = /\.render\.com/i.test(DATABASE_URL) || process.env.PG_SSL === 'true';
    return new Pool({
        connectionString: DATABASE_URL,
        ssl: useSSL ? { rejectUnauthorized: false } : false,
        max: 4,
        idleTimeoutMillis: 30_000,
        connectionTimeoutMillis: 15_000,
    });
}

/** Inicializa la conexión y crea las tablas. Idempotente. */
async function init() {
    if (!isEnabled()) return false;
    if (ready) return true;
    if (initPromise) return initPromise;
    initPromise = (async () => {
        try {
            pool = _makePool();
            await pool.query(`
                CREATE TABLE IF NOT EXISTS live_state (
                    key        TEXT PRIMARY KEY,
                    payload    JSONB NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                CREATE TABLE IF NOT EXISTS backups (
                    id            BIGSERIAL PRIMARY KEY,
                    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
                    label         TEXT NOT NULL DEFAULT '',
                    kind          TEXT NOT NULL DEFAULT 'manual',
                    total_videos  INTEGER NOT NULL DEFAULT 0,
                    total_courses INTEGER NOT NULL DEFAULT 0,
                    payload       JSONB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_backups_created ON backups(created_at DESC);
                CREATE TABLE IF NOT EXISTS pg_config (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL DEFAULT ''
                );
            `);
            ready = true;
            console.log('[pg] PostgreSQL conectado y tablas listas');
            return true;
        } catch (err) {
            console.error('[pg] Error inicializando PostgreSQL:', err.message);
            ready = false;
            return false;
        }
    })();
    return initPromise;
}

function _ok() {
    return isEnabled() && ready && pool;
}

/** Guarda el estado completo actual (rehidratable) bajo la clave 'live'. */
async function saveLiveState(snapshot) {
    if (!_ok()) return false;
    try {
        await pool.query(
            `INSERT INTO live_state (key, payload, updated_at)
             VALUES ('live', $1::jsonb, now())
             ON CONFLICT (key) DO UPDATE SET payload = EXCLUDED.payload, updated_at = now()`,
            [JSON.stringify(snapshot)]
        );
        return true;
    } catch (err) {
        console.error('[pg] saveLiveState error:', err.message);
        return false;
    }
}

/** Devuelve el último estado guardado o null. */
async function loadLiveState() {
    if (!_ok()) return null;
    try {
        const r = await pool.query(`SELECT payload FROM live_state WHERE key = 'live'`);
        return r.rows.length ? r.rows[0].payload : null;
    } catch (err) {
        console.error('[pg] loadLiveState error:', err.message);
        return null;
    }
}

/** Crea una copia de seguridad. payload usa la misma estructura del backup JSON. */
async function createBackup({ label = '', kind = 'manual', payload }) {
    if (!_ok()) return null;
    try {
        const totalVideos  = payload?.totalVideos  || (payload?.catalog?.value?.length || 0);
        const totalCourses = payload?.totalCourses || (payload?.courses?.length || 0);
        const r = await pool.query(
            `INSERT INTO backups (label, kind, total_videos, total_courses, payload)
             VALUES ($1, $2, $3, $4, $5::jsonb)
             RETURNING id, created_at, label, kind, total_videos, total_courses`,
            [label, kind, totalVideos, totalCourses, JSON.stringify(payload)]
        );
        return r.rows[0];
    } catch (err) {
        console.error('[pg] createBackup error:', err.message);
        return null;
    }
}

/** Lista las copias de seguridad (sin el payload, para no traer megas). */
async function listBackups(limit = 100) {
    if (!_ok()) return [];
    try {
        const r = await pool.query(
            `SELECT id, created_at, label, kind, total_videos, total_courses
             FROM backups ORDER BY created_at DESC LIMIT $1`,
            [limit]
        );
        return r.rows;
    } catch (err) {
        console.error('[pg] listBackups error:', err.message);
        return [];
    }
}

/** Devuelve una copia de seguridad completa (con payload). */
async function getBackup(id) {
    if (!_ok()) return null;
    try {
        const r = await pool.query(`SELECT * FROM backups WHERE id = $1`, [id]);
        return r.rows.length ? r.rows[0] : null;
    } catch (err) {
        console.error('[pg] getBackup error:', err.message);
        return null;
    }
}

/** Elimina una copia de seguridad. */
async function deleteBackup(id) {
    if (!_ok()) return false;
    try {
        await pool.query(`DELETE FROM backups WHERE id = $1`, [id]);
        return true;
    } catch (err) {
        console.error('[pg] deleteBackup error:', err.message);
        return false;
    }
}

/** Conserva solo las N copias más recientes de un tipo; elimina el resto. */
async function pruneBackups(kind = 'weekly', keep = 12) {
    if (!_ok()) return;
    try {
        await pool.query(
            `DELETE FROM backups WHERE kind = $1 AND id NOT IN (
                 SELECT id FROM backups WHERE kind = $1 ORDER BY created_at DESC LIMIT $2
             )`,
            [kind, keep]
        );
    } catch (err) {
        console.error('[pg] pruneBackups error:', err.message);
    }
}

async function getConfig(key) {
    if (!_ok()) return null;
    try {
        const r = await pool.query(`SELECT value FROM pg_config WHERE key = $1`, [key]);
        return r.rows.length ? r.rows[0].value : null;
    } catch (err) {
        console.error('[pg] getConfig error:', err.message);
        return null;
    }
}

async function setConfig(key, value) {
    if (!_ok()) return false;
    try {
        await pool.query(
            `INSERT INTO pg_config (key, value) VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
            [key, String(value)]
        );
        return true;
    } catch (err) {
        console.error('[pg] setConfig error:', err.message);
        return false;
    }
}

module.exports = {
    isEnabled,
    init,
    isReady: () => _ok(),
    saveLiveState,
    loadLiveState,
    createBackup,
    listBackups,
    getBackup,
    deleteBackup,
    pruneBackups,
    getConfig,
    setConfig,
};
