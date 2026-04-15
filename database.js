'use strict';
/**
 * database.js — Base de datos SQLite embebida (better-sqlite3)
 *
 * SQLite con WAL mode maneja cientos de lecturas simultáneas sin bloqueos.
 * Todas las escrituras son atómicas y serializadas por SQLite internamente.
 * No necesita servidor separado — es un solo archivo: data/app.db
 *
 * Tablas:
 *   students       — alumnos registrados
 *   audit_log      — cada reproducción entregada (fingerprint forense)
 *   catalog        — videos procesados y su estado
 */

const path = require('path');
const fs   = require('fs');

// En producción (Render/Railway) el único directorio escribible es /tmp
const DATA_DIR = process.env.NODE_ENV === 'production'
    ? '/tmp/data'
    : path.resolve('./data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const Database = require('better-sqlite3');
const db = new Database(path.join(DATA_DIR, 'app.db'));

// WAL mode: lecturas concurrentes sin bloquear escrituras
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('foreign_keys = ON');

// Migraciones no destructivas (columnas nuevas en tablas existentes)
try { db.exec("ALTER TABLE catalog ADD COLUMN source_type TEXT NOT NULL DEFAULT 'local'"); } catch {}
try { db.exec('ALTER TABLE catalog ADD COLUMN bunny_url TEXT'); } catch {}

// ================================================================
//  ESQUEMA
// ================================================================

db.exec(`
CREATE TABLE IF NOT EXISTS students (
    id             TEXT PRIMARY KEY,
    email          TEXT NOT NULL UNIQUE,
    student_id     TEXT NOT NULL,
    name           TEXT NOT NULL DEFAULT '',
    active         INTEGER NOT NULL DEFAULT 1,
    allowed_videos TEXT NOT NULL DEFAULT '*',
    device_id      TEXT,
    created_at     TEXT NOT NULL,
    last_login     TEXT
);
CREATE INDEX IF NOT EXISTS idx_students_email ON students(email);

CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint  TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    video_id     TEXT NOT NULL,
    device_id    TEXT NOT NULL DEFAULT 'desconocido',
    ip           TEXT NOT NULL DEFAULT 'desconocida',
    user_agent   TEXT NOT NULL DEFAULT 'desconocido',
    delivered_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_user    ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_video   ON audit_log(video_id);
CREATE INDEX IF NOT EXISTS idx_audit_fp      ON audit_log(fingerprint);

CREATE TABLE IF NOT EXISTS catalog (
    video_id      TEXT PRIMARY KEY,
    title         TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'processing',
    segment_count INTEGER NOT NULL DEFAULT 0,
    key_id        TEXT,
    error         TEXT,
    uploaded_at   TEXT NOT NULL,
    source_type   TEXT NOT NULL DEFAULT 'local',
    bunny_url     TEXT
);

CREATE TABLE IF NOT EXISTS active_sessions (
    session_id   TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    video_id     TEXT NOT NULL,
    started_at   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON active_sessions(user_id);

CREATE TABLE IF NOT EXISTS allowed_domains (
    domain TEXT PRIMARY KEY
);
`);

// ================================================================
//  STATEMENTS PREPARADOS (más rápidos que queries ad-hoc)
// ================================================================

// --- Students ---
const stmts = {
    getStudentByEmail:    db.prepare('SELECT * FROM students WHERE email = ?'),
    getStudentById:       db.prepare('SELECT * FROM students WHERE id = ?'),
    getAllStudents:        db.prepare('SELECT * FROM students ORDER BY created_at DESC'),
    insertStudent:        db.prepare(`
        INSERT INTO students (id, email, student_id, name, active, allowed_videos, device_id, created_at, last_login)
        VALUES (@id, @email, @student_id, @name, @active, @allowed_videos, @device_id, @created_at, @last_login)
    `),
    updateStudentDevice:  db.prepare('UPDATE students SET device_id = ?, last_login = ? WHERE id = ?'),
    updateStudent:        db.prepare(`
        UPDATE students SET name=@name, active=@active, allowed_videos=@allowed_videos,
        student_id=@student_id, device_id=@device_id WHERE id=@id
    `),
    deleteStudent:        db.prepare('DELETE FROM students WHERE id = ?'),

    // --- Audit log ---
    insertAudit:          db.prepare(`
        INSERT INTO audit_log (fingerprint, user_id, video_id, device_id, ip, user_agent, delivered_at)
        VALUES (@fingerprint, @user_id, @video_id, @device_id, @ip, @user_agent, @delivered_at)
    `),
    getAuditByFp:         db.prepare('SELECT * FROM audit_log WHERE fingerprint = ? LIMIT 1'),
    getAuditAll:          db.prepare('SELECT * FROM audit_log ORDER BY delivered_at DESC LIMIT ?'),
    getAuditByUser:       db.prepare('SELECT * FROM audit_log WHERE user_id = ? ORDER BY delivered_at DESC LIMIT ?'),
    getAuditByVideo:      db.prepare('SELECT * FROM audit_log WHERE video_id = ? ORDER BY delivered_at DESC LIMIT ?'),
    getAuditByUserVideo:  db.prepare('SELECT * FROM audit_log WHERE user_id = ? AND video_id = ? ORDER BY delivered_at DESC LIMIT ?'),
    countAudit:           db.prepare('SELECT COUNT(*) as n FROM audit_log'),
    countAuditUser:       db.prepare('SELECT COUNT(*) as n FROM audit_log WHERE user_id = ?'),
    countAuditVideo:      db.prepare('SELECT COUNT(*) as n FROM audit_log WHERE video_id = ?'),
    countAuditUserVideo:  db.prepare('SELECT COUNT(*) as n FROM audit_log WHERE user_id = ? AND video_id = ?'),

    // --- Catalog ---
    getCatalogAll:        db.prepare('SELECT * FROM catalog ORDER BY uploaded_at DESC'),
    getCatalogById:       db.prepare('SELECT * FROM catalog WHERE video_id = ?'),
    insertCatalog:        db.prepare(`
        INSERT OR REPLACE INTO catalog (video_id, title, status, segment_count, key_id, error, uploaded_at, source_type, bunny_url)
        VALUES (@video_id, @title, @status, @segment_count, @key_id, @error, @uploaded_at, @source_type, @bunny_url)
    `),
    updateCatalogStatus:  db.prepare(`
        UPDATE catalog SET status=@status, segment_count=@segment_count, key_id=@key_id, error=@error WHERE video_id=@video_id
    `),
    deleteCatalog:        db.prepare('DELETE FROM catalog WHERE video_id = ?'),

    // --- Sessions ---
    insertSession:        db.prepare('INSERT INTO active_sessions (session_id, user_id, video_id, started_at, last_seen) VALUES (?, ?, ?, ?, ?)'),
    heartbeatSession:     db.prepare('UPDATE active_sessions SET last_seen = ? WHERE session_id = ?'),
    deleteSession:        db.prepare('DELETE FROM active_sessions WHERE session_id = ?'),
    countActiveSessions:  db.prepare('SELECT COUNT(*) as n FROM active_sessions WHERE user_id = ? AND last_seen > ?'),
    cleanExpiredSessions: db.prepare('DELETE FROM active_sessions WHERE last_seen < ?'),
};

// ================================================================
//  API — STUDENTS
// ================================================================

function parseAllowedVideos(raw) {
    if (!raw || raw === '*') return ['*'];
    try {
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : ['*'];
    } catch { return raw.split(',').map(v => v.trim()).filter(Boolean) || ['*']; }
}

function serializeAllowedVideos(arr) {
    if (!Array.isArray(arr)) return '*';
    if (arr.includes('*')) return '*';
    return JSON.stringify(arr);
}

function rowToStudent(row) {
    if (!row) return null;
    return {
        id:             row.id,
        email:          row.email,
        studentId:      row.student_id,
        name:           row.name,
        active:         row.active === 1,
        allowedVideos:  parseAllowedVideos(row.allowed_videos),
        deviceId:       row.device_id || null,
        createdAt:      row.created_at,
        lastLogin:      row.last_login || null,
    };
}

module.exports.findStudentByEmail = (email) =>
    rowToStudent(stmts.getStudentByEmail.get(email));

module.exports.findStudentById = (id) =>
    rowToStudent(stmts.getStudentById.get(id));

module.exports.getAllStudents = () =>
    stmts.getAllStudents.all().map(rowToStudent);

module.exports.createStudent = ({ id, email, studentId, name, active, allowedVideos, createdAt }) => {
    stmts.insertStudent.run({
        id, email,
        student_id: studentId,
        name: name || '',
        active: active !== false ? 1 : 0,
        allowed_videos: serializeAllowedVideos(allowedVideos),
        device_id: null,
        created_at: createdAt || new Date().toISOString(),
        last_login: null,
    });
    return rowToStudent(stmts.getStudentById.get(id));
};

module.exports.bindDevice = (id, deviceId, lastLogin) =>
    stmts.updateStudentDevice.run(deviceId, lastLogin, id);

module.exports.updateStudent = (id, { name, active, allowedVideos, studentId, resetDevice, deviceId }) => {
    const row = stmts.getStudentById.get(id);
    if (!row) return null;
    stmts.updateStudent.run({
        id,
        name:           name !== undefined           ? String(name).slice(0, 100) : row.name,
        active:         active !== undefined          ? (active ? 1 : 0)          : row.active,
        allowed_videos: allowedVideos !== undefined   ? serializeAllowedVideos(allowedVideos) : row.allowed_videos,
        student_id:     studentId !== undefined       ? String(studentId).trim()  : row.student_id,
        device_id:      resetDevice                   ? null : (deviceId !== undefined ? deviceId : row.device_id),
    });
    return rowToStudent(stmts.getStudentById.get(id));
};

module.exports.deleteStudent = (id) =>
    stmts.deleteStudent.run(id);

module.exports.importStudents = (list) => {
    const insert = db.transaction((students) => {
        let added = 0, skipped = 0;
        for (const s of students) {
            try {
                stmts.insertStudent.run({
                    id: s.id, email: s.email,
                    student_id: s.studentId,
                    name: s.name || '',
                    active: s.active !== false ? 1 : 0,
                    allowed_videos: serializeAllowedVideos(s.allowedVideos || ['*']),
                    device_id: null,
                    created_at: s.createdAt || new Date().toISOString(),
                    last_login: null,
                });
                added++;
            } catch { skipped++; } // UNIQUE constraint → email duplicado
        }
        return { added, skipped };
    });
    return insert(list);
};

// ================================================================
//  API — AUDIT LOG
// ================================================================

module.exports.logDelivery = ({ fingerprint, userId, videoId, deviceId, ip, userAgent }) => {
    stmts.insertAudit.run({
        fingerprint,
        user_id: userId,
        video_id: videoId,
        device_id: deviceId || 'desconocido',
        ip: ip || 'desconocida',
        user_agent: userAgent || 'desconocido',
        delivered_at: new Date().toISOString(),
    });
};

module.exports.detectLeak = (fingerprint) => {
    const row = stmts.getAuditByFp.get(fingerprint);
    if (!row) return null;
    return {
        fingerprint:  row.fingerprint,
        userId:       row.user_id,
        videoId:      row.video_id,
        deviceId:     row.device_id,
        ip:           row.ip,
        userAgent:    row.user_agent,
        deliveredAt:  row.delivered_at,
    };
};

module.exports.getAuditLog = ({ userId, videoId, limit = 500 } = {}) => {
    let rows, count;
    if (userId && videoId) {
        rows  = stmts.getAuditByUserVideo.all(userId, videoId, limit);
        count = stmts.countAuditUserVideo.get(userId, videoId).n;
    } else if (userId) {
        rows  = stmts.getAuditByUser.all(userId, limit);
        count = stmts.countAuditUser.get(userId).n;
    } else if (videoId) {
        rows  = stmts.getAuditByVideo.all(videoId, limit);
        count = stmts.countAuditVideo.get(videoId).n;
    } else {
        rows  = stmts.getAuditAll.all(limit);
        count = stmts.countAudit.get().n;
    }
    return {
        entries: rows.map(r => ({
            fingerprint: r.fingerprint,
            userId:      r.user_id,
            videoId:     r.video_id,
            deviceId:    r.device_id,
            ip:          r.ip,
            userAgent:   r.user_agent,
            deliveredAt: r.delivered_at,
        })),
        total: count,
    };
};

// ================================================================
//  API — CATALOG
// ================================================================

function rowToCatalog(r) {
    if (!r) return null;
    return {
        videoId:      r.video_id,
        title:        r.title,
        status:       r.status,
        segmentCount: r.segment_count,
        keyId:        r.key_id,
        error:        r.error,
        uploadedAt:   r.uploaded_at,
        sourceType:   r.source_type || 'local',
        bunnyUrl:     r.bunny_url || null,
    };
}

module.exports.loadCatalog = () =>
    stmts.getCatalogAll.all().map(rowToCatalog);

module.exports.getCatalogById = (videoId) =>
    rowToCatalog(stmts.getCatalogById.get(videoId));

module.exports.addToCatalog = ({ videoId, title, status, segmentCount, keyId, error, uploadedAt, sourceType, bunnyUrl }) => {
    stmts.insertCatalog.run({
        video_id:      videoId,
        title:         title || videoId,
        status:        status || 'processing',
        segment_count: segmentCount || 0,
        key_id:        keyId || null,
        error:         error || null,
        uploaded_at:   uploadedAt || new Date().toISOString(),
        source_type:   sourceType || 'local',
        bunny_url:     bunnyUrl || null,
    });
};

module.exports.updateCatalogEntry = ({ videoId, status, segmentCount, keyId, error }) => {
    stmts.updateCatalogStatus.run({
        video_id:      videoId,
        status:        status || 'error',
        segment_count: segmentCount || 0,
        key_id:        keyId || null,
        error:         error || null,
    });
};

module.exports.deleteCatalogEntry = (videoId) =>
    stmts.deleteCatalog.run(videoId);

// ================================================================
//  SEED DE CATÁLOGO DESDE ENV VAR
//  Si CATALOG_SEED=<JSON> está definido, inserta los videos que
//  no existan aún. Permite sobrevivir reinicios en Render free tier.
//  Formato: JSON array de objetos con los mismos campos de addToCatalog.
// ================================================================
(function seedCatalogFromEnv() {
    const raw = process.env.CATALOG_SEED;
    if (!raw) return;
    let entries;
    try { entries = JSON.parse(raw); } catch { console.error('[db] CATALOG_SEED JSON inválido'); return; }
    if (!Array.isArray(entries)) return;
    for (const e of entries) {
        if (!e.videoId || !e.bunnyUrl) continue;
        const existing = stmts.getCatalogById.get(e.videoId);
        if (!existing) {
            try {
                stmts.insertCatalog.run({
                    video_id:      e.videoId,
                    title:         e.title || e.videoId,
                    status:        e.status || 'ready',
                    segment_count: e.segmentCount || 0,
                    key_id:        e.keyId || null,
                    error:         null,
                    uploaded_at:   e.uploadedAt || new Date().toISOString(),
                    source_type:   e.sourceType || 'bunny',
                    bunny_url:     e.bunnyUrl,
                });
                console.log('[db] Catálogo seed:', e.videoId, e.title);
            } catch (err) {
                console.error('[db] Error en seed:', err.message);
            }
        }
    }
})();

// Seed de dominios permitidos desde env var
(function seedDomainsFromEnv() {
    const raw = process.env.ALLOWED_DOMAINS_SEED;
    if (!raw) return;
    try {
        const domains = JSON.parse(raw);
        if (!Array.isArray(domains)) return;
        for (const d of domains) {
            if (typeof d === 'string' && d.trim()) {
                db.prepare('INSERT OR IGNORE INTO allowed_domains (domain) VALUES (?)').run(d.trim());
            }
        }
        console.log('[db] Dominios seed:', domains.length);
    } catch { console.error('[db] ALLOWED_DOMAINS_SEED JSON inválido'); }
})();

// ================================================================
//  API — SESIONES ACTIVAS
// ================================================================

/** Crea una sesión activa al iniciar reproducción */
module.exports.createSession = (sessionId, userId, videoId) => {
    const now = Date.now();
    stmts.insertSession.run(sessionId, userId, videoId, now, now);
};

/** Actualiza el timestamp de la sesión. Devuelve true si la sesión existía. */
module.exports.heartbeatSession = (sessionId) => {
    const result = stmts.heartbeatSession.run(Date.now(), sessionId);
    return result.changes > 0;
};

/** Elimina una sesión (alumno cerró sesión o terminó el video) */
module.exports.endSession = (sessionId) =>
    stmts.deleteSession.run(sessionId);

/** Cuenta sesiones activas de un usuario (inactivas >90s no cuentan) */
module.exports.countActiveSessions = (userId) => {
    const threshold = Date.now() - 90_000;
    return stmts.countActiveSessions.get(userId, threshold).n;
};

/** Elimina todas las sesiones cuyo último heartbeat fue hace >90s */
module.exports.cleanExpiredSessions = () => {
    const threshold = Date.now() - 90_000;
    stmts.cleanExpiredSessions.run(threshold);
};

// Exponer instancia para queries avanzadas si se necesitan
module.exports.db = db;

// ================================================================
//  API — ALLOWED DOMAINS
// ================================================================

module.exports.getAllowedDomains = () =>
    db.prepare('SELECT domain FROM allowed_domains ORDER BY domain').all().map(r => r.domain);

module.exports.addAllowedDomain = (domain) =>
    db.prepare('INSERT OR IGNORE INTO allowed_domains (domain) VALUES (?)').run(domain);

module.exports.removeAllowedDomain = (domain) =>
    db.prepare('DELETE FROM allowed_domains WHERE domain = ?').run(domain);
