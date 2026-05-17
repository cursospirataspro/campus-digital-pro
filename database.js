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
try { db.exec('ALTER TABLE catalog ADD COLUMN course_id TEXT'); } catch {}
try { db.exec('ALTER TABLE catalog ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0'); } catch {}
try { db.exec('ALTER TABLE catalog ADD COLUMN module_id TEXT'); } catch {}
try { db.exec("ALTER TABLE audit_log ADD COLUMN student_email TEXT NOT NULL DEFAULT ''"); } catch {}
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
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint   TEXT NOT NULL,
    user_id       TEXT NOT NULL,
    video_id      TEXT NOT NULL,
    device_id     TEXT NOT NULL DEFAULT 'desconocido',
    student_email TEXT NOT NULL DEFAULT '',
    ip            TEXT NOT NULL DEFAULT 'desconocida',
    user_agent    TEXT NOT NULL DEFAULT 'desconocido',
    delivered_at  TEXT NOT NULL
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
    bunny_url     TEXT,
    course_id     TEXT,
    sort_order    INTEGER NOT NULL DEFAULT 0,
    module_id     TEXT
);

CREATE TABLE IF NOT EXISTS active_sessions (
    session_id   TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    video_id     TEXT NOT NULL,
    started_at   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    current_time INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON active_sessions(user_id);

CREATE TABLE IF NOT EXISTS allowed_domains (
    domain TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS courses (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    author     TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_catalog_course ON catalog(course_id);

CREATE TABLE IF NOT EXISTS modules (
    id         TEXT PRIMARY KEY,
    course_id  TEXT NOT NULL,
    parent_id  TEXT,
    name       TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_modules_course ON modules(course_id);
CREATE INDEX IF NOT EXISTS idx_modules_parent ON modules(parent_id);

CREATE TABLE IF NOT EXISTS app_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

-- ================================================================
--  AUDITORÍA DEL REPRODUCTOR
-- ================================================================

-- Progreso real de reproducción por alumno+video
CREATE TABLE IF NOT EXISTS playback_progress (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      TEXT NOT NULL,
    video_id     TEXT NOT NULL,
    session_id   TEXT NOT NULL,
    duration_secs INTEGER NOT NULL DEFAULT 0,
    position_secs INTEGER NOT NULL DEFAULT 0,
    wall_secs    INTEGER NOT NULL DEFAULT 0,
    speed_max    REAL    NOT NULL DEFAULT 1.0,
    updated_at   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pp_user_video ON playback_progress(user_id, video_id);
CREATE INDEX IF NOT EXISTS idx_pp_session    ON playback_progress(session_id);

-- Registro de solicitudes HLS por sesión
CREATE TABLE IF NOT EXISTS hls_requests (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    video_id     TEXT NOT NULL,
    req_type     TEXT NOT NULL DEFAULT 'segment',
    requested_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hls_session ON hls_requests(session_id);
CREATE INDEX IF NOT EXISTS idx_hls_user    ON hls_requests(user_id, video_id);

-- Flags de auditoría para revisión manual
CREATE TABLE IF NOT EXISTS audit_flags (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      TEXT NOT NULL,
    video_id     TEXT NOT NULL,
    email        TEXT NOT NULL DEFAULT '',
    course_id    TEXT,
    flag_type    TEXT NOT NULL,
    factor       REAL NOT NULL DEFAULT 0,
    details      TEXT NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL DEFAULT 'new',
    note         TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    reviewed_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_flags_user   ON audit_flags(user_id);
CREATE INDEX IF NOT EXISTS idx_flags_video  ON audit_flags(video_id);
CREATE INDEX IF NOT EXISTS idx_flags_status ON audit_flags(status);
`);

// Migraciones para DBs existentes (en BD nueva ya vienen en el CREATE TABLE)
try { db.exec('ALTER TABLE active_sessions ADD COLUMN current_time INTEGER NOT NULL DEFAULT 0'); } catch {}
try { db.exec('ALTER TABLE catalog ADD COLUMN duration_secs INTEGER NOT NULL DEFAULT 0'); } catch {}

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
        INSERT INTO audit_log (fingerprint, user_id, video_id, device_id, student_email, ip, user_agent, delivered_at)
        VALUES (@fingerprint, @user_id, @video_id, @device_id, @student_email, @ip, @user_agent, @delivered_at)
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
    getCatalogByCourse:   db.prepare('SELECT * FROM catalog WHERE course_id = ? ORDER BY sort_order ASC, uploaded_at DESC'),
    getCatalogUnassigned: db.prepare('SELECT * FROM catalog WHERE course_id IS NULL ORDER BY uploaded_at DESC'),
    insertCatalog:        db.prepare(`
        INSERT OR REPLACE INTO catalog (video_id, title, status, segment_count, key_id, error, uploaded_at, source_type, bunny_url, course_id, sort_order)
        VALUES (@video_id, @title, @status, @segment_count, @key_id, @error, @uploaded_at, @source_type, @bunny_url, @course_id, @sort_order)
    `),
    updateCatalogStatus:  db.prepare(`
        UPDATE catalog SET status=@status, segment_count=@segment_count, key_id=@key_id, error=@error WHERE video_id=@video_id
    `),
    updateCatalogCourse:  db.prepare('UPDATE catalog SET course_id = ?, sort_order = ? WHERE video_id = ?'),
    updateCatalogSort:    db.prepare('UPDATE catalog SET sort_order = ? WHERE video_id = ?'),
    deleteCatalog:        db.prepare('DELETE FROM catalog WHERE video_id = ?'),

    // --- Modules ---
    getAllModulesByCourse:    db.prepare('SELECT * FROM modules WHERE course_id = ? ORDER BY sort_order ASC, created_at ASC'),
    getModuleById:           db.prepare('SELECT * FROM modules WHERE id = ?'),
    insertModule:            db.prepare('INSERT INTO modules (id, course_id, parent_id, name, sort_order, created_at) VALUES (@id, @course_id, @parent_id, @name, @sort_order, @created_at)'),
    updateModule:            db.prepare('UPDATE modules SET name = @name, sort_order = @sort_order WHERE id = @id'),
    deleteModule:            db.prepare('DELETE FROM modules WHERE id = ?'),
    deleteModuleChildren:    db.prepare('DELETE FROM modules WHERE parent_id = ?'),
    deleteModulesByCourse:   db.prepare('DELETE FROM modules WHERE course_id = ?'),
    unassignModuleVideos:    db.prepare('UPDATE catalog SET module_id = NULL WHERE module_id = ?'),
    updateCatalogModule:     db.prepare('UPDATE catalog SET module_id = ? WHERE video_id = ?'),

    // --- Config ---
    getConfig:  db.prepare('SELECT value FROM app_config WHERE key = ?'),
    setConfig:  db.prepare('INSERT OR REPLACE INTO app_config (key, value) VALUES (?, ?)'),

    // --- Courses ---
    getAllCourses:        db.prepare('SELECT * FROM courses ORDER BY sort_order ASC, created_at DESC'),
    getCourseById:        db.prepare('SELECT * FROM courses WHERE id = ?'),
    insertCourse:         db.prepare('INSERT INTO courses (id, name, author, sort_order, created_at) VALUES (@id, @name, @author, @sort_order, @created_at)'),
    updateCourse:         db.prepare('UPDATE courses SET name = @name, author = @author WHERE id = @id'),
    deleteCourse:         db.prepare('DELETE FROM courses WHERE id = ?'),
    unassignCourseVideos: db.prepare('UPDATE catalog SET course_id = NULL WHERE course_id = ?'),

    // --- Sessions ---
    insertSession:        db.prepare('INSERT INTO active_sessions (session_id, user_id, video_id, started_at, last_seen) VALUES (?, ?, ?, ?, ?)'),
    heartbeatSession:     db.prepare('UPDATE active_sessions SET last_seen = ?, current_time = ? WHERE session_id = ?'),
    getActiveByUser:      db.prepare('SELECT * FROM active_sessions WHERE user_id = ? AND last_seen > ?'),
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

module.exports.logDelivery = ({ fingerprint, userId, videoId, deviceId, studentEmail, ip, userAgent }) => {
    stmts.insertAudit.run({
        fingerprint,
        user_id: userId,
        video_id: videoId,
        device_id: deviceId || 'desconocido',
        student_email: studentEmail || '',
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
            fingerprint:  r.fingerprint,
            userId:       r.user_id,
            videoId:      r.video_id,
            deviceId:     r.device_id,
            studentEmail: r.student_email || '',
            ip:           r.ip,
            userAgent:    r.user_agent,
            deliveredAt:  r.delivered_at,
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
        courseId:     r.course_id || null,
        sortOrder:    r.sort_order || 0,
        moduleId:     r.module_id || null,
    };
}

module.exports.loadCatalog = () =>
    stmts.getCatalogAll.all().map(rowToCatalog);

module.exports.getCatalogById = (videoId) =>
    rowToCatalog(stmts.getCatalogById.get(videoId));

module.exports.addToCatalog = ({ videoId, title, status, segmentCount, keyId, error, uploadedAt, sourceType, bunnyUrl, courseId, sortOrder }) => {
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
        course_id:     courseId || null,
        sort_order:    sortOrder || 0,
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
//  SEED DE CURSOS DESDE ENV VAR
//  Si COURSES_SEED=<JSON> está definido, inserta los cursos preservando IDs.
// ================================================================
(function seedCoursesFromEnv() {
    const raw = process.env.COURSES_SEED;
    if (!raw) return;
    let entries;
    try { entries = JSON.parse(raw); } catch { console.error('[db] COURSES_SEED JSON inválido'); return; }
    if (!Array.isArray(entries)) return;
    for (const c of entries) {
        if (!c.id || !c.name) continue;
        const existing = stmts.getCourseById.get(c.id);
        if (!existing) {
            try {
                stmts.insertCourse.run({
                    id:         c.id,
                    name:       c.name,
                    author:     c.author || '',
                    sort_order: c.sortOrder || 0,
                    created_at: c.createdAt || new Date().toISOString(),
                });
                console.log('[db] Curso seed:', c.id, c.name);
            } catch (err) { console.error('[db] Error en curso seed:', err.message); }
        }
    }
})();

// ================================================================
//  SEED DE CATÁLOGO DESDE ENV VAR
//  Soporta CATALOG_SEED (array completo) o CATALOG_SEED_1 + CATALOG_SEED_2
//  (partes divididas para evitar el límite de 128KB por variable del OS).
// ================================================================
(function seedCatalogFromEnv() {
    let entries = [];
    if (process.env.CATALOG_SEED) {
        try { entries = JSON.parse(process.env.CATALOG_SEED); }
        catch { console.error('[db] CATALOG_SEED JSON inválido'); return; }
    } else {
        const p1 = process.env.CATALOG_SEED_1;
        const p2 = process.env.CATALOG_SEED_2;
        const p3 = process.env.CATALOG_SEED_3;
        if (!p1) return;
        try {
            if (p1) entries.push(...JSON.parse(p1));
            if (p2) entries.push(...JSON.parse(p2));
            if (p3) entries.push(...JSON.parse(p3));
        } catch { console.error('[db] CATALOG_SEED_N JSON inválido'); return; }
    }
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
                    course_id:     e.courseId || null,
                    sort_order:    e.sortOrder || 0,
                });
            } catch (err) { console.error('[db] Error en seed:', err.message); }
        }
    }
    console.log('[db] Catálogo seed completado');
})();

// Seed de dominios permitidos desde env var
// Dominios predeterminados — siempre presentes (se re-insertan en cada inicio)
(function seedDefaultDomains() {
    const DEFAULTS = [
        'https://campusdigitalpro.com',
        'https://campusdigitalpro.com/student',
        'https://campusdigitalpro.com/student/course',
    ];
    const ins = db.prepare('INSERT OR IGNORE INTO allowed_domains (domain) VALUES (?)');
    for (const d of DEFAULTS) ins.run(d);
    console.log('[db] Dominios predeterminados insertados:', DEFAULTS.length);
})();

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

/** Actualiza el timestamp y posición actual de la sesión. Devuelve true si existía. */
module.exports.heartbeatSession = (sessionId, currentTime) => {
    const ct = Math.floor(Number(currentTime) || 0);
    const result = stmts.heartbeatSession.run(Date.now(), ct, sessionId);
    return result.changes > 0;
};

/** Obtiene sesiones activas de un usuario (inactivas >90s no cuentan) */
module.exports.getActiveSessionsByUser = (userId) => {
    const threshold = Date.now() - 90_000;
    return stmts.getActiveByUser.all(userId, threshold);
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

// ================================================================
//  API — COURSES
// ================================================================

function rowToCourse(r) {
    if (!r) return null;
    return { id: r.id, name: r.name, author: r.author, sortOrder: r.sort_order, createdAt: r.created_at };
}

module.exports.getAllCourses = () =>
    stmts.getAllCourses.all().map(rowToCourse);

module.exports.getCourseById = (id) =>
    rowToCourse(stmts.getCourseById.get(id));

module.exports.createCourse = ({ id, name, author, sortOrder }) => {
    stmts.insertCourse.run({ id, name, author: author || '', sort_order: sortOrder || 0, created_at: new Date().toISOString() });
    return rowToCourse(stmts.getCourseById.get(id));
};

module.exports.updateCourse = (id, { name, author }) => {
    stmts.updateCourse.run({ id, name, author: author || '' });
    return rowToCourse(stmts.getCourseById.get(id));
};

module.exports.deleteCourse = (id) => {
    stmts.unassignCourseVideos.run(id);
    stmts.deleteModulesByCourse.run(id);
    stmts.deleteCourse.run(id);
};

module.exports.moveVideoToCourse = (videoId, courseId) => {
    const maxSort = db.prepare('SELECT COALESCE(MAX(sort_order),0) as m FROM catalog WHERE course_id = ?').get(courseId || null);
    stmts.updateCatalogCourse.run(courseId || null, (maxSort?.m || 0) + 1, videoId);
};

module.exports.reorderVideos = (videoOrders) => {
    const tx = db.transaction((items) => {
        for (const { videoId, sortOrder } of items) {
            stmts.updateCatalogSort.run(sortOrder, videoId);
        }
    });
    tx(videoOrders);
};

module.exports.getCatalogByCourse = (courseId) =>
    stmts.getCatalogByCourse.all(courseId).map(rowToCatalog);

module.exports.getCatalogUnassigned = () =>
    stmts.getCatalogUnassigned.all().map(rowToCatalog);

// ================================================================
//  API — MODULES
// ================================================================

function rowToModule(r) {
    if (!r) return null;
    return { id: r.id, courseId: r.course_id, parentId: r.parent_id || null, name: r.name, sortOrder: r.sort_order, createdAt: r.created_at };
}

module.exports.getModulesByCourse = (courseId) =>
    stmts.getAllModulesByCourse.all(courseId).map(rowToModule);

module.exports.getModuleById = (id) =>
    rowToModule(stmts.getModuleById.get(id));

module.exports.createModule = ({ id, courseId, parentId, name, sortOrder }) => {
    stmts.insertModule.run({
        id, course_id: courseId, parent_id: parentId || null,
        name: name.trim().slice(0, 120), sort_order: sortOrder || 0,
        created_at: new Date().toISOString(),
    });
    return rowToModule(stmts.getModuleById.get(id));
};

module.exports.updateModule = (id, { name, sortOrder }) => {
    const existing = stmts.getModuleById.get(id);
    if (!existing) return null;
    stmts.updateModule.run({ id, name: name.trim().slice(0, 120), sort_order: sortOrder !== undefined ? sortOrder : existing.sort_order });
    return rowToModule(stmts.getModuleById.get(id));
};

/** Elimina un módulo, sus hijos, y desasigna los videos */
module.exports.deleteModule = (id) => {
    const tx = db.transaction(() => {
        // Desasignar videos del módulo
        stmts.unassignModuleVideos.run(id);
        // Obtener hijos directos y limpiarlos recursivamente
        const children = stmts.getAllModulesByCourse.all(
            stmts.getModuleById.get(id)?.course_id || ''
        ).filter(m => m.parent_id === id);
        for (const child of children) {
            stmts.unassignModuleVideos.run(child.id);
            stmts.deleteModuleChildren.run(child.id);
            stmts.deleteModule.run(child.id);
        }
        stmts.deleteModuleChildren.run(id);
        stmts.deleteModule.run(id);
    });
    tx();
};

/** Elimina todos los módulos de un curso (al borrar el curso) */
module.exports.deleteModulesByCourse = (courseId) => {
    stmts.deleteModulesByCourse.run(courseId);
};

/** Asigna un video a un módulo (o lo desasigna si moduleId=null) */
module.exports.moveVideoToModule = (videoId, moduleId) => {
    stmts.updateCatalogModule.run(moduleId || null, videoId);
};

// ================================================================
//  API — APP CONFIG
// ================================================================

module.exports.getConfig = (key) => {
    const row = stmts.getConfig.get(key);
    return row ? row.value : null;
};

module.exports.setConfig = (key, value) => {
    stmts.setConfig.run(key, value);
};

// ================================================================
//  PLAYBACK SESSIONS EXTERNAS
//  Tabla para sesiones iniciadas desde reproductores externos.
//  No toca ninguna tabla existente.
// ================================================================

// Migración no destructiva: añade event_type a audit_log si no existe
try { db.exec('ALTER TABLE audit_log ADD COLUMN event_type TEXT'); } catch {}

// Tabla nueva exclusiva para sesiones de reproducción externas
db.exec(`
CREATE TABLE IF NOT EXISTS playback_sessions (
    session_id    TEXT PRIMARY KEY,
    student_id    TEXT NOT NULL,
    student_email TEXT NOT NULL,
    course_id     TEXT NOT NULL,
    lesson_id     TEXT NOT NULL,
    device_id     TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS playback_event_dedupe (
    idempotency_key TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dedupe_created_at ON playback_event_dedupe(created_at);
`);

const pbStmts = {
    insertSession:  db.prepare(`
        INSERT INTO playback_sessions (session_id, student_id, student_email, course_id, lesson_id, device_id, created_at, expires_at)
        VALUES (@session_id, @student_id, @student_email, @course_id, @lesson_id, @device_id, @created_at, @expires_at)
    `),
    getSession:     db.prepare('SELECT * FROM playback_sessions WHERE session_id = ?'),
    deleteSession:  db.prepare('DELETE FROM playback_sessions WHERE session_id = ?'),
    deleteExpired:  db.prepare("DELETE FROM playback_sessions WHERE expires_at < ?"),
    insertDedupe:   db.prepare('INSERT OR IGNORE INTO playback_event_dedupe (idempotency_key, session_id, created_at) VALUES (?, ?, ?)'),
    deleteOldDedupe: db.prepare("DELETE FROM playback_event_dedupe WHERE created_at < ?"),
    insertEvent:    db.prepare(`
        INSERT INTO audit_log (fingerprint, user_id, video_id, device_id, ip, user_agent, delivered_at, event_type)
        VALUES (@fingerprint, @user_id, @video_id, @device_id, @ip, @user_agent, @delivered_at, @event_type)
    `),
};

/** Crea una sesión de reproducción externa. expires_at = ahora + ttlSeconds */
module.exports.createPlaybackSession = ({ sessionId, studentId, studentEmail, courseId, lessonId, deviceId, ttlSeconds = 900 }) => {
    const now = new Date();
    const expires = new Date(now.getTime() + ttlSeconds * 1000);
    pbStmts.insertSession.run({
        session_id:    sessionId,
        student_id:    studentId,
        student_email: studentEmail,
        course_id:     courseId,
        lesson_id:     lessonId,
        device_id:     deviceId,
        created_at:    now.toISOString(),
        expires_at:    expires.toISOString(),
    });
};

/** Obtiene una sesión por sessionId. Devuelve null si no existe. */
module.exports.getPlaybackSession = (sessionId) => {
    const row = pbStmts.getSession.get(sessionId);
    if (!row) return null;
    return {
        sessionId:    row.session_id,
        studentId:    row.student_id,
        studentEmail: row.student_email,
        courseId:     row.course_id,
        lessonId:     row.lesson_id,
        deviceId:     row.device_id,
        createdAt:    row.created_at,
        expiresAt:    row.expires_at,
    };
};

/** Finaliza explícitamente una sesión de reproducción externa. */
module.exports.endPlaybackSession = (sessionId) => {
    pbStmts.deleteSession.run(sessionId);
};

/**
 * Registra una llave de idempotencia para eventos de playback.
 * Devuelve true si es primera vez; false si el evento es duplicado/replay.
 */
module.exports.claimPlaybackEventIdempotency = (idempotencyKey, sessionId) => {
    const result = pbStmts.insertDedupe.run(idempotencyKey, sessionId, new Date().toISOString());
    return result.changes > 0;
};

/** Registra un evento de reproducción en audit_log con su event_type */
module.exports.logPlaybackEvent = ({ sessionId, studentId, lessonId, deviceId, ip, userAgent, eventType, extra }) => {
    const fp = `pb:${sessionId}:${eventType}:${Date.now()}`;
    pbStmts.insertEvent.run({
        fingerprint:  fp,
        user_id:      studentId,
        video_id:     lessonId,
        device_id:    deviceId || 'unknown',
        ip:           ip || 'unknown',
        user_agent:   userAgent || 'unknown',
        delivered_at: new Date().toISOString(),
        event_type:   eventType,
    });
};

/** Limpia sesiones expiradas de la tabla playback_sessions */
module.exports.cleanExpiredPlaybackSessions = () => {
    pbStmts.deleteExpired.run(new Date().toISOString());
};

// ================================================================
//  MÉTRICAS POR ALUMNO — para el Dashboard y Monitor API
// ================================================================

// Queries SQL ejecutadas en el momento (no preparadas porque usan GROUP BY)
const _qVideosByUser   = db.prepare('SELECT DISTINCT video_id, MAX(delivered_at) as last_at FROM audit_log WHERE user_id = ? GROUP BY video_id');
const _qTimeByUser     = db.prepare('SELECT video_id, MAX(current_time) as max_time FROM active_sessions WHERE user_id = ? GROUP BY video_id');
const _qLastAccess     = db.prepare('SELECT MAX(delivered_at) as last_at FROM audit_log WHERE user_id = ?');
const _qAllModules     = db.prepare('SELECT * FROM modules ORDER BY course_id, sort_order ASC');
const _qAllSessions    = db.prepare('SELECT * FROM active_sessions WHERE user_id = ? ORDER BY last_seen DESC');

/**
 * Devuelve métricas de actividad por alumno.
 * Para cada alumno: videos vistos, cursos activos, módulos, tiempo total, último acceso.
 */
module.exports.getStudentMetrics = () => {
    const students = stmts.getAllStudents.all();
    const catalog  = stmts.getCatalogAll.all();
    const courses  = stmts.getAllCourses.all();

    // Índices rápidos
    const vidMap    = {};
    const courseMap = {};
    for (const v of catalog)  vidMap[v.video_id]  = v;
    for (const c of courses)  courseMap[c.id]      = c;

    return students.map(s => {
        const videos   = _qVideosByUser.all(s.id);   // [{video_id, last_at}]
        const sessions = _qTimeByUser.all(s.id);     // [{video_id, max_time}]

        // Tiempo total = suma del max current_time de cada video visto
        const tiempoTotalSeg = sessions.reduce((sum, r) => sum + (r.max_time || 0), 0);

        // Cursos y módulos distintos donde el alumno tiene actividad
        const courseIds = new Set();
        const moduleIds = new Set();
        for (const ev of videos) {
            const v = vidMap[ev.video_id];
            if (v?.course_id) courseIds.add(v.course_id);
            if (v?.module_id) moduleIds.add(v.module_id);
        }

        // Detalles por curso
        const cursosDetalle = [...courseIds].map(cId => {
            const vidsEnCurso = videos.filter(ev => vidMap[ev.video_id]?.course_id === cId);
            return {
                courseId:   cId,
                courseName: courseMap[cId]?.name || cId,
                clases:     vidsEnCurso.length,
            };
        });

        const lastAccess = _qLastAccess.get(s.id)?.last_at || s.last_login || null;

        return {
            studentId:      s.student_id,
            email:          s.email,
            name:           s.name  || '',
            active:         s.active === 1,
            videosVistos:   videos.length,
            cursosActivos:  courseIds.size,
            modulosVistos:  moduleIds.size,
            tiempoTotalSeg,
            ultimoAcceso:   lastAccess,
            deviceBound:    !!s.device_id,
            cursos:         cursosDetalle,
        };
    });
};

/** Devuelve todos los módulos de todas las secciones */
module.exports.getAllModules = () => _qAllModules.all();

/** Devuelve todas las sesiones (activas e históricas) de un usuario */
module.exports.getSessionsByUser = (userId) => _qAllSessions.all(userId);

/** Limpia llaves de idempotencia antiguas (retención 48 horas). */
module.exports.cleanOldPlaybackDedupe = () => {
    const threshold = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString();
    pbStmts.deleteOldDedupe.run(threshold);
};

// ================================================================
//  AUDITORÍA DEL REPRODUCTOR — statements y funciones
// ================================================================

const auditStmts = {
    // playback_progress
    upsertProgress: db.prepare(`
        INSERT INTO playback_progress (user_id, video_id, session_id, duration_secs, position_secs, wall_secs, speed_max, updated_at)
        VALUES (@user_id, @video_id, @session_id, @duration_secs, @position_secs, @wall_secs, @speed_max, @updated_at)
        ON CONFLICT(id) DO NOTHING
    `),
    updateProgress: db.prepare(`
        UPDATE playback_progress
        SET duration_secs = MAX(duration_secs, @duration_secs),
            position_secs = MAX(position_secs, @position_secs),
            wall_secs     = MAX(wall_secs,     @wall_secs),
            speed_max     = MAX(speed_max,     @speed_max),
            updated_at    = @updated_at
        WHERE session_id = @session_id
    `),
    getProgressBySession: db.prepare('SELECT * FROM playback_progress WHERE session_id = ? LIMIT 1'),
    getProgressByUserVideo: db.prepare('SELECT * FROM playback_progress WHERE user_id = ? AND video_id = ? ORDER BY updated_at DESC'),
    getAllProgressByUser:  db.prepare('SELECT * FROM playback_progress WHERE user_id = ? ORDER BY updated_at DESC'),

    // hls_requests
    insertHlsReq: db.prepare('INSERT INTO hls_requests (session_id, user_id, video_id, req_type, requested_at) VALUES (?, ?, ?, ?, ?)'),
    countHlsReqs: db.prepare('SELECT COUNT(*) as n, MIN(requested_at) as first_req, MAX(requested_at) as last_req FROM hls_requests WHERE session_id = ? AND req_type = ?'),
    countHlsWindow: db.prepare('SELECT COUNT(*) as n FROM hls_requests WHERE session_id = ? AND requested_at > ?'),

    // audit_flags
    insertFlag: db.prepare(`
        INSERT INTO audit_flags (user_id, video_id, email, course_id, flag_type, factor, details, status, note, created_at)
        VALUES (@user_id, @video_id, @email, @course_id, @flag_type, @factor, @details, 'new', '', @created_at)
    `),
    getAllFlags:    db.prepare(`
        SELECT f.*, c.title as video_title, co.name as course_name
        FROM audit_flags f
        LEFT JOIN catalog c  ON c.video_id  = f.video_id
        LEFT JOIN courses co ON co.id        = f.course_id
        ORDER BY f.created_at DESC
        LIMIT ?
    `),
    getFlagsByStatus: db.prepare(`
        SELECT f.*, c.title as video_title, co.name as course_name
        FROM audit_flags f
        LEFT JOIN catalog c  ON c.video_id  = f.video_id
        LEFT JOIN courses co ON co.id        = f.course_id
        WHERE f.status = ?
        ORDER BY f.created_at DESC
        LIMIT ?
    `),
    updateFlagStatus: db.prepare('UPDATE audit_flags SET status = ?, note = ?, reviewed_at = ? WHERE id = ?'),
    getFlag:          db.prepare('SELECT * FROM audit_flags WHERE id = ?'),

    // catalog duration
    updateDuration: db.prepare('UPDATE catalog SET duration_secs = ? WHERE video_id = ? AND duration_secs < ?'),
};

/**
 * Registra / actualiza el progreso de reproducción de una sesión.
 * Llamado por el heartbeat y por /api/session/progress
 */
module.exports.upsertPlaybackProgress = ({ sessionId, userId, videoId, durationSecs, positionSecs, wallSecs, speedMax }) => {
    const now = new Date().toISOString();
    const existing = auditStmts.getProgressBySession.get(sessionId);
    if (!existing) {
        auditStmts.upsertProgress.run({
            user_id: userId, video_id: videoId, session_id: sessionId,
            duration_secs: durationSecs || 0, position_secs: positionSecs || 0,
            wall_secs: wallSecs || 0, speed_max: speedMax || 1.0, updated_at: now,
        });
    } else {
        auditStmts.updateProgress.run({
            session_id: sessionId,
            duration_secs: durationSecs || 0, position_secs: positionSecs || 0,
            wall_secs: wallSecs || 0, speed_max: speedMax || 1.0, updated_at: now,
        });
    }
    // actualizar duración en catalog si es mayor
    if (durationSecs > 0) {
        auditStmts.updateDuration.run(durationSecs, videoId, durationSecs);
    }
};

/** Registra una solicitud HLS (manifest o segment) */
module.exports.logHlsRequest = (sessionId, userId, videoId, reqType) => {
    try { auditStmts.insertHlsReq.run(sessionId, userId, videoId, reqType || 'segment', Date.now()); } catch {}
};

/**
 * Analiza una sesión al terminar y genera flags de auditoría si hay anomalías.
 * MAX_SPEED = 2.0 (velocidad máxima permitida por el reproductor)
 */
const MAX_SPEED = 2.0;

module.exports.analyzeSession = (sessionId) => {
    const prog = auditStmts.getProgressBySession.get(sessionId);
    if (!prog || prog.duration_secs <= 0 || prog.wall_secs <= 0) return null;

    const durationSecs = prog.duration_secs;
    const wallSecs     = prog.wall_secs;
    const positionSecs = prog.position_secs;
    const minTime      = durationSecs / MAX_SPEED; // tiempo mínimo razonable

    const percentWatched = Math.min(100, Math.round((positionSecs / durationSecs) * 100));
    const factor         = parseFloat((durationSecs / wallSecs).toFixed(2));

    let flagType = null;
    if (factor > MAX_SPEED * 1.5) {
        flagType = 'posible_grabacion_acelerada'; // ej: completó 1h en 12min → factor 5x
    } else if (percentWatched >= 90 && wallSecs < minTime * 0.7) {
        flagType = 'consumo_rapido'; // vio +90% pero en menos del 70% del tiempo mínimo
    }

    // HLS bulk: muchos segmentos pedidos muy rápido
    const hlsStats   = auditStmts.countHlsReqs.get(sessionId, 'segment');
    const segCount   = hlsStats?.n || 0;
    const hlsWindow  = (hlsStats?.last_req - hlsStats?.first_req) || 0; // ms
    if (segCount > 20 && hlsWindow > 0 && hlsWindow < wallSecs * 1000 * 0.3) {
        // más de 20 segmentos pedidos en menos del 30% del tiempo real
        flagType = 'posible_extraccion_hls';
    }

    if (!flagType) return null; // reproducción normal

    const student = db.prepare('SELECT email, allowed_videos FROM students WHERE id = ?').get(prog.user_id);
    const video   = db.prepare('SELECT course_id FROM catalog WHERE video_id = ?').get(prog.video_id);

    auditStmts.insertFlag.run({
        user_id:    prog.user_id,
        video_id:   prog.video_id,
        email:      student?.email || '',
        course_id:  video?.course_id || null,
        flag_type:  flagType,
        factor,
        details:    JSON.stringify({
            durationSecs, wallSecs, positionSecs, percentWatched,
            factor, segCount, hlsWindowMs: hlsWindow, minTimeSecs: Math.round(minTime),
        }),
        created_at: new Date().toISOString(),
    });

    return flagType;
};

/** Devuelve todos los flags (con join de título de video y nombre de curso) */
module.exports.getAuditFlags = ({ status, limit = 200 } = {}) => {
    const rows = status
        ? auditStmts.getFlagsByStatus.all(status, limit)
        : auditStmts.getAllFlags.all(limit);
    return rows.map(r => ({
        id:          r.id,
        userId:      r.user_id,
        videoId:     r.video_id,
        email:       r.email,
        courseId:    r.course_id,
        videoTitle:  r.video_title || r.video_id,
        courseName:  r.course_name || '—',
        flagType:    r.flag_type,
        factor:      r.factor,
        details:     (() => { try { return JSON.parse(r.details); } catch { return {}; } })(),
        status:      r.status,
        note:        r.note,
        createdAt:   r.created_at,
        reviewedAt:  r.reviewed_at || null,
    }));
};

/** Actualiza estado de un flag (revisado, falso positivo, en observación, nota) */
module.exports.updateAuditFlag = (id, { status, note }) => {
    auditStmts.updateFlagStatus.run(
        status || 'reviewed',
        note   || '',
        new Date().toISOString(),
        id,
    );
    return auditStmts.getFlag.get(id);
};

/** Estadísticas diarias por alumno — cuánto contenido consumió hoy */
module.exports.getDailyStats = (userId, dateStr) => {
    const dayStart = new Date(dateStr + 'T00:00:00.000Z').toISOString();
    const dayEnd   = new Date(dateStr + 'T23:59:59.999Z').toISOString();
    return db.prepare(`
        SELECT pp.video_id, c.title, c.course_id, c.duration_secs,
               MAX(pp.position_secs) as position_secs,
               SUM(pp.wall_secs)     as wall_secs_total,
               ROUND(MAX(pp.position_secs) * 100.0 / NULLIF(c.duration_secs, 0)) as percent
        FROM playback_progress pp
        LEFT JOIN catalog c ON c.video_id = pp.video_id
        WHERE pp.user_id = ? AND pp.updated_at >= ? AND pp.updated_at <= ?
        GROUP BY pp.video_id
        ORDER BY pp.updated_at DESC
    `).all(userId, dayStart, dayEnd);
};

// ================================================================
//  HIDRATACIÓN DESDE GOOGLE SHEETS
//  Llamar al arrancar el servidor para restaurar datos persistentes.
// ================================================================

/**
 * Inserta/actualiza alumnos, cursos y módulos que vienen de Sheets.
 * Es idempotente: si el registro ya existe (mismo id) lo ignora.
 */
module.exports.hydrateFromSheets = ({ students = [], courses = [], modules = [], catalog = [] } = {}) => {
    const insertOrIgnoreStudent = db.prepare(`
        INSERT OR IGNORE INTO students
            (id, email, student_id, name, active, allowed_videos, device_id, created_at, last_login)
        VALUES (@id, @email, @student_id, @name, @active, @allowed_videos, @device_id, @created_at, @last_login)
    `);
    const insertOrIgnoreCourse = db.prepare(`
        INSERT OR IGNORE INTO courses (id, name, author, sort_order, created_at)
        VALUES (@id, @name, @author, @sort_order, @created_at)
    `);
    const insertOrIgnoreModule = db.prepare(`
        INSERT OR IGNORE INTO modules (id, course_id, parent_id, name, sort_order, created_at)
        VALUES (@id, @course_id, @parent_id, @name, @sort_order, @created_at)
    `);
    const insertOrIgnoreVideo = db.prepare(`
        INSERT OR IGNORE INTO catalog
            (video_id, title, status, segment_count, key_id, uploaded_at, source_type, bunny_url, course_id, sort_order, module_id)
        VALUES (@video_id, @title, @status, @segment_count, @key_id, @uploaded_at, @source_type, @bunny_url, @course_id, @sort_order, @module_id)
    `);

    const txStudents = db.transaction((rows) => {
        for (const s of rows) {
            try {
                insertOrIgnoreStudent.run({
                    id: s.id, email: (s.email || '').toLowerCase(),
                    student_id: s.id, name: s.name || '',
                    active: s.active === '0' ? 0 : 1,
                    allowed_videos: s.allowedVideos || '*',
                    device_id: s.deviceId || null,
                    created_at: s.createdAt || new Date().toISOString(),
                    last_login: s.lastLogin || null,
                });
            } catch {}
        }
    });

    const txCourses = db.transaction((rows) => {
        for (const c of rows) {
            try {
                insertOrIgnoreCourse.run({
                    id: c.id, name: c.name || '', author: c.author || '',
                    sort_order: 0, created_at: c.createdAt || new Date().toISOString(),
                });
            } catch {}
        }
    });

    const txModules = db.transaction((rows) => {
        for (const m of rows) {
            try {
                insertOrIgnoreModule.run({
                    id: m.id, course_id: m.courseId || '', parent_id: m.parentId || null,
                    name: m.name || '', sort_order: parseInt(m.sortOrder) || 0,
                    created_at: m.createdAt || new Date().toISOString(),
                });
                // Asociar video al módulo si existe
                if (m.videoId) {
                    db.prepare('UPDATE catalog SET module_id = ? WHERE video_id = ? AND module_id IS NULL').run(m.id, m.videoId);
                    db.prepare('UPDATE modules SET video_id = ? WHERE id = ?').run(m.videoId, m.id);
                }
            } catch {}
        }
    });

    const txVideos = db.transaction((rows) => {
        for (const v of rows) {
            try {
                insertOrIgnoreVideo.run({
                    video_id: v.videoId, title: v.title || '',
                    status: v.status || 'ready',
                    segment_count: 0, key_id: null, error: null,
                    uploaded_at: v.uploadedAt || new Date().toISOString(),
                    source_type: 'bunny', bunny_url: null,
                    course_id: v.courseId || null,
                    sort_order: parseInt(v.sortOrder) || 0,
                    module_id: v.moduleId || null,
                });
            } catch {}
        }
    });

    let loaded = { students: 0, courses: 0, modules: 0, videos: 0 };
    try { txStudents(students); loaded.students = students.length; } catch {}
    try { txCourses(courses);   loaded.courses  = courses.length;  } catch {}
    try { txModules(modules);   loaded.modules  = modules.length;  } catch {}
    try { txVideos(catalog);    loaded.videos   = catalog.length;  } catch {}

    console.log(`[db] hydrateFromSheets: ${loaded.students} alumnos, ${loaded.courses} cursos, ${loaded.modules} módulos, ${loaded.videos} videos`);
    return loaded;
};

