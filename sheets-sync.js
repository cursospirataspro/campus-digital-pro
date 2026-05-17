/**
 * sheets-sync.js
 * ============================================================
 * Google Sheets como base de datos persistente para Render.
 *
 * Problema: Render usa SQLite efímero → cada reinicio borra todos
 * los datos (alumnos, cursos, eventos, etc.).
 *
 * Solución: cada escritura va a SQLite (rápido) + Google Sheets
 * (persistente). Al reiniciar Render, se re-hidrata desde Sheets.
 *
 * Variables de entorno requeridas en Render:
 *   GOOGLE_SHEET_ID  = ID del Google Sheet (el string largo de la URL)
 *   GOOGLE_SA_JSON   = JSON completo de la cuenta de servicio (en una sola línea)
 *
 * Permisos: compartir el Sheet con el email de la cuenta de servicio
 * con rol "Editor".
 * ============================================================
 */

'use strict';

const { google } = require('googleapis');

const SHEET_ID = process.env.GOOGLE_SHEET_ID || '';
const SA_JSON  = process.env.GOOGLE_SA_JSON  || '';

// Nombres de las hojas (tabs del spreadsheet)
const TABS = {
    students : 'alumnos',
    courses  : 'cursos',
    modules  : 'modulos',
    catalog  : 'catalogo',
    eventos  : 'eventos',
    flags    : 'audit_flags',
    progress : 'playback',
};

// Columnas de cada hoja (orden = columnas A, B, C…)
const HEADERS = {
    students : ['id','email','name','passwordHash','active','deviceId','allowedVideos','createdAt','lastLogin'],
    courses  : ['id','name','author','description','createdAt'],
    modules  : ['id','courseId','parentId','name','sortOrder','videoId','createdAt'],
    catalog  : ['videoId','title','courseId','moduleId','status','sortOrder','durationSecs','uploadedAt'],
    eventos  : ['ts','sessionId','studentId','studentEmail','videoId','deviceId','ip','eventType'],
    flags    : ['id','userId','videoId','email','courseId','flagType','factor','details','status','note','createdAt','reviewedAt'],
    progress : ['sessionId','userId','videoId','durationSecs','positionSecs','wallSecs','speedMax','updatedAt'],
};

let _api   = null;  // googleapis sheets client
let _ready = false;

// ============================================================
//  INICIALIZACIÓN
// ============================================================

/**
 * Inicializa auth con la cuenta de servicio y verifica acceso.
 * Crea las hojas (tabs) que no existan todavía.
 * Llamar UNA VEZ al arrancar el servidor.
 */
async function init() {
    if (!SHEET_ID || !SA_JSON) {
        console.log('[sheets] Variables GOOGLE_SHEET_ID / GOOGLE_SA_JSON no definidas — sync desactivado');
        return false;
    }
    try {
        const creds = JSON.parse(SA_JSON);
        const auth  = new google.auth.GoogleAuth({
            credentials: creds,
            scopes: ['https://www.googleapis.com/auth/spreadsheets'],
        });
        _api = google.sheets({ version: 'v4', auth });
        await _ensureTabs();
        _ready = true;
        console.log('[sheets] ✅ Google Sheets conectado:', SHEET_ID);
        return true;
    } catch (err) {
        console.error('[sheets] ❌ Error al inicializar:', err.message);
        return false;
    }
}

/**
 * Crea los tabs que no existan y escribe las cabeceras.
 */
async function _ensureTabs() {
    const meta     = await _api.spreadsheets.get({ spreadsheetId: SHEET_ID, fields: 'sheets.properties.title' });
    const existing = new Set(meta.data.sheets.map(s => s.properties.title));
    const toCreate = Object.entries(TABS).filter(([, t]) => !existing.has(t));

    if (toCreate.length === 0) return;

    // Crear los tabs nuevos
    await _api.spreadsheets.batchUpdate({
        spreadsheetId: SHEET_ID,
        resource: {
            requests: toCreate.map(([, title]) => ({ addSheet: { properties: { title } } })),
        },
    });

    // Escribir cabeceras
    const data = toCreate.map(([key, title]) => ({
        range  : `${title}!A1`,
        values : [HEADERS[key] || []],
    }));
    await _api.spreadsheets.values.batchUpdate({
        spreadsheetId: SHEET_ID,
        resource: { valueInputOption: 'RAW', data },
    });
    console.log('[sheets] Tabs creados:', toCreate.map(([, t]) => t).join(', '));
}

// ============================================================
//  HELPERS INTERNOS
// ============================================================

/** Lee todas las filas de un tab → array de objetos */
async function _readSheet(tabName) {
    const r    = await _api.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: `${tabName}!A1:ZZ` });
    const rows = r.data.values || [];
    if (rows.length < 2) return [];
    const hdrs = rows[0];
    return rows.slice(1).map(row => Object.fromEntries(hdrs.map((h, i) => [h, row[i] ?? ''])));
}

/** Actualiza una fila existente (rowIndex 1-based, fila 1 = cabecera) */
async function _updateRow(tabName, rowIndex, hdrs, obj) {
    await _api.spreadsheets.values.update({
        spreadsheetId : SHEET_ID,
        range         : `${tabName}!A${rowIndex}`,
        valueInputOption: 'RAW',
        resource      : { values: [hdrs.map(h => String(obj[h] ?? ''))] },
    });
}

/** Agrega una fila al final del tab */
async function _appendRow(tabName, hdrs, obj) {
    await _api.spreadsheets.values.append({
        spreadsheetId   : SHEET_ID,
        range           : `${tabName}!A1`,
        valueInputOption: 'RAW',
        insertDataOption: 'INSERT_ROWS',
        resource        : { values: [hdrs.map(h => String(obj[h] ?? ''))] },
    });
}

/**
 * Upsert genérico: busca la fila por `idKey`, la actualiza si existe,
 * si no la agrega. Silencia errores (best-effort).
 */
async function _upsert(tabKey, obj, idKey = 'id') {
    if (!_ready) return;
    const tabName = TABS[tabKey];
    const hdrs    = HEADERS[tabKey];
    try {
        const r    = await _api.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: `${tabName}!A1:ZZ` });
        const rows = r.data.values || [];
        if (rows.length === 0) { await _appendRow(tabName, hdrs, obj); return; }
        const sheetHdrs = rows[0];
        const idCol     = sheetHdrs.indexOf(idKey);
        const rowIdx    = rows.findIndex((row, i) => i > 0 && row[idCol] === String(obj[idKey] ?? ''));
        if (rowIdx >= 1) {
            await _updateRow(tabName, rowIdx + 1, sheetHdrs, obj);
        } else {
            await _appendRow(tabName, hdrs, obj);
        }
    } catch (err) {
        console.error(`[sheets] _upsert(${tabKey}) error:`, err.message);
    }
}

// ============================================================
//  API PÚBLICA — escritura (todas async best-effort)
// ============================================================

/** Guardar / actualizar alumno en Sheets */
module.exports.saveStudent = (s) => _upsert('students', {
    id          : s.id || s.studentId || '',
    email       : s.email       || '',
    name        : s.name        || '',
    passwordHash: s.passwordHash || s.password || '',
    active      : (s.active === true || s.active === 1) ? '1' : '0',
    deviceId    : s.deviceId    || '',
    allowedVideos: Array.isArray(s.allowedVideos) ? s.allowedVideos.join(',') : (s.allowedVideos || '*'),
    createdAt   : s.createdAt   || new Date().toISOString(),
    lastLogin   : s.lastLogin   || '',
}, 'id').catch(err => console.error('[sheets] saveStudent:', err.message));

/** Guardar / actualizar curso en Sheets */
module.exports.saveCourse = (c) => _upsert('courses', {
    id         : c.id          || '',
    name       : c.name        || '',
    author     : c.author      || '',
    description: c.description || '',
    createdAt  : c.createdAt   || new Date().toISOString(),
}, 'id').catch(err => console.error('[sheets] saveCourse:', err.message));

/** Guardar / actualizar módulo en Sheets */
module.exports.saveModule = (m) => _upsert('modules', {
    id       : m.id        || '',
    courseId : m.courseId  || '',
    parentId : m.parentId  || '',
    name     : m.name      || '',
    sortOrder: m.sortOrder || 0,
    videoId  : m.videoId   || '',
    createdAt: m.createdAt || new Date().toISOString(),
}, 'id').catch(err => console.error('[sheets] saveModule:', err.message));

/** Guardar / actualizar video del catálogo en Sheets */
module.exports.saveVideo = (v) => _upsert('catalog', {
    videoId    : v.videoId     || '',
    title      : v.title       || '',
    courseId   : v.courseId    || '',
    moduleId   : v.moduleId    || '',
    status     : v.status      || 'ready',
    sortOrder  : v.sortOrder   || 0,
    durationSecs: v.durationSecs || 0,
    uploadedAt : v.uploadedAt  || new Date().toISOString(),
}, 'videoId').catch(err => console.error('[sheets] saveVideo:', err.message));

/** Registrar evento de reproducción (append puro, nunca sobreescribe) */
module.exports.appendEvent = (e) => {
    if (!_ready) return;
    _appendRow(TABS.eventos, HEADERS.eventos, {
        ts           : new Date().toISOString(),
        sessionId    : e.sessionId    || '',
        studentId    : e.userId       || e.studentId  || '',
        studentEmail : e.studentEmail || '',
        videoId      : e.videoId      || '',
        deviceId     : e.deviceId     || '',
        ip           : e.ip           || '',
        eventType    : e.eventType    || 'delivery',
    }).catch(err => console.error('[sheets] appendEvent:', err.message));
};

/** Guardar / actualizar flag de auditoría en Sheets */
module.exports.saveFlag = (f) => _upsert('flags', {
    id        : String(f.id           || ''),
    userId    : f.user_id    || f.userId   || '',
    videoId   : f.video_id  || f.videoId  || '',
    email     : f.email      || '',
    courseId  : f.course_id  || f.courseId || '',
    flagType  : f.flag_type  || f.flagType || '',
    factor    : f.factor     || '',
    details   : typeof f.details === 'string' ? f.details : JSON.stringify(f.details || {}),
    status    : f.status     || 'new',
    note      : f.note       || '',
    createdAt : f.created_at || f.createdAt  || new Date().toISOString(),
    reviewedAt: f.reviewed_at || f.reviewedAt || '',
}, 'id').catch(err => console.error('[sheets] saveFlag:', err.message));

/** Registrar progreso de reproducción (append) */
module.exports.saveProgress = (p) => {
    if (!_ready) return;
    _appendRow(TABS.progress, HEADERS.progress, {
        sessionId   : p.sessionId    || '',
        userId      : p.userId       || '',
        videoId     : p.videoId      || '',
        durationSecs: p.durationSecs || 0,
        positionSecs: p.positionSecs || 0,
        wallSecs    : p.wallSecs     || 0,
        speedMax    : p.speedMax     || 1.0,
        updatedAt   : new Date().toISOString(),
    }).catch(err => console.error('[sheets] saveProgress:', err.message));
};

// ============================================================
//  API PÚBLICA — lectura / hidratación
// ============================================================

module.exports.isReady = () => _ready;
module.exports.init    = init;

/**
 * Hidrata la base SQLite con los datos guardados en Sheets.
 * Devuelve { students, courses, modules, catalog } con arrays de objetos.
 * Llamar al arrancar el servidor, ANTES de app.listen().
 */
module.exports.hydrate = async () => {
    if (!_ready) return null;
    try {
        const [students, courses, modules, catalog] = await Promise.all([
            _readSheet(TABS.students),
            _readSheet(TABS.courses),
            _readSheet(TABS.modules),
            _readSheet(TABS.catalog),
        ]);
        console.log(`[sheets] Hydrate: ${students.length} alumnos | ${courses.length} cursos | ${modules.length} módulos | ${catalog.length} videos`);
        return { students, courses, modules, catalog };
    } catch (err) {
        console.error('[sheets] hydrate error:', err.message);
        return null;
    }
};
