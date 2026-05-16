'use strict';
/**
 * server.js — Backend principal: autenticación, DRM, HLS, marcas de agua
 *
 * ENDPOINTS:
 *
 *  Autenticación
 *    POST /api/auth/login          → Emite JWT de usuario
 *    POST /api/auth/refresh        → Renueva JWT (si no expiró)
 *
 *  Videos
 *    GET  /api/video/:videoId/play → Devuelve URL firmada del .m3u8 + token DRM
 *    GET  /api/video/list          → [ADMIN] Lista videos disponibles
 *    POST /api/video/upload        → [ADMIN] Sube video y lanza procesamiento HLS
 *
 *  DRM / Claves
 *    GET  /api/drm/key/:keyId      → Sirve clave AES-128 binaria (autenticado)
 *    POST /api/drm/clearkey        → Licencia ClearKey EME (autenticado)
 *    POST /api/drm/widevine        → Proxy licencia Widevine (autenticado)
 *
 *  Auditoría
 *    POST /api/watermark/log       → Registra apertura del reproductor
 *    GET  /api/watermark/detect    → [ADMIN] Identifica fingerprint de video filtrado
 *    GET  /api/audit/log           → [ADMIN] Ver log de entregas
 *
 *  Archivos estáticos
 *    GET  /                        → index.html (reproductor)
 */

require('dotenv').config();

const express    = require('express');
const path       = require('path');
const fs         = require('fs');
const os         = require('os');
const crypto     = require('crypto');
const jwt        = require('jsonwebtoken');
const multer     = require('multer');
const { v4: uuidv4 } = require('uuid');

const { getKeyBuffer, getKeyHex, getVideoIdForKey, generateKey, buildClearKeyLicense, proxyWidevineLicense } = require('./drm-manager');
const { generateFingerprint, buildWatermarkText } = require('./watermark-manager');
const { getPresignedUrl, listFiles, LOCAL_MODE } = require('./storage');
const { processVideo }                       = require('./hls-processor');
const db = require('./database');
const https = require('https');
const http  = require('http');

// ---- Catálogo: ahora en SQLite vía database.js ----
const loadCatalog    = () => db.loadCatalog();
const addToCatalog   = (e) => db.addToCatalog(e);
const saveCatalog    = () => {}; // no-op: SQLite es transaccional

/**
 * Sincroniza el catálogo completo a CATALOG_SEED en Render.
 * Se ejecuta en background después de cada cambio en el catálogo.
 * Sin límite de tamaño — guarda todos los videos.
 */
function syncCatalogSeed() {
    if (!RENDER_API_KEY || !RENDER_SERVICE_ID) return;
    try {
        const catalog = db.loadCatalog();
        const entries = catalog.map(v => ({
            videoId: v.videoId, title: v.title, sourceType: v.sourceType || 'bunny',
            status: v.status || 'ready', bunnyUrl: v.bunnyUrl || null,
            keyId: v.keyId || null, uploadedAt: v.uploadedAt,
            courseId: v.courseId || null, sortOrder: v.sortOrder || 0
        }));

        const courses = db.getAllCourses ? db.getAllCourses() : [];
        const coursesSeed = JSON.stringify(courses.map(c => ({
            id: c.id, name: c.name, author: c.author || '', sortOrder: c.sortOrder || 0
        })));

        // Dividir catálogo en 2 partes para respetar límite OS de ~128KB por var
        const half = Math.ceil(entries.length / 2);
        const part1 = JSON.stringify(entries.slice(0, half));
        const part2 = JSON.stringify(entries.slice(half));

        const getOpts = { hostname: 'api.render.com', path: `/v1/services/${RENDER_SERVICE_ID}/env-vars`,
            headers: { Authorization: `Bearer ${RENDER_API_KEY}`, Accept: 'application/json' } };
        https.get(getOpts, (res) => {
            let raw = ''; res.on('data', c => raw += c);
            res.on('end', () => {
                try {
                    // Filtrar vars viejas de catalog seed y courses seed
                    let vars = JSON.parse(raw).map(v => ({ key: v.envVar.key, value: v.envVar.value }))
                        .filter(v => !['CATALOG_SEED','CATALOG_SEED_1','CATALOG_SEED_2','CATALOG_SEED_3','COURSES_SEED'].includes(v.key));
                    vars.push({ key: 'COURSES_SEED', value: coursesSeed });
                    vars.push({ key: 'CATALOG_SEED_1', value: part1 });
                    vars.push({ key: 'CATALOG_SEED_2', value: part2 });
                    const body = JSON.stringify(vars);
                    const putOpts = { hostname: 'api.render.com', path: `/v1/services/${RENDER_SERVICE_ID}/env-vars`,
                        method: 'PUT', headers: { Authorization: `Bearer ${RENDER_API_KEY}`, Accept: 'application/json', 'Content-Type': 'application/json' } };
                    const req = https.request(putOpts, (r2) => {
                        let d = ''; r2.on('data', c => d += c);
                        r2.on('end', () => console.log(`[sync] Seeds actualizados: ${courses.length} cursos, ${catalog.length} videos`));
                    });
                    req.on('error', e => console.error('[sync] Error:', e.message));
                    req.write(body); req.end();
                } catch (e) { console.error('[sync] Parse error:', e.message); }
            });
        }).on('error', e => console.error('[sync] GET error:', e.message));
    } catch (e) { console.error('[sync] Error:', e.message); }
}

/**
 * Sincroniza los dominios permitidos a ALLOWED_DOMAINS_SEED en Render.
 */
function syncDomainsSeed() {
    if (!RENDER_API_KEY || !RENDER_SERVICE_ID) return;
    try {
        const domains = db.getAllowedDomains();
        const seed = JSON.stringify(domains);
        const getOpts = { hostname: 'api.render.com', path: `/v1/services/${RENDER_SERVICE_ID}/env-vars`,
            headers: { Authorization: `Bearer ${RENDER_API_KEY}`, Accept: 'application/json' } };
        https.get(getOpts, (res) => {
            let raw = ''; res.on('data', c => raw += c);
            res.on('end', () => {
                try {
                    const vars = JSON.parse(raw).map(v => ({ key: v.envVar.key, value: v.envVar.value }));
                    const idx = vars.findIndex(v => v.key === 'ALLOWED_DOMAINS_SEED');
                    if (idx >= 0) vars[idx].value = seed; else vars.push({ key: 'ALLOWED_DOMAINS_SEED', value: seed });
                    const body = JSON.stringify(vars);
                    const putOpts = { hostname: 'api.render.com', path: `/v1/services/${RENDER_SERVICE_ID}/env-vars`,
                        method: 'PUT', headers: { Authorization: `Bearer ${RENDER_API_KEY}`, Accept: 'application/json', 'Content-Type': 'application/json' } };
                    const req = https.request(putOpts, (r2) => {
                        let d = ''; r2.on('data', c => d += c);
                        r2.on('end', () => console.log(`[sync] ALLOWED_DOMAINS_SEED actualizado: ${domains.length} dominios`));
                    });
                    req.on('error', e => console.error('[sync] Error dominios:', e.message));
                    req.write(body); req.end();
                } catch (e) { console.error('[sync] Parse error dominios:', e.message); }
            });
        }).on('error', e => console.error('[sync] GET error dominios:', e.message));
    } catch (e) { console.error('[sync] Error dominios:', e.message); }
}

// ---- Alumnos: ahora en SQLite vía database.js ----
const findStudentByEmail = (email) => db.findStudentByEmail(email);

// ================================================================
//  HELPERS — BUNNY.NET / FETCH REMOTO
// ================================================================

// SSRF: solo se permiten dominios de Bunny.net
const SAFE_BUNNY_RE = /^https:\/\/[a-z0-9-]+\.(?:b-cdn\.net|bunnycdn\.com|mediadelivery\.net)\//i;
function isSafeBunnyUrl(url) { return SAFE_BUNNY_RE.test(url); }

// Token auth key para el pull zone de Bunny Stream
const BUNNY_TOKEN_KEY = process.env.BUNNY_TOKEN_KEY || '';

/**
 * Genera una URL firmada con token auth de Bunny CDN (Advanced — HMAC-SHA256).
 * Implementación oficial: https://github.com/BunnyWay/BunnyCDN.TokenAuthentication
 * @param {string} url - URL original de Bunny (sin token)
 * @param {number} expiresIn - Segundos de validez (default 24h)
 * @returns {string} URL con token auth (query string format)
 */
function signBunnyUrl(url, expiresIn = 86400) {
    if (!BUNNY_TOKEN_KEY) return url;
    const parsed = new URL(url);
    const expires = String(Math.floor(Date.now() / 1000) + expiresIn);
    // message = signaturePath + expires + signingData + userIp
    // signingData and userIp are empty for our case
    const message = parsed.pathname + expires;
    const digest = crypto.createHmac('sha256', BUNNY_TOKEN_KEY).update(message).digest();
    const token = 'HS256-' + digest.toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}?token=${token}&expires=${expires}`;
}

/** Resuelve una URL relativa a una URL base.
 *  Preserva el prefijo de token Bunny CDN (bcdn_token=...) si existe en base. */
function resolveUrl(base, relative) {
    if (/^https?:\/\//.test(relative)) return relative;
    try {
        const resolved = new URL(relative, base);
        // Bunny CDN pone la auth como prefijo del path: /bcdn_token=...&expires=.../
        // Si base tiene ese prefijo y la URL resuelta lo perdió, restaurarlo
        const baseUrl = new URL(base);
        const tokenMatch = baseUrl.pathname.match(/^(\/bcdn_token=[^/]+\/)/);
        if (tokenMatch && !resolved.pathname.startsWith('/bcdn_token=')) {
            resolved.pathname = tokenMatch[1] + resolved.pathname.replace(/^\//, '');
        }
        return resolved.href;
    } catch {
        const u = new URL(base);
        if (relative.startsWith('/')) return u.origin + relative;
        const dir = u.pathname.substring(0, u.pathname.lastIndexOf('/') + 1);
        return u.origin + dir + relative;
    }
}

/** Descarga una URL remota (texto). Sigue hasta 1 redirección. */
function fetchRemoteText(url) {
    return new Promise((resolve, reject) => {
        const mod = url.startsWith('https') ? https : http;
        const parsedUrl = new URL(url);
        const opts = { timeout: 15000, headers: { Referer: `${parsedUrl.protocol}//${parsedUrl.host}/` } };
        const chunks = [];
        mod.get(url, opts, (res) => {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                return fetchRemoteText(res.headers.location).then(resolve, reject);
            }
            if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode} desde Bunny`));
            res.on('data', c => chunks.push(c));
            res.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
            res.on('error', reject);
        }).on('error', reject);
    });
}

const { Transform } = require('stream');

/**
 * Crea un Transform stream que cifra AES-128-CBC en tiempo real.
 * El cifrado se aplica en bloques de 16 bytes conforme llegan los chunks,
 * permitiendo empezar a enviar bytes cifrados sin esperar el segmento completo.
 */
function createAES128CipherStream(keyHex, segIndex) {
    const iv = Buffer.alloc(16, 0);
    iv.writeUInt32BE(segIndex, 12);
    return crypto.createCipheriv('aes-128-cbc', Buffer.from(keyHex, 'hex'), iv);
}

/** Crea un IV de 16 bytes para el índice de segmento dado */
function segmentIV(segIndex) {
    const iv = Buffer.alloc(16, 0);
    iv.writeUInt32BE(segIndex, 12);
    return iv;
}

/**
 * Envía un manifest HLS envuelto en JSON+base64 para ocultar el contenido
 * a extensiones de descarga que inspeccionan Content-Type y cuerpo.
 */
function sendManifest(res, content) {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    res.end(JSON.stringify({ d: Buffer.from(content).toString('base64url') }));
}

const app  = express();
const PORT = parseInt(process.env.PORT || '3000', 10);
const JWT_SECRET  = process.env.JWT_SECRET;
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || '2h';
const MEDIA_TTL      = parseInt(process.env.MEDIA_TOKEN_TTL || '1800', 10);
const MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT_SESSIONS || '1', 10);
const RENDER_API_KEY    = process.env.RENDER_API_KEY || '';
const RENDER_SERVICE_ID = process.env.RENDER_SERVICE_ID || '';

/**
 * Resuelve la URL base pública del servidor.
 * Prioriza PUBLIC_URL del .env; si no existe, la deduce del request.
 */
function getPublicBase(req) {
    if (process.env.PUBLIC_URL) return process.env.PUBLIC_URL.replace(/\/+$/, '');
    const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
    const host  = req.headers['x-forwarded-host']  || req.headers['host'] || `localhost:${PORT}`;
    return `${proto}://${host}`;
}

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error('[FATAL] JWT_SECRET no configurado o demasiado corto. Edita .env');
    process.exit(1);
}

// ================================================================
//  MIDDLEWARES GLOBALES
// ================================================================

app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));

// CORS — permite peticiones desde dominios configurados en BD + Base44
const STATIC_ORIGINS = [
    /\.base44\.com$/,
    /\.base44\.app$/,
];
app.use((req, res, next) => {
    const origin = req.headers['origin'] || '';
    const dbDomains = db.getAllowedDomains();
    const allowed = STATIC_ORIGINS.some(o => o.test(origin))
        || dbDomains.some(d => origin === d || origin === d.replace(/\/$/, ''))
        || origin.includes('onrender.com');
    if (allowed) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // Permitir iframe desde dominios configurados en BD + Base44
    const dbDomains = db.getAllowedDomains();
    const frameAncestors = ["'self'", ...dbDomains, 'https://*.base44.com', 'https://*.base44.app'].join(' ');
    res.setHeader('Content-Security-Policy', `frame-ancestors ${frameAncestors}`);
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=()');
    // Deshabilitar caché para rutas de API y DRM
    if (req.path.startsWith('/api/')) {
        res.setHeader('Cache-Control', 'no-store');
    }
    next();
});

// ================================================================
//  HELPERS DE AUTENTICACIÓN
// ================================================================

/**
 * Extrae y verifica el JWT del header Authorization: Bearer <token>
 * Devuelve el payload o null si inválido.
 */
function verifyToken(req) {
    const header = req.headers['authorization'] || '';
    if (!header.startsWith('Bearer ')) return null;
    try {
        return jwt.verify(header.slice(7), JWT_SECRET);
    } catch {
        return null;
    }
}

/** Middleware: rechaza peticiones sin JWT válido */
function requireAuth(req, res, next) {
    const payload = verifyToken(req);
    if (!payload) return res.status(401).json({ error: 'No autorizado' });
    req.user = payload;
    next();
}

/** Middleware: rechaza peticiones que no sean del administrador */
function requireAdmin(req, res, next) {
    const payload = verifyToken(req);
    if (!payload || !payload.admin) return res.status(403).json({ error: 'Acceso denegado' });
    req.user = payload;
    next();
}

/** Contrato de error estandarizado para APIs de playback y tracking. */
function apiError(res, status, code, message, details = null) {
    return res.status(status).json({
        ok: false,
        error: { code, message, details, ts: new Date().toISOString() },
    });
}

// ================================================================
//  USUARIOS EN MEMORIA (reemplazar por base de datos en producción)
//  Las contraseñas se almacenan como hashes bcrypt-like (PBKDF2 aquí
//  para evitar dependencia externa; usa bcrypt en producción real).
// ================================================================

const USERS_PATH = path.resolve('./data/users.json');

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256').toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
    const [salt, hash] = stored.split(':');
    const attempt = crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256').toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(attempt, 'hex'));
}

function loadUsers() {
    if (!fs.existsSync(USERS_PATH)) {
        // Crear usuario admin inicial desde .env
        const dir = path.dirname(USERS_PATH);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        const users = [{
            id: uuidv4(),
            username: process.env.ADMIN_USER || 'admin',
            passwordHash: hashPassword(process.env.ADMIN_PASS || 'changeme'),
            admin: true,
            label: 'Administrador',
        }];
        fs.writeFileSync(USERS_PATH, JSON.stringify(users, null, 2), { mode: 0o600 });
        return users;
    }
    return JSON.parse(fs.readFileSync(USERS_PATH, 'utf-8'));
}

function findUser(username) {
    return loadUsers().find(u => u.username === username) || null;
}

// ================================================================
//  RUTAS: AUTENTICACIÓN
// ================================================================

// --- Login de alumnos: email + ID de alumno + fingerprint de dispositivo ---
app.post('/api/auth/login', (req, res) => {
    const { email, studentId, deviceFingerprint } = req.body || {};
    if (typeof email !== 'string' || typeof studentId !== 'string') {
        return res.status(400).json({ error: 'Email e ID de alumno requeridos' });
    }

    const emailNorm = email.trim().toLowerCase();
    const studentIdNorm = studentId.trim();
    const student = findStudentByEmail(emailNorm);

    // Fallo idéntico si no existe o si ID no coincide (evita enumeración de emails)
    if (!student || student.studentId !== studentIdNorm) {
        return res.status(401).json({ error: 'Email o ID de alumno incorrecto' });
    }
    if (!student.active) {
        return res.status(403).json({ error: 'Acceso desactivado. Contacta al administrador.' });
    }

    // Vinculación de dispositivo: primer login → guarda; login distinto → rechaza
    const fp = (typeof deviceFingerprint === 'string') ? deviceFingerprint.slice(0, 64) : '';
    if (fp) {
        if (student.deviceId && student.deviceId !== fp) {
            return res.status(403).json({
                error: 'Este acceso está vinculado a otro dispositivo. Contacta al administrador para desvincular.'
            });
        }
        db.bindDevice(student.id, fp || student.deviceId, new Date().toISOString());
    }

    const token = jwt.sign(
        {
            sub: student.id,
            email: student.email,
            label: student.name || student.email,
            deviceId: fp || student.deviceId || 'unknown',
            allowedVideos: Array.isArray(student.allowedVideos) ? student.allowedVideos : ['*'],
            admin: false,
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES, issuer: 'reproductor-cursos' }
    );
    res.json({ token, expiresIn: JWT_EXPIRES });
});

// --- Login de administrador: username + contraseña ---
app.post('/api/auth/admin-login', (req, res) => {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Credenciales requeridas' });
    }
    const user = findUser(username.trim());
    const hash = user?.passwordHash || `${crypto.randomBytes(16).toString('hex')}:${crypto.randomBytes(32).toString('hex')}`;
    const valid = user ? verifyPassword(password, hash) : false;
    if (!valid) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const token = jwt.sign(
        { sub: user.id, username: user.username, admin: !!user.admin, label: user.label || user.username },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES, issuer: 'reproductor-cursos' }
    );
    res.json({ token, expiresIn: JWT_EXPIRES });
});

app.post('/api/auth/refresh', requireAuth, (req, res) => {
    const { sub, username, admin, label } = req.user;
    const token = jwt.sign(
        { sub, username, admin, label },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES, issuer: 'reproductor-cursos' }
    );
    res.json({ token, expiresIn: JWT_EXPIRES });
});

/**
 * GET /api/health
 * Health check para Render y otros servicios de hosting.
 */
app.get('/api/health', (req, res) => res.json({ status: 'ok', ts: Date.now() }));

/**
 * GET /api/auth/auto
 * Emite un JWT de sesión anónima sin credenciales.
 * Acepta ?did=<deviceFingerprint> para embeber el ID del dispositivo en el token.
 */
app.get('/api/auth/auto', (req, res) => {
    const sessionId = uuidv4();
    // Sanitizar deviceId: solo hex/alfanumérico, max 64 chars
    const rawDid = (req.query.did || '').slice(0, 64).replace(/[^a-zA-Z0-9]/g, '');
    const deviceId = rawDid || 'anon-' + sessionId.slice(0, 8);
    // Sanitizar studentEmail: formato básico de email, max 254 chars
    const rawUid = (req.query.uid || '').slice(0, 254).trim();
    const studentEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rawUid) ? rawUid : '';
    const token = jwt.sign(
        {
            sub:           sessionId,
            email:         studentEmail || 'guest',
            label:         deviceId,
            deviceId,
            studentEmail,
            allowedVideos: ['*'],
            admin:         false,
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES, issuer: 'reproductor-cursos' }
    );
    res.json({ token, expiresIn: JWT_EXPIRES });
});

/**
 * GET /api/embed-status
 * Indica si hay restricción de dominios activa (público, sin auth).
 */
app.get('/api/embed-status', (req, res) => {
    const domains = db.getAllowedDomains();
    res.json({ restricted: domains.length > 0 });
});

// ================================================================
//  RUTAS: REPRODUCCIÓN DE VIDEO
// ================================================================

/**
 * GET /api/video/:videoId/play
 * Devuelve una URL pre-firmada de corta duración para el manifest .m3u8
 * y el fingerprint de marca de agua específico para este usuario.
 */
app.get('/api/video/:videoId/play', requireAuth, async (req, res) => {
    const { videoId } = req.params;
    // Validar videoId (UUID v4)
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(videoId)) {
        return res.status(400).json({ error: 'videoId inválido' });
    }

    // Validar dominio de origen — solo permitir dominios configurados
    const allowedDomains = db.getAllowedDomains();
    if (allowedDomains.length > 0) {
        const origin  = req.headers['origin']  || '';
        const referer = req.headers['referer'] || '';
        // Same-origin (iframe en onrender.com) → origin y referer vacíos o propios → permitir
        const isSameOrigin = (!origin && !referer)
            || origin.includes('onrender.com')
            || referer.includes('onrender.com');
        const isDomainAllowed = allowedDomains.some(d =>
            origin.startsWith(d) || referer.startsWith(d)
        );
        if (!isSameOrigin && !isDomainAllowed && !req.user.admin) {
            return res.status(403).json({ error: 'Reproducción no permitida desde este sitio.' });
        }
    }

    // Verificar que el alumno tenga acceso a este video
    if (!req.user.admin) {
        const allowed = Array.isArray(req.user.allowedVideos) ? req.user.allowedVideos : ['*'];
        if (!allowed.includes('*') && !allowed.includes(videoId)) {
            return res.status(403).json({ error: 'No tienes acceso a este video.' });
        }
    }

    try {
        const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
        const manifestUrl = `${baseUrl}/api/r/${videoId}`;

        // Fingerprint forense único para esta sesión (para el audit log)
        const fingerprint = generateFingerprint(req.user.sub, videoId);
        // El watermark visible en pantalla ES el device fingerprint del dispositivo
        const deviceId = req.user.deviceId || req.user.sub.slice(0, 12);
        const watermarkText = deviceId;

        // Verificar sesiones concurrentes (limpiar expiradas primero)
        db.cleanExpiredSessions();
        const activeSessions = db.countActiveSessions(req.user.sub);
        if (activeSessions >= MAX_CONCURRENT) {
            return res.status(429).json({
                error: `Ya tienes ${activeSessions} reproducción activa. Cierra otras pestañas o dispositivos para continuar.`
            });
        }

        // Crear registro de sesión activa
        const sessionId = uuidv4();
        db.createSession(sessionId, req.user.sub, videoId);

        // Registrar la entrega en el log de auditoría (deviceId en lugar de IP)
        db.logDelivery({
            userId: req.user.sub,
            videoId,
            fingerprint,
            deviceId: req.user.deviceId || 'unknown',
            studentEmail: req.user.studentEmail || '',
            ip: req.ip,
            userAgent: req.headers['user-agent'],
        });

        // Token de medios de corta duración
        const mediaToken = jwt.sign(
            {
                sub: req.user.sub,
                videoId,
                fingerprint,
                watermarkText,
                sessionId,
                studentEmail: req.user.studentEmail || '',
            },
            JWT_SECRET,
            { expiresIn: MEDIA_TTL, issuer: 'reproductor-cursos' }
        );

        res.json({ manifestUrl, mediaToken, watermarkText, ttl: MEDIA_TTL, sessionId });
    } catch (err) {
        console.error('[video/play]', err.message);
        res.status(500).json({ error: 'No se pudo preparar el video' });
    }
});

/**
 * GET /api/video/list  [ADMIN]
 * Lista los IDs de videos procesados disponibles en B2.
 */
app.get('/api/video/list', requireAdmin, async (req, res) => {
    try {
        const keys = await listFiles('hls/');
        // Extraer videoIds únicos de las rutas hls/<videoId>/...
        const ids = [...new Set(
            keys.map(k => k.split('/')[1]).filter(Boolean)
        )];
        res.json({ videos: ids });
    } catch (err) {
        console.error('[video/list]', err.message);
        res.status(500).json({ error: 'No se pudo obtener la lista de videos' });
    }
});

// ================================================================
//  RUTAS: DRM — CLAVES AES-128
// ================================================================

/**
 * GET /api/drm/key/:keyId
 * Devuelve la clave AES-128 binaria SOLO a clientes con JWT válido.
 * FFmpeg apunta el EXT-X-KEY URI a este endpoint.
 *
 * El reproductor HLS.js solicita este endpoint automáticamente cuando
 * encuentra EXT-X-KEY en el manifest.
 */
/**
 * GET /api/drm/proxy-key
 * Para videos de Bunny que ya vienen cifrados con su propia clave AES-128.
 * Proxea la clave original de Bunny pero detrás de autenticación JWT.
 */
app.get('/api/drm/proxy-key', async (req, res) => {
    const token = req.query.token || (req.headers['authorization'] || '').replace('Bearer ', '');
    try { jwt.verify(token, JWT_SECRET); } catch { return res.status(401).send('No autorizado'); }

    const { k } = req.query;
    if (!k) return res.status(400).send('k requerido');
    let keyUrl;
    try { keyUrl = Buffer.from(k, 'base64url').toString('utf-8'); } catch {
        return res.status(400).send('k inválido');
    }
    if (!isSafeBunnyUrl(keyUrl)) return res.status(400).send('URL no permitida');
    // Firmar URL con token auth de Bunny
    keyUrl = signBunnyUrl(keyUrl);

    const mod = keyUrl.startsWith('https') ? https : http;
    const parsedUrl = new URL(keyUrl);
    mod.get(keyUrl, { timeout: 8000, headers: { Referer: `${parsedUrl.protocol}//${parsedUrl.host}/` } }, (upstream) => {
        if (upstream.statusCode !== 200) {
            return res.status(502).send(`Error Bunny key: ${upstream.statusCode}`);
        }
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Cache-Control', 'no-store');
        upstream.pipe(res);
    }).on('error', () => { if (!res.headersSent) res.status(502).send('Error de conexión'); });
});

app.get('/api/drm/key/:keyId', (req, res) => {
    // El token puede venir como query param (HLS.js lo agrega a las peticiones de clave)
    // o como Authorization header
    const token = req.query.token || (req.headers['authorization'] || '').replace('Bearer ', '');
    let payload = null;
    try {
        payload = jwt.verify(token, JWT_SECRET);
    } catch {
        return res.status(401).send('No autorizado');
    }

    const { keyId } = req.params;
    if (!/^[0-9a-f-]{36}$/.test(keyId)) return res.status(400).send('keyId inválido');

    // Verificar que la clave pertenezca al videoId del token
    const videoId = getVideoIdForKey(keyId);
    if (!videoId || (payload.videoId && payload.videoId !== videoId)) {
        return res.status(403).send('Clave no autorizada para este video');
    }

    const keyBuf = getKeyBuffer(keyId);
    if (!keyBuf) return res.status(404).send('Clave no encontrada');

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', keyBuf.length);
    res.send(keyBuf);
});

/**
 * POST /api/drm/clearkey
 * Licencia ClearKey EME (W3C). El navegador envía { kids, type }.
 * Solo disponible para usuarios autenticados.
 */
app.post('/api/drm/clearkey', requireAuth, (req, res) => {
    const { kids } = req.body || {};
    if (!Array.isArray(kids) || kids.length === 0) {
        return res.status(400).json({ error: 'kids requerido' });
    }
    // Validar formato base64url
    for (const k of kids) {
        if (typeof k !== 'string' || !/^[A-Za-z0-9_-]+=*$/.test(k)) {
            return res.status(400).json({ error: 'kid inválido' });
        }
    }
    const license = buildClearKeyLicense(kids);
    res.json(license);
});

/**
 * POST /api/drm/widevine
 * Proxy de licencia Widevine (requiere EZDRM / BuyDRM configurado en .env).
 * El cuerpo debe ser el challenge binario enviado por el Widevine CDM.
 */
app.post('/api/drm/widevine', requireAuth, express.raw({ type: 'application/octet-stream', limit: '64kb' }), async (req, res) => {
    try {
        const response = await proxyWidevineLicense(req.body);
        res.setHeader('Content-Type', 'application/octet-stream');
        res.send(response);
    } catch (err) {
        console.error('[drm/widevine]', err.message);
        res.status(502).json({ error: err.message });
    }
});

// ================================================================
//  RUTAS: SUBIDA DE VIDEO [ADMIN]
// ================================================================

const upload = multer({
    storage: multer.diskStorage({
        destination: os.tmpdir(),
        filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname)),
    }),
    limits: { fileSize: 10 * 1024 * 1024 * 1024 }, // 10 GB
    fileFilter: (req, file, cb) => {
        const allowed = ['.mp4', '.mov', '.mkv', '.avi', '.webm'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowed.includes(ext)) cb(null, true);
        else cb(new Error('Tipo de archivo no permitido'), false);
    },
});

app.post('/api/video/upload', requireAdmin, upload.single('video'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Archivo de video requerido (mp4, mov, mkv, avi, webm)' });

    const videoId = uuidv4();
    const title   = (req.body && req.body.title) ? req.body.title.slice(0, 120) : req.file.originalname;
    const localPath = req.file.path;

    // Añadir al catálogo inmediatamente (estado: procesando)
    addToCatalog({ videoId, title, status: 'processing', uploadedAt: new Date().toISOString(), segmentCount: 0 });

    // Responder de inmediato y procesar en segundo plano
    res.json({ videoId, status: 'processing', message: '¡Video recibido! El procesamiento HLS comenzó en segundo plano.' });

    const base = getPublicBase(req);
    try {
        const result = await processVideo(localPath, videoId, base);
        db.updateCatalogEntry({ videoId, status: 'ready', segmentCount: result.segmentCount, keyId: result.keyId });
        console.log(`[upload] Video listo: ${videoId} (${result.segmentCount} segmentos)`);
        syncCatalogSeed();
    } catch (err) {
        db.updateCatalogEntry({ videoId, status: 'error', error: err.message });
        console.error(`[upload] Error procesando video ${videoId}:`, err.message);
    } finally {
        fs.unlink(localPath, () => {});
    }
});

/**
 * GET /api/video/catalog  [ADMIN]
 * Devuelve el catálogo completo de videos con su estado de procesamiento.
 */
app.get('/api/video/catalog', requireAdmin, (req, res) => {
    res.json({ catalog: db.loadCatalog() });
});

/**
 * GET /api/video/catalog/export-seed  [ADMIN]
 * Devuelve el catálogo en formato JSON listo para pegar en CATALOG_SEED.
 * Permite persistir el catálogo entre reinicios de Render.
 */
app.get('/api/video/catalog/export-seed', requireAdmin, (req, res) => {
    const catalog = db.loadCatalog();
    res.json(catalog);
});

/**
/**
 * DELETE /api/video/bulk  [ADMIN]
 * Elimina múltiples videos del catálogo en una sola petición.
 * Body: { videoIds: string[] }
 */
app.delete('/api/video/bulk', requireAdmin, async (req, res) => {
    const { videoIds } = req.body || {};
    if (!Array.isArray(videoIds) || !videoIds.length) return res.status(400).json({ error: 'videoIds (array) requerido' });
    // Validar cada ID antes de borrar
    for (const id of videoIds) {
        if (!/^[0-9a-f-]{36}$/i.test(id)) return res.status(400).json({ error: 'videoId inválido: ' + id });
    }
    let deleted = 0;
    for (const videoId of videoIds) {
        try {
            db.deleteCatalogEntry(videoId);
            if (LOCAL_MODE) {
                const dir = path.join('./public/hls', 'hls', videoId);
                if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
            }
            deleted++;
        } catch (e) { /* skip single failures */ }
    }
    syncCatalogSeed();
    res.json({ ok: true, deleted });
});

/**
 * DELETE /api/video/:videoId  [ADMIN]
 * Elimina un video del catálogo (y sus archivos si es modo local).
 */
app.delete('/api/video/:videoId', requireAdmin, async (req, res) => {
    const { videoId } = req.params;
    if (!/^[0-9a-f-]{36}$/i.test(videoId)) return res.status(400).json({ error: 'videoId inválido' });
    db.deleteCatalogEntry(videoId);
    if (LOCAL_MODE) {
        const dir = path.join('./public/hls', 'hls', videoId);
        if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
    }
    syncCatalogSeed();
    res.json({ ok: true });
});

/**
 * POST /api/catalog/add-bunny  [ADMIN]
 * Agrega un video de Bunny.net al catálogo sin subir ni procesar archivos.
 * El admin pega la URL HLS (.m3u8) de Bunny Stream.
 *
 * Body: { title, bunnyUrl }
 * bunnyUrl ejemplo: https://vz-XXXXXX.b-cdn.net/VIDEO-ID/playlist.m3u8
 */

/**
 * POST /api/catalog/restore-bulk  [ADMIN]
 * Restaura un array de videos preservando IDs originales (para recuperación tras reinicio).
 * Body: { videos: [{ videoId, title, bunnyUrl, courseId, sortOrder, keyId, uploadedAt }] }
 */
app.post('/api/catalog/restore-bulk', requireAdmin, (req, res) => {
    const { videos } = req.body || {};
    if (!Array.isArray(videos)) return res.status(400).json({ error: 'videos array requerido' });
    let inserted = 0, skipped = 0;
    for (const v of videos) {
        if (!v.videoId || !v.bunnyUrl) { skipped++; continue; }
        if (!isSafeBunnyUrl(v.bunnyUrl)) { skipped++; continue; }
        const existing = db.getCatalogById(v.videoId);
        if (existing) { skipped++; continue; }
        try {
            db.addToCatalog({
                videoId:    v.videoId,
                title:      (v.title || v.videoId).slice(0, 120),
                status:     'ready',
                sourceType: 'bunny',
                bunnyUrl:   v.bunnyUrl,
                keyId:      v.keyId || null,
                courseId:   v.courseId || null,
                sortOrder:  v.sortOrder || 0,
                uploadedAt: v.uploadedAt || new Date().toISOString(),
            });
            inserted++;
        } catch { skipped++; }
    }
    res.json({ ok: true, inserted, skipped });
});
app.post('/api/catalog/add-bunny', requireAdmin, async (req, res) => {
    const { title, bunnyUrl } = req.body || {};
    if (!title || typeof title !== 'string') return res.status(400).json({ error: 'title requerido' });
    if (!bunnyUrl || typeof bunnyUrl !== 'string') return res.status(400).json({ error: 'bunnyUrl requerido' });

    // Seguridad: solo dominios de Bunny.net permitidos
    if (!isSafeBunnyUrl(bunnyUrl)) {
        return res.status(400).json({ error: 'URL inválida. Solo se permiten dominios de Bunny.net (*.b-cdn.net, *.bunnycdn.com)' });
    }
    if (!bunnyUrl.includes('.m3u8')) {
        return res.status(400).json({ error: 'La URL debe apuntar a un archivo .m3u8' });
    }

    const videoId = uuidv4();
    // Generar clave AES-128 exclusiva para este video de Bunny
    const { keyId } = generateKey(videoId);

    addToCatalog({
        videoId,
        title:      title.trim().slice(0, 120),
        status:     'ready',
        sourceType: 'bunny',
        bunnyUrl:   bunnyUrl.trim(),
        keyId,
        uploadedAt: new Date().toISOString(),
    });

    syncCatalogSeed();
    res.status(201).json({ videoId, title, status: 'ready', sourceType: 'bunny' });
});

// ================================================================
//  RUTAS: DOMINIOS PERMITIDOS [ADMIN]
// ================================================================

/** GET /api/allowed-domains — Lista dominios permitidos */
app.get('/api/allowed-domains', requireAdmin, (req, res) => {
    res.json({ domains: db.getAllowedDomains() });
});

/** POST /api/allowed-domains — Agrega un dominio */
app.post('/api/allowed-domains', requireAdmin, (req, res) => {
    const { domain } = req.body || {};
    if (!domain || typeof domain !== 'string') return res.status(400).json({ error: 'domain requerido' });
    const clean = domain.trim().toLowerCase().replace(/\/+$/, '');
    if (!/^https?:\/\/[a-z0-9.-]+/.test(clean)) return res.status(400).json({ error: 'Formato inválido. Ejemplo: https://campusdigitalpro.com' });
    db.addAllowedDomain(clean);
    syncDomainsSeed();
    res.json({ ok: true, domains: db.getAllowedDomains() });
});

/** DELETE /api/allowed-domains — Elimina un dominio */
app.delete('/api/allowed-domains', requireAdmin, (req, res) => {
    const { domain } = req.body || {};
    if (!domain) return res.status(400).json({ error: 'domain requerido' });
    db.removeAllowedDomain(domain);
    syncDomainsSeed();
    res.json({ ok: true, domains: db.getAllowedDomains() });
});

// ================================================================
//  RUTAS: CURSOS [ADMIN]
// ================================================================

/** GET /api/courses — Lista todos los cursos con conteo de videos */
app.get('/api/courses', requireAdmin, (req, res) => {
    const courses = db.getAllCourses();
    const catalog = db.loadCatalog();
    const result = courses.map(c => ({
        ...c,
        videoCount: catalog.filter(v => v.courseId === c.id).length,
    }));
    const unassigned = catalog.filter(v => !v.courseId).length;
    res.json({ courses: result, unassignedCount: unassigned });
});

/** POST /api/courses — Crea un curso */
app.post('/api/courses', requireAdmin, (req, res) => {
    const { name, author } = req.body || {};
    if (!name || typeof name !== 'string') return res.status(400).json({ error: 'name requerido' });
    const id = uuidv4();
    const course = db.createCourse({ id, name: name.trim().slice(0, 120), author: (author || '').trim().slice(0, 100) });
    res.status(201).json(course);
});

/** POST /api/courses/restore-bulk — Restaura cursos preservando IDs originales */
app.post('/api/courses/restore-bulk', requireAdmin, (req, res) => {
    const { courses } = req.body || {};
    if (!Array.isArray(courses)) return res.status(400).json({ error: 'courses array requerido' });
    let inserted = 0, skipped = 0;
    for (const c of courses) {
        if (!c.id || !c.name) { skipped++; continue; }
        try {
            const existing = db.getCourseById(c.id);
            if (existing) { skipped++; continue; }
            db.createCourse({ id: c.id, name: c.name.slice(0, 120), author: (c.author || '').slice(0, 100) });
            inserted++;
        } catch { skipped++; }
    }
    res.json({ ok: true, inserted, skipped });
});

/**
 * POST /api/audit/seed-devices  [ADMIN]
 * Restaura asociaciones email+deviceId en audit_log tras un deploy.
 * Acepta [{ studentEmail, deviceId }] — inserta un registro mínimo por par si no existe ya.
 */
app.post('/api/audit/seed-devices', requireAdmin, (req, res) => {
    const { records } = req.body || {};
    if (!Array.isArray(records)) return res.status(400).json({ error: 'records array requerido' });
    let inserted = 0, skipped = 0;
    for (const r of records) {
        const email    = (r.studentEmail || '').slice(0, 254).trim();
        const deviceId = (r.deviceId     || '').slice(0, 128).trim();
        if (!email || !deviceId || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { skipped++; continue; }
        try {
            const fp = `seed_${Buffer.from(email + ':' + deviceId).toString('base64').slice(0, 40)}`;
            // Verificar si ya existe un registro con este fingerprint
            const ex = db.detectLeak(fp);
            if (ex) { skipped++; continue; }
            db.logDelivery({
                fingerprint:   fp,
                userId:        email,
                videoId:       'restored_association',
                deviceId:      deviceId,
                studentEmail:  email,
                ip:            'restored',
                userAgent:     'restored',
            });
            inserted++;
        } catch { skipped++; }
    }
    res.json({ ok: true, inserted, skipped });
});

/** PUT /api/courses/:id — Actualiza nombre/autor */
app.put('/api/courses/:id', requireAdmin, (req, res) => {
    const { name, author } = req.body || {};
    if (!name || typeof name !== 'string') return res.status(400).json({ error: 'name requerido' });
    const course = db.updateCourse(req.params.id, { name: name.trim().slice(0, 120), author: (author || '').trim().slice(0, 100) });
    if (!course) return res.status(404).json({ error: 'Curso no encontrado' });
    res.json(course);
});

/** DELETE /api/courses/all — Elimina TODOS los cursos (solo en emergencia de restauración) */
app.delete('/api/courses/all', requireAdmin, (req, res) => {
    const courses = db.getAllCourses();
    for (const c of courses) db.deleteCourse(c.id);
    res.json({ ok: true, deleted: courses.length });
});

/** DELETE /api/courses/:id — Elimina un curso (videos quedan sin asignar) */
app.delete('/api/courses/:id', requireAdmin, (req, res) => {
    db.deleteCourse(req.params.id);
    syncCatalogSeed();
    res.json({ ok: true });
});

/** GET /api/courses/unassigned/videos — Videos sin curso (MUST be before :id route) */
app.get('/api/courses/unassigned/videos', requireAdmin, (req, res) => {
    const videos = db.getCatalogUnassigned();
    res.json({ videos });
});

/** GET /api/courses/:id/videos — Videos de un curso */
app.get('/api/courses/:id/videos', requireAdmin, (req, res) => {
    const videos = db.getCatalogByCourse(req.params.id);
    res.json({ videos });
});

/** POST /api/courses/move-video — Mover video a un curso (y opcionalmente a un módulo) */
app.post('/api/courses/move-video', requireAdmin, (req, res) => {
    const { videoId, courseId, moduleId } = req.body || {};
    if (!videoId) return res.status(400).json({ error: 'videoId requerido' });
    db.moveVideoToCourse(videoId, courseId || null);
    // Si se indica módulo, asignarlo; si moduleId===null explícito, desasignar
    if (moduleId !== undefined) db.moveVideoToModule(videoId, moduleId || null);
    syncCatalogSeed();
    res.json({ ok: true });
});

/** POST /api/courses/bulk-move — Mover multiples videos a un curso */
app.post('/api/courses/bulk-move', requireAdmin, (req, res) => {
    const { videoIds, courseId } = req.body || {};
    if (!Array.isArray(videoIds) || !videoIds.length) return res.status(400).json({ error: 'videoIds requerido (array no vacio)' });
    for (const vid of videoIds) {
        db.moveVideoToCourse(vid, courseId || null);
    }
    syncCatalogSeed();
    res.json({ ok: true, moved: videoIds.length });
});

/** POST /api/courses/reorder — Reordenar videos dentro de un curso */
app.post('/api/courses/reorder', requireAdmin, (req, res) => {
    const { orders } = req.body || {};
    if (!Array.isArray(orders)) return res.status(400).json({ error: 'orders requerido (array)' });
    db.reorderVideos(orders);
    syncCatalogSeed();
    res.json({ ok: true });
});

// ================================================================
//  RUTAS: MÓDULOS [ADMIN]
// ================================================================

/** GET /api/courses/:id/modules — Lista todos los módulos de un curso */
app.get('/api/courses/:id/modules', requireAdmin, (req, res) => {
    const modules = db.getModulesByCourse(req.params.id);
    res.json({ modules });
});

/** POST /api/courses/:id/modules — Crea un módulo (o submódulo con parentId) */
app.post('/api/courses/:id/modules', requireAdmin, (req, res) => {
    const { name, parentId, sortOrder } = req.body || {};
    if (!name || typeof name !== 'string') return res.status(400).json({ error: 'name requerido' });
    const id = uuidv4();
    const mod = db.createModule({ id, courseId: req.params.id, parentId: parentId || null, name, sortOrder: sortOrder || 0 });
    res.status(201).json(mod);
});

/** PUT /api/modules/:id — Renombra o reordena un módulo */
app.put('/api/modules/:id', requireAdmin, (req, res) => {
    const { name, sortOrder } = req.body || {};
    if (!name || typeof name !== 'string') return res.status(400).json({ error: 'name requerido' });
    const mod = db.updateModule(req.params.id, { name, sortOrder: sortOrder || 0 });
    if (!mod) return res.status(404).json({ error: 'Módulo no encontrado' });
    res.json(mod);
});

/** DELETE /api/modules/:id — Elimina un módulo (y sus hijos; videos quedan sin módulo) */
app.delete('/api/modules/:id', requireAdmin, (req, res) => {
    db.deleteModule(req.params.id);
    res.json({ ok: true });
});

/** POST /api/courses/set-module — Asigna un video a un módulo específico */
app.post('/api/courses/set-module', requireAdmin, (req, res) => {
    const { videoId, moduleId } = req.body || {};
    if (!videoId) return res.status(400).json({ error: 'videoId requerido' });
    db.moveVideoToModule(videoId, moduleId || null);
    res.json({ ok: true });
});

// ================================================================
//  RUTAS: BUNNY.NET API IMPORT [ADMIN]
// ================================================================

/** GET /api/bunny/config — Devuelve si hay config guardada (sin exponer la key) */
app.get('/api/bunny/config', requireAdmin, (req, res) => {
    const hasKey = !!db.getConfig('bunny_api_key');
    const libraryId = db.getConfig('bunny_library_id') || '';
    const cdnHostname = db.getConfig('bunny_cdn_hostname') || '';
    // accountKey: DB tiene prioridad, si no, usar env var BUNNY_ACCOUNT_KEY
    const accountKey = db.getConfig('bunny_account_key') || process.env.BUNNY_ACCOUNT_KEY || '';
    res.json({ configured: hasKey, libraryId, cdnHostname, accountKey });
});

/** POST /api/bunny/config — Guarda API key, library ID y CDN hostname */
app.post('/api/bunny/config', requireAdmin, (req, res) => {
    const { apiKey, libraryId, cdnHostname, accountKey } = req.body || {};
    if (!apiKey || !libraryId) return res.status(400).json({ error: 'apiKey y libraryId requeridos' });
    db.setConfig('bunny_api_key', apiKey.trim());
    db.setConfig('bunny_library_id', libraryId.trim());
    if (cdnHostname) {
        let cdn = cdnHostname.trim().replace(/\/$/, '');
        if (!/^https?:\/\//i.test(cdn)) cdn = 'https://' + cdn;
        db.setConfig('bunny_cdn_hostname', cdn);
    }
    if (accountKey) db.setConfig('bunny_account_key', accountKey.trim());
    res.json({ ok: true });
});

/**
 * GET /api/bunny/videos — Obtiene todos los videos de la biblioteca Bunny configurada.
 * Pagina automáticamente (Bunny devuelve max 100 por página).
 */
app.get('/api/bunny/videos', requireAdmin, async (req, res) => {
    const apiKey = req.query.apiKey || db.getConfig('bunny_api_key');
    const libraryId = req.query.libraryId || db.getConfig('bunny_library_id');
    // cdnHostname puede venir como query param (prioridad) o desde DB
    const cdnHostnameParam = (req.query.cdnHostname || '').trim().replace(/\/$/, '');
    if (!apiKey || !libraryId) return res.status(400).json({ error: 'Bunny API key y library ID requeridos. Configúralos primero.' });

    try {
        const allVideos = [];
        let page = 1;
        const perPage = 100;
        let total = Infinity;

        while (allVideos.length < total) {
            const data = await bunnyApiRequest(`/library/${libraryId}/videos?page=${page}&itemsPerPage=${perPage}&orderBy=title`, { extraHeaders: { AccessKey: apiKey } });
            if (!data.items || !data.items.length) break;
            total = data.totalItems || data.items.length;
            allVideos.push(...data.items);
            if (allVideos.length >= total || data.items.length < perPage) break;
            page++;
        }

        // Detectar CDN hostname: prioridad: query param > DB > auto-detección
        let cdnHostname = cdnHostnameParam || db.getConfig('bunny_cdn_hostname') || '';
        if (cdnHostnameParam) db.setConfig('bunny_cdn_hostname', cdnHostnameParam); // persist
        if (!cdnHostname) {
            // Intento 1: extraer hostname del thumbnailUrl de cualquier video (más confiable)
            const sampleVideo = allVideos.find(v => v.thumbnailUrl && v.thumbnailUrl.includes('.b-cdn.net'));
            if (sampleVideo) {
                const match = sampleVideo.thumbnailUrl.match(/^(https:\/\/[^/]+)/);
                if (match) { cdnHostname = match[1]; db.setConfig('bunny_cdn_hostname', cdnHostname); }
            }
        }
        if (!cdnHostname) {
            // Intento 2: buscar en catálogo existente alguna bunnyUrl para extraer hostname
            const catalog = db.loadCatalog();
            const sample = catalog.find(v => v.bunnyUrl && v.bunnyUrl.includes('.b-cdn.net'));
            if (sample) {
                const match = sample.bunnyUrl.match(/^(https:\/\/[^/]+)/);
                if (match) { cdnHostname = match[1]; db.setConfig('bunny_cdn_hostname', cdnHostname); }
            }
        }

        const videos = allVideos.map(v => ({
            guid: v.guid,
            title: v.title || v.guid,
            status: v.status, // 4=ready
            hlsUrl: cdnHostname ? `${cdnHostname}/${v.guid}/playlist.m3u8` : null,
            dateUploaded: v.dateUploaded,
        }));

        res.json({ videos, cdnHostname, total: videos.length });
    } catch (err) {
        res.status(502).json({ error: 'Error conectando Bunny API: ' + err.message });
    }
});

/** POST /api/bunny/save-account-key — Guarda la account key de Bunny permanentemente en DB */
app.post('/api/bunny/save-account-key', requireAdmin, (req, res) => {
    const { accountKey } = req.body || {};
    if (!accountKey) return res.status(400).json({ error: 'accountKey requerida' });
    db.setConfig('bunny_account_key', accountKey.trim());
    res.json({ ok: true });
});

/** GET /api/bunny/library-raw — Devuelve info completa de la libreria (para detectar CDN hostname) */
app.get('/api/bunny/library-raw', requireAdmin, async (req, res) => {
    const apiKey = db.getConfig('bunny_api_key');
    const libraryId = db.getConfig('bunny_library_id');
    if (!apiKey || !libraryId) return res.status(400).json({ error: 'Bunny API key y library ID no configurados' });
    try {
        const data = await bunnyApiRequest(`/library/${libraryId}`, { extraHeaders: { AccessKey: apiKey } });
        res.json(data);
    } catch (err) {
        res.status(502).json({ error: 'Error obteniendo library info: ' + err.message });
    }
});

/** GET /api/bunny/libraries — Lista todas las bibliotecas de video de la cuenta Bunny */
app.get('/api/bunny/libraries', requireAdmin, async (req, res) => {
    const accountKey = (req.query.accountKey || '').trim();
    if (!accountKey) return res.status(400).json({ error: 'accountKey requerida' });
    try {
        const data = await bunnyApiRequest('/videolibrary?page=1&perPage=1000&includeAccessKey=true', {
            hostname: 'api.bunny.net',
            extraHeaders: { AccessKey: accountKey },
        });
        const items = data.Items || data.items || [];
        const libraries = items.map(l => ({
            id: l.Id || l.id,
            name: l.Name || l.name,
            apiKey: l.ApiKey || l.apiKey || '',
            pullZoneUrl: l.PullZoneUrl ? l.PullZoneUrl.replace(/\/$/, '') : ''
        }));
        res.json({ libraries });
    } catch (err) {
        res.status(502).json({ error: 'Error listando bibliotecas Bunny: ' + err.message });
    }
});

/**
 * POST /api/bunny/import — Crea un curso completo con estructura de módulos.
 * Body: { courseName, author, apiKey, libraryId, cdnHostname, structure }
 * structure: [{ name, type:'module'|'video', children:[], fileName, matchedGuid, matchedTitle, hlsUrl }]
 */
app.post('/api/bunny/import', requireAdmin, async (req, res) => {
    const { courseName, author, apiKey: reqApiKey, libraryId: reqLibId, cdnHostname: reqCdn, structure } = req.body || {};
    if (!courseName) return res.status(400).json({ error: 'courseName requerido' });
    if (!Array.isArray(structure)) return res.status(400).json({ error: 'structure requerida (array)' });

    const apiKey = reqApiKey || db.getConfig('bunny_api_key');
    const libraryId = reqLibId || db.getConfig('bunny_library_id');
    let cdnHostname = reqCdn || db.getConfig('bunny_cdn_hostname') || '';
    if (cdnHostname && !/^https?:\/\//i.test(cdnHostname)) cdnHostname = 'https://' + cdnHostname;

    if (!apiKey || !libraryId) return res.status(400).json({ error: 'Bunny API key y library ID requeridos' });

    try {
        // Crear el curso
        const courseId = uuidv4();
        db.createCourse({ id: courseId, name: courseName.trim().slice(0, 120), author: (author || '').trim().slice(0, 100) });

        let videoSortOrder = 1;

        // Función recursiva para procesar la estructura
        function processItems(items, parentModuleId) {
            for (const item of items) {
                if (item.type === 'module') {
                    const modId = uuidv4();
                    db.createModule({ id: modId, courseId, parentId: parentModuleId || null, name: item.name, sortOrder: item.sortOrder || 0 });
                    if (Array.isArray(item.children)) {
                        processItems(item.children, modId);
                    }
                } else if (item.type === 'video') {
                    // Construir hlsUrl: prioridad: lo que viene del frontend → construir con guid + cdn
                    let hlsUrl = item.hlsUrl || null;
                    if (!hlsUrl && item.matchedGuid && cdnHostname) {
                        hlsUrl = `${cdnHostname}/${item.matchedGuid}/playlist.m3u8`;
                    }
                    if (!hlsUrl) continue; // sin guid ni url: saltar
                    if (!isSafeBunnyUrl(hlsUrl)) continue;
                    const videoId = uuidv4();
                    const { keyId } = generateKey(videoId);
                    db.addToCatalog({
                        videoId,
                        title: (item.matchedTitle || item.fileName || item.name || 'Video').slice(0, 120),
                        status: 'ready',
                        sourceType: 'bunny',
                        bunnyUrl: hlsUrl,
                        keyId,
                        courseId,
                        sortOrder: videoSortOrder++,
                        uploadedAt: new Date().toISOString(),
                    });
                    if (parentModuleId) db.moveVideoToModule(videoId, parentModuleId);
                }
            }
        }

        processItems(structure, null);
        syncCatalogSeed();

        const course = db.getCourseById(courseId);
        const modules = db.getModulesByCourse(courseId);
        const videos = db.getCatalogByCourse(courseId);
        res.status(201).json({ ok: true, courseId, course, modules: modules.length, videos: videos.length });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/** Helper: llama a la API de Bunny (Stream o Account) */
function bunnyApiRequest(path, { hostname = 'video.bunnycdn.com', extraHeaders = {} } = {}) {
    return new Promise((resolve, reject) => {
        const opts = {
            hostname,
            path,
            method: 'GET',
            headers: { Accept: 'application/json', ...extraHeaders },
        };
        const req = https.request(opts, (res) => {
            let raw = '';
            res.on('data', c => raw += c);
            res.on('end', () => {
                try { resolve(JSON.parse(raw)); }
                catch { reject(new Error('Respuesta inválida de Bunny API')); }
            });
        });
        req.on('error', reject);
        req.setTimeout(30000, () => { req.destroy(); reject(new Error('Timeout Bunny API')); });
        req.end();
    });
}

/**
 * Actualiza ADMIN_USER y ADMIN_PASS en Render env vars.
 * Body: { newUser, newPass }
 */
app.post('/api/admin/update-credentials', requireAdmin, (req, res) => {
    const { newUser, newPass } = req.body || {};
    if (!newUser || !newPass) return res.status(400).json({ error: 'newUser y newPass requeridos' });
    if (!RENDER_API_KEY || !RENDER_SERVICE_ID) return res.status(500).json({ error: 'RENDER_API_KEY no configurada' });

    const getOpts = { hostname: 'api.render.com', path: `/v1/services/${RENDER_SERVICE_ID}/env-vars`,
        headers: { Authorization: `Bearer ${RENDER_API_KEY}`, Accept: 'application/json' } };
    https.get(getOpts, (r) => {
        let raw = ''; r.on('data', c => raw += c);
        r.on('end', () => {
            try {
                const vars = JSON.parse(raw).map(v => ({ key: v.envVar.key, value: v.envVar.value }));
                const iUser = vars.findIndex(v => v.key === 'ADMIN_USER');
                const iPass = vars.findIndex(v => v.key === 'ADMIN_PASS');
                if (iUser >= 0) vars[iUser].value = newUser; else vars.push({ key: 'ADMIN_USER', value: newUser });
                if (iPass >= 0) vars[iPass].value = newPass; else vars.push({ key: 'ADMIN_PASS', value: newPass });
                const body = JSON.stringify(vars);
                const putOpts = { hostname: 'api.render.com', path: `/v1/services/${RENDER_SERVICE_ID}/env-vars`,
                    method: 'PUT', headers: { Authorization: `Bearer ${RENDER_API_KEY}`, Accept: 'application/json', 'Content-Type': 'application/json' } };
                const req2 = https.request(putOpts, (r2) => {
                    let d = ''; r2.on('data', c => d += c);
                    r2.on('end', () => {
                        console.log('[admin] Credenciales actualizadas en Render');
                        res.json({ ok: true, message: 'Credenciales actualizadas. El servicio se reiniciará.' });
                    });
                });
                req2.on('error', e => res.status(500).json({ error: e.message }));
                req2.write(body); req2.end();
            } catch (e) { res.status(500).json({ error: e.message }); }
        });
    }).on('error', e => res.status(500).json({ error: e.message }));
});

// ================================================================
//  RUTAS: GESTIÓN DE ALUMNOS [ADMIN]
// ================================================================

/** GET /api/students  — Lista todos los alumnos */
app.get('/api/students', requireAdmin, (req, res) => {
    res.json({ students: db.getAllStudents() });
});

app.post('/api/students/import-json', requireAdmin, (req, res) => {
    const { students: input } = req.body || {};
    if (!Array.isArray(input)) return res.status(400).json({ error: 'Se esperaba { students: [...] }' });

    const prepared = [];
    for (const s of input) {
        if (!s.email || !s.studentId) continue;
        const em = String(s.email).trim().toLowerCase();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) continue;
        prepared.push({
            id: uuidv4(), email: em,
            studentId: String(s.studentId).trim(),
            name: s.name ? String(s.name).trim().slice(0, 100) : '',
            active: s.active !== false,
            allowedVideos: Array.isArray(s.allowedVideos) ? s.allowedVideos : ['*'],
            createdAt: new Date().toISOString(),
        });
    }
    const { added, skipped } = db.importStudents(prepared);
    const total = db.getAllStudents().length;
    res.json({ added, skipped: skipped + (input.length - prepared.length), total });
});

/** POST /api/students/import-csv  — Importa CSV (email,studentId,nombre) */
const csvUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (['.csv', '.txt'].includes(ext)) cb(null, true);
        else cb(new Error('Solo archivos CSV/TXT permitidos'), false);
    },
});

app.post('/api/students/import-csv', requireAdmin, csvUpload.single('csv'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Archivo CSV requerido' });

    const lines = req.file.buffer.toString('utf-8').split('\n').map(l => l.trim()).filter(Boolean);
    const startIdx = lines[0] && lines[0].toLowerCase().includes('email') ? 1 : 0;
    const prepared = [], errors = [];
    for (let i = startIdx; i < lines.length; i++) {
        const parts = lines[i].split(',').map(p => p.trim().replace(/^"|"$/g, ''));
        const [rawEmail, rawSid, rawName] = parts;
        if (!rawEmail || !rawSid) continue;
        const em = rawEmail.toLowerCase();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) { errors.push(`Fila ${i + 1}: email inválido`); continue; }
        prepared.push({ id: uuidv4(), email: em, studentId: rawSid, name: rawName || '', active: true, allowedVideos: ['*'], createdAt: new Date().toISOString() });
    }
    const { added, skipped } = db.importStudents(prepared);
    const total = db.getAllStudents().length;
    res.json({ added, skipped, total, errors });
});

app.post('/api/students', requireAdmin, (req, res) => {
    const { email, studentId, name, active, allowedVideos } = req.body || {};
    if (!email || !studentId) return res.status(400).json({ error: 'email y studentId requeridos' });
    const em = String(email).trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return res.status(400).json({ error: 'Email inválido' });
    if (db.findStudentByEmail(em)) return res.status(409).json({ error: 'Ya existe un alumno con ese email' });
    const student = db.createStudent({
        id: uuidv4(), email: em,
        studentId: String(studentId).trim(),
        name: name ? String(name).trim().slice(0, 100) : '',
        active: active !== false,
        allowedVideos: Array.isArray(allowedVideos) ? allowedVideos : ['*'],
        createdAt: new Date().toISOString(),
    });
    res.status(201).json({ student });
});

app.put('/api/students/:id', requireAdmin, (req, res) => {
    const { name, active, allowedVideos, studentId, resetDevice } = req.body || {};
    const updated = db.updateStudent(req.params.id, { name, active, allowedVideos, studentId, resetDevice });
    if (!updated) return res.status(404).json({ error: 'Alumno no encontrado' });
    res.json({ student: updated });
});

app.delete('/api/students/:id', requireAdmin, (req, res) => {
    const existing = db.findStudentById(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Alumno no encontrado' });
    db.deleteStudent(req.params.id);
    res.json({ ok: true });
});

// ================================================================
//  RUTAS: PROXY DE MANIFEST Y SEGMENTOS
// ================================================================
//
//  PROBLEMA QUE RESUELVEN ESTAS RUTAS:
//
//  En B2 mode los segmentos .ts están en un bucket PRIVADO de Backblaze.
//  El manifest (.m3u8) contiene rutas RELATIVAS a esos segmentos.
//  Si el reproductor descargara el manifest directamente desde B2, las
//  peticiones de segmentos irían a B2 sin auth → 403.
//
//  En local mode el manifest estaba siendo servido como fichero ESTÁTICO
//  sin ninguna validación de JWT → descargable sin autenticación.
//
//  SOLUCIÓN: TODOS los manifests se sirven a través de este proxy.
//  El proxy:
//    1. Valida el JWT (Bearer header o ?token=)
//    2. Lee el manifest (desde disco local o descargando de B2)
//    3. Rewrites segment URLs → apuntan a /api/proxy/segment/:videoId/:seg
//    4. Devuelve el manifest reescrito al reproductor
//
//  Los segmentos .ts son CIFRADOS con AES-128 por FFmpeg → son datos
//  basura sin la clave. Servir segmentos sin auth es seguro.
//  La clave /api/drm/key/:keyId → siempre requiere JWT.
//
//  RESULTADO FINAL:
//    - Alguien con curl/wget/extensión de descarga sólo obtiene
//      segmentos .ts cifrados inutilizables.
//    - El manifest sólo se entrega con JWT válido y de corta duración.
//    - La clave AES-128 sólo se entrega con JWT válido que además debe
//      contener el videoId correcto.
//    - Sin clave → sin video. Sin JWT → sin clave.

/**
 * GET /api/proxy/manifest/:videoId
 * Sirve el .m3u8 con JWT validado y URLs de segmentos reescritas.
 *
 * MODO LOCAL : segmentos apuntan a /api/proxy/segment/:videoId/:seg (pasan por el servidor)
 * MODO B2    : segmentos apuntan a URLs pre-firmadas de B2 directamente.
 *              El servidor NO toca el contenido del segmento → escala ilimitado.
 *              Los segmentos son AES-128 cifrados → inútiles sin la clave.
 *              La clave sigue requiriendo JWT válido → protección intacta.
 */
app.get('/api/r/:videoId', async (req, res) => {
    let token = (req.headers['authorization'] || '').replace('Bearer ', '') || req.query.token;
    if (token) {
        try { jwt.verify(token, JWT_SECRET); } catch { return res.status(401).send('Token inválido o expirado'); }
    } else {
        // Auto-emisión de token guest (5 min) para reproductores externos (Base44, etc.)
        // El token se incrusta en todas las URLs del manifest — el cliente nunca ve las URLs reales de Bunny
        token = jwt.sign(
            { sub: 'guest-' + crypto.randomBytes(4).toString('hex'), guest: true },
            JWT_SECRET,
            { expiresIn: '5m', issuer: 'reproductor-cursos' }
        );
    }

    const { videoId } = req.params;
    if (!/^[0-9a-f-]{36}$/i.test(videoId)) return res.status(400).send('videoId inválido');

    const base = getPublicBase(req);

    // ====== MODO BUNNY.NET ================================================
    // La URL del manifest viene de la BD. Se proxea reescribiendo
    // todas las rutas relativas → nuestro propio servidor (con auth JWT).
    // El alumno nunca ve la URL real de Bunny.
    // ======================================================================
    const catalogEntry = db.getCatalogById(videoId);
    if (catalogEntry && catalogEntry.sourceType === 'bunny') {
        // ?sub= = manifest de rendición (base64url de URL absoluta de Bunny)
        const sub = req.query.sub ? Buffer.from(req.query.sub, 'base64url').toString('utf-8') : null;
        // Firmar URL con token auth de Bunny (genera bcdn_token automáticamente)
        const rawUrl = sub || catalogEntry.bunnyUrl;
        const targetUrl = signBunnyUrl(rawUrl);

        if (!isSafeBunnyUrl(targetUrl)) return res.status(400).send('URL inválida');

        try {
            const content = await fetchRemoteText(targetUrl);

            if (content.includes('#EXT-X-STREAM-INF')) {
                // Master manifest: reescribir renditions → nuestro proxy (con token incrustado)
                const rewritten = content.split('\n').map(line => {
                    const t = line.trim();
                    if (!t || t.startsWith('#')) return line;
                    const absUrl = resolveUrl(targetUrl, t);
                    const enc = Buffer.from(absUrl).toString('base64url');
                    return `${base}/api/r/${videoId}?sub=${enc}&token=${encodeURIComponent(token)}`;
                }).join('\n');
                return sendManifest(res, rewritten);
            }

            // Rendition manifest: detectar si Bunny ya tiene su propio cifrado
            const bunnyHasKey = content.includes('#EXT-X-KEY');
            const lines = content.split('\n');
            const rewrittenLines = [];

            if (bunnyHasKey) {
                // Bunny ya cifra sus segmentos: proxear su clave (requiere JWT) y
                // pasar los segmentos SIN re-cifrar (evita doble cifrado)
                for (const line of lines) {
                    const t = line.trim();
                    if (t.startsWith('#EXT-X-KEY:')) {
                        // Reescribir URI de la clave de Bunny → nuestro proxy-key (requiere JWT)
                        const uriMatch = t.match(/URI="([^"]+)"/);
                        if (uriMatch) {
                            const bunnyKeyUrl = resolveUrl(targetUrl, uriMatch[1]);
                            const encodedK = Buffer.from(bunnyKeyUrl).toString('base64url');
                            rewrittenLines.push(t.replace(/URI="[^"]+"/, `URI="${base}/api/drm/proxy-key?k=${encodedK}&token=${encodeURIComponent(token)}"`));
                        } else {
                            rewrittenLines.push(line);
                        }
                    } else if (t && !t.startsWith('#')) {
                        // Línea de segmento: enc=0 → proxy sin re-cifrar
                        const absUrl = resolveUrl(targetUrl, t);
                        const enc = Buffer.from(absUrl).toString('base64url');
                        rewrittenLines.push(`${base}/api/b/${videoId}?seg=${enc}&enc=0&token=${encodeURIComponent(token)}`);
                    } else {
                        rewrittenLines.push(line);
                    }
                }
            } else {
                // Bunny NO cifra: inyectar nuestra propia EXT-X-KEY y cifrar segmentos
                const keyUri = `${base}/api/drm/key/${catalogEntry.keyId}?token=${encodeURIComponent(token)}`;
                rewrittenLines.push(`#EXT-X-KEY:METHOD=AES-128,URI="${keyUri}",IV=0x${'0'.repeat(32)}`);
                for (const line of lines) {
                    const t = line.trim();
                    if (t && !t.startsWith('#')) {
                        const absUrl = resolveUrl(targetUrl, t);
                        const enc = Buffer.from(absUrl).toString('base64url');
                        rewrittenLines.push(`${base}/api/b/${videoId}?seg=${enc}&token=${encodeURIComponent(token)}`);
                    } else {
                        rewrittenLines.push(line);
                    }
                }
            }

            return sendManifest(res, rewrittenLines.join('\n'));
        } catch (err) {
            console.error('[proxy/manifest bunny]', err.message);
            return res.status(502).send('Error al obtener manifest de Bunny');
        }
    }
    // ====== FIN MODO BUNNY ================================================

    if (LOCAL_MODE) {
        const quality    = req.query.q || null;
        const hlsBase    = path.join(__dirname, 'public', 'hls', 'hls', videoId);
        const masterPath = path.join(hlsBase, 'master.m3u8');
        const singlePath = path.join(hlsBase, 'playlist.m3u8');

        // Solicitud de rendición específica (multi-bitrate ABR)
        if (quality) {
            if (!/^(360p|720p|1080p)$/.test(quality)) return res.status(400).send('Calidad inválida');
            const renditionPath = path.join(hlsBase, `${quality}.m3u8`);
            if (!fs.existsSync(renditionPath)) return res.status(404).send('Calidad no disponible');
            let content = fs.readFileSync(renditionPath, 'utf-8');
            content = content.replace(/^(seg\w+\.ts)$/gm, `${base}/api/b/${videoId}/$1?token=${encodeURIComponent(token)}`);
            return sendManifest(res, content);
        }

        // Master manifest (videos multi-bitrate procesados con el nuevo pipeline)
        if (fs.existsSync(masterPath)) {
            let content = fs.readFileSync(masterPath, 'utf-8');
            content = content.replace(/^(360p|720p|1080p)\.m3u8$/gm,
                (_, q) => `${base}/api/r/${videoId}?q=${q}&token=${encodeURIComponent(token)}`);
            return sendManifest(res, content);
        }

        // Playlist única (backward compat: videos procesados con el pipeline anterior)
        if (!fs.existsSync(singlePath)) return res.status(404).send('Video no encontrado');
        let content = fs.readFileSync(singlePath, 'utf-8');
        content = content.replace(/^(seg\w+\.ts)$/gm, `${base}/api/b/${videoId}/$1?token=${encodeURIComponent(token)}`);
        return sendManifest(res, content);
    }

    // ==== MODO B2: segmentos se sirven DIRECTAMENTE desde B2 =================
    // Descarga el manifest de B2, reescribe URLs y devuelve manifest al cliente.
    // Para renditions → URLs pre-firmadas de segmentos (TTL 6h).
    // Para master     → URLs del proxy de manifest para cada rendition.
    // =========================================================================
    try {
        const { downloadBuffer, getPresignedUrl } = require('./storage');
        const quality = req.query.q || null;

        // Descargar el manifest correcto
        let buf;
        if (quality) {
            if (!/^(360p|720p|1080p)$/.test(quality)) return res.status(400).send('Calidad inválida');
            buf = await downloadBuffer(`hls/${videoId}/${quality}.m3u8`);
        } else {
            try { buf = await downloadBuffer(`hls/${videoId}/master.m3u8`); }
            catch { buf = await downloadBuffer(`hls/${videoId}/playlist.m3u8`); }
        }
        const content = buf.toString('utf-8');

        // Master manifest: reescribir referencias a renditions con URLs del proxy
        if (content.includes('#EXT-X-STREAM-INF')) {
            const rewritten = content.replace(/^(360p|720p|1080p)\.m3u8$/gm,
                (_, q) => `${base}/api/r/${videoId}?q=${q}&token=${encodeURIComponent(token)}`);
            return sendManifest(res, rewritten);
        }

        // Rendition / playlist única: generar pre-signed URLs por segmento (TTL 6h)
        const SEG_TTL = 6 * 3600;
        const lines   = content.split('\n');
        const segs    = lines.map(l => l.trim()).filter(l => /^seg\w+\.ts$/.test(l));
        const urlMap  = {};
        await Promise.all(segs.map(async (seg) => {
            urlMap[seg] = await getPresignedUrl(`hls/${videoId}/${seg}`, SEG_TTL);
        }));
        const rewritten = lines.map(l => { const t = l.trim(); return urlMap[t] ? urlMap[t] : l; }).join('\n');
        return sendManifest(res, rewritten);
    } catch (err) {
        console.error('[proxy/manifest B2]', err.message);
        return res.status(502).send('Error al obtener manifest de B2');
    }
});

/**
 * GET /api/proxy/segment/:videoId  — Bunny.net segments (vía ?seg=BASE64URL)
 * Requiere JWT. El parámetro ?seg= lleva la URL real de Bunny codificada.
 * El alumno nunca ve la URL real de Bunny — solo ve nuestro proxy.
 */
app.get('/api/b/:videoId', (req, res) => {
    if (!req.query.seg) return res.status(400).send('Parámetro seg requerido');

    const { videoId } = req.params;
    if (!/^[0-9a-f-]{36}$/i.test(videoId)) return res.status(400).send('videoId inválido');

    const token = (req.headers['authorization'] || '').replace('Bearer ', '') || req.query.token;
    try { jwt.verify(token, JWT_SECRET); } catch { return res.status(401).send('No autorizado'); }

    let segUrl;
    try { segUrl = Buffer.from(req.query.seg, 'base64url').toString('utf-8'); } catch {
        return res.status(400).send('Parámetro seg inválido');
    }
    if (!isSafeBunnyUrl(segUrl)) return res.status(400).send('URL no permitida');
    // Firmar URL con token auth de Bunny
    segUrl = signBunnyUrl(segUrl);

    // enc=0 → Bunny ya cifra sus segmentos, pasar sin re-cifrar
    if (req.query.enc === '0') {
        const mod = segUrl.startsWith('https') ? https : http;
        const parsedUrl = new URL(segUrl);
        const upReq = mod.get(segUrl, { timeout: 30000, headers: { Referer: `${parsedUrl.protocol}//${parsedUrl.host}/` } }, (upstream) => {
            if (upstream.statusCode >= 300 && upstream.statusCode < 400 && upstream.headers.location) {
                upReq.destroy();
                const loc = upstream.headers.location;
                if (!isSafeBunnyUrl(loc)) { res.status(400).send('Redirect no permitido'); return; }
                const mod2 = loc.startsWith('https') ? https : http;
                mod2.get(loc, { timeout: 30000 }, (up2) => {
                    if (up2.statusCode !== 200) { res.status(502).send('Error Bunny'); return; }
                    up2.pipe(res);
                }).on('error', () => { if (!res.headersSent) res.status(502).send(''); });
                return;
            }
            if (upstream.statusCode !== 200) { res.status(502).send(`Bunny HTTP ${upstream.statusCode}`); return; }
            upstream.pipe(res);
            upstream.on('error', () => { if (!res.headersSent) res.status(502).send(''); else res.end(); });
        });
        upReq.on('error', () => { if (!res.headersSent) res.status(502).send('Error conectando Bunny'); });
        upReq.on('timeout', () => { upReq.destroy(); if (!res.headersSent) res.status(504).send('Timeout'); });
        res.on('close', () => upReq.destroy());
        return;
    }

    const segIdx = Math.max(0, parseInt(req.query.idx || '0', 10));

    const catalogEntry = db.getCatalogById(videoId);
    if (!catalogEntry || !catalogEntry.keyId) return res.status(500).send('Clave no encontrada');
    const keyHex = getKeyHex(catalogEntry.keyId);
    if (!keyHex) return res.status(500).send('Clave inválida');

    // Headers: application/octet-stream → extensiones de descarga no lo reconocen como video
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Cache-Control', 'no-store, no-cache');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Disposition', 'inline');

    // Cifrado AES-128-CBC en streaming: no espera descarga completa del segmento
    const mod = segUrl.startsWith('https') ? https : http;
    const parsedUrl = new URL(segUrl);
    const reqOpts = {
        timeout: 30000,
        headers: { Referer: `${parsedUrl.protocol}//${parsedUrl.host}/` }
    };

    const upstreamReq = mod.get(segUrl, reqOpts, (upstream) => {
        if (upstream.statusCode >= 300 && upstream.statusCode < 400 && upstream.headers.location) {
            // Redireccion: reintentar una sola vez
            upstreamReq.destroy();
            res.removeHeader('Content-Type');
            req.url = req.url; // keep url
            // Recurse manually
            const loc = upstream.headers.location;
            if (!isSafeBunnyUrl(loc)) { res.status(400).send('Redirect no permitido'); return; }
            const mod2 = loc.startsWith('https') ? https : http;
            const cipher2 = createAES128CipherStream(keyHex, segIdx);
            mod2.get(loc, reqOpts, (up2) => {
                if (up2.statusCode !== 200) { res.status(502).send('Error Bunny'); return; }
                up2.pipe(cipher2).pipe(res);
                up2.on('error', () => { if (!res.headersSent) res.status(502).send(''); });
            }).on('error', () => { if (!res.headersSent) res.status(502).send(''); });
            return;
        }
        if (upstream.statusCode !== 200) {
            if (!res.headersSent) res.status(502).send(`Bunny HTTP ${upstream.statusCode}`);
            return;
        }
        // Crear cipher stream y hacer pipe directo: Bunny → cifrador → cliente
        // El cliente empieza a recibir bytes cifrados inmediatamente
        const cipher = createAES128CipherStream(keyHex, segIdx);
        upstream.pipe(cipher).pipe(res);
        upstream.on('error', (e) => {
            console.error('[bunny stream upstream]', e.message);
            if (!res.headersSent) res.status(502).send('');
            else res.end();
        });
        cipher.on('error', (e) => {
            console.error('[bunny cipher]', e.message);
            if (!res.headersSent) res.status(502).send('');
            else res.end();
        });
    });
    upstreamReq.on('error', (e) => {
        console.error('[bunny req]', e.message);
        if (!res.headersSent) res.status(502).send('Error conectando Bunny');
    });
    upstreamReq.on('timeout', () => {
        upstreamReq.destroy();
        if (!res.headersSent) res.status(504).send('Timeout Bunny');
    });
    // Si el cliente cierra la conexión, cancelar la petición a Bunny
    res.on('close', () => upstreamReq.destroy());
});

/**
 * GET /api/proxy/segment/:videoId/:segname
 * Sirve el segmento .ts cifrado (sin auth — los datos son inutilizables
 * sin la clave AES-128, la cual siempre requiere JWT).
 * En local mode sirve desde disco; en B2 mode hace streaming desde B2.
 */
app.get('/api/b/:videoId/:segname', (req, res) => {
    const { videoId, segname } = req.params;
    if (!/^[0-9a-f-]{36}$/i.test(videoId)) return res.status(400).send('videoId inválido');
    if (!/^seg\w{1,20}\.ts$/.test(segname)) return res.status(400).send('segname inválido');

    // application/octet-stream: evita que extensiones de descarga lo reconozcan como video
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Cache-Control', 'no-store, no-cache');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Disposition', 'inline');

    if (LOCAL_MODE) {
        const segPath = path.join(__dirname, 'public', 'hls', 'hls', videoId, segname);
        if (!fs.existsSync(segPath)) return res.status(404).send('Segmento no encontrado');
        return res.sendFile(segPath);
    }

    // B2 mode: streaming desde B2
    const { downloadBuffer } = require('./storage');
    downloadBuffer(`hls/${videoId}/${segname}`)
        .then(buf => res.send(buf))
        .catch(err => {
            console.error('[proxy/segment]', err.message);
            res.status(502).send('Error al obtener segmento de B2');
        });
});

// ================================================================
//  RUTAS: SESIONES ACTIVAS
// ================================================================

/**
 * POST /api/session/heartbeat
 * El reproductor envía un ping cada 30s para mantener viva la sesión.
 * Si el JWT expiró o la sesión no existe → { revoked: true } → cliente pausa el video.
 */
app.post('/api/session/heartbeat', (req, res) => {
    const { sessionId, mediaToken, currentTime } = req.body || {};
    if (!sessionId || !mediaToken) {
        return apiError(res, 400, 'BAD_REQUEST', 'sessionId y mediaToken requeridos');
    }

    let tokenPayload;
    try {
        tokenPayload = jwt.verify(mediaToken, JWT_SECRET);
    } catch {
        return res.status(401).json({
            ok: false,
            revoked: true,
            reason: 'token_expired',
            error: { code: 'TOKEN_EXPIRED', message: 'mediaToken inválido o expirado', details: null, ts: new Date().toISOString() },
        });
    }

    if (tokenPayload.sessionId && tokenPayload.sessionId !== sessionId) {
        return apiError(res, 409, 'SESSION_MISMATCH', 'sessionId no coincide con el mediaToken');
    }

    const tokenEmail = String(tokenPayload.studentEmail || tokenPayload.email || '').trim().toLowerCase();
    if (tokenEmail) {
        const student = db.findStudentByEmail(tokenEmail);
        if (student && !student.active) {
            db.endSession(sessionId);
            return res.status(403).json({
                ok: false,
                revoked: true,
                reason: 'access_revoked',
                error: { code: 'ACCESS_REVOKED', message: 'Acceso revocado en tiempo real', details: null, ts: new Date().toISOString() },
            });
        }
    }

    const updated = db.heartbeatSession(sessionId, currentTime);
    if (!updated) {
        return res.status(404).json({
            ok: false,
            revoked: true,
            reason: 'session_not_found',
            error: { code: 'SESSION_NOT_FOUND', message: 'La sesión ya no existe o expiró', details: null, ts: new Date().toISOString() },
        });
    }
    res.json({ ok: true });
});

/**
 * POST /api/session/end
 * El reproductor avisa al servidor que terminó la reproducción.
 * Libera el slot de sesión para que el alumno pueda abrir otra pestaña.
 */
app.post('/api/session/end', (req, res) => {
    const { sessionId } = req.body || {};
    if (sessionId) db.endSession(sessionId);
    res.json({ ok: true });
});

// ================================================================
//  RUTAS: AUDITORÍA Y MARCA DE AGUA [ADMIN]
// ================================================================

/**
 * POST /api/audit/seed-devices  [ADMIN]
 * Restaura asociaciones correo+deviceId en audit_log tras cada deploy.
 * Body: { records: [{ studentEmail, deviceId }] }
 */
app.post('/api/audit/seed-devices', requireAdmin, (req, res) => {
    const { records } = req.body || {};
    if (!Array.isArray(records) || records.length === 0)
        return res.status(400).json({ error: 'records array requerido' });

    let inserted = 0, skipped = 0;
    for (const r of records) {
        const email    = (r.studentEmail || '').trim().slice(0, 254);
        const deviceId = (r.deviceId     || '').trim().slice(0, 128);
        if (!email || !deviceId) { skipped++; continue; }
        try {
            db.logDelivery({
                fingerprint:  `seed_${deviceId}`,
                userId:       email,
                videoId:      'seed',
                deviceId,
                studentEmail: email,
                ip:           'restored',
                userAgent:    'seed-restore',
            });
            inserted++;
        } catch { skipped++; }
    }
    res.json({ ok: true, inserted, skipped });
});

/**
 * POST /api/watermark/log
 * El reproductor cliente registra que comenzó la reproducción.
 * El body debe contener { mediaToken } (el token emitido por /api/video/:id/play).
 */
app.post('/api/watermark/log', (req, res) => {
    const { mediaToken } = req.body || {};
    if (!mediaToken) return res.status(400).json({ error: 'mediaToken requerido' });
    try {
        jwt.verify(mediaToken, JWT_SECRET); // Solo verificar que sea válido
        res.json({ ok: true });
    } catch {
        res.status(401).json({ error: 'Token inválido' });
    }
});

/**
 * GET /api/watermark/detect?fp=<fingerprint>  [ADMIN]
 * Busca a quién pertenece un fingerprint extraído de un video filtrado.
 */
app.get('/api/watermark/detect', requireAdmin, (req, res) => {
    const fp = (req.query.fp || '').trim().toLowerCase();
    if (!/^[0-9a-f]{16}$/.test(fp)) return res.status(400).json({ error: 'Fingerprint inválido (16 hex chars)' });
    const match = db.detectLeak(fp);
    if (!match) return res.status(404).json({ error: 'Fingerprint no encontrado' });
    res.json(match);
});

/**
 * GET /api/audit/log  [ADMIN]
 * Devuelve el log de entregas filtrable por userId y videoId.
 */
app.get('/api/audit/log', requireAdmin, (req, res) => {
    const userId  = req.query.userId  || undefined;
    const videoId = req.query.videoId || undefined;
    const limit   = Math.min(parseInt(req.query.limit || '500', 10), 2000);
    const { entries, total } = db.getAuditLog({ userId, videoId, limit });
    res.json({ entries, total });
});

// ================================================================
//  ARCHIVOS ESTÁTICOS
// ================================================================

// Servir segmentos HLS locales (los .ts están cifrados, la clave requiere auth)
if (LOCAL_MODE) {
    app.use('/hls', express.static(path.join(__dirname, 'public/hls'), {
        dotfiles: 'deny',
        setHeaders: (res, filePath) => {
            if (filePath.endsWith('.m3u8')) res.setHeader('Content-Type', 'application/vnd.apple.mpegurl');
            // octet-stream: segmentos cifrados AES-128 — extensiones no los reconocen como video
            if (filePath.endsWith('.ts'))   res.setHeader('Content-Type', 'application/octet-stream');
            res.setHeader('Cache-Control', 'no-store, no-cache');
            res.setHeader('X-Content-Type-Options', 'nosniff');
        },
    }));
}

// Archivos estáticos del frontend (index.html, admin.html, etc.)
app.use(express.static(path.join(__dirname), {
    index: false,
    dotfiles: 'deny',
    etag: process.env.NODE_ENV === 'production',
}));

// Librerías JS propias (HLS.js, etc.) — servidas desde /js/
app.use('/js', express.static(path.join(__dirname, 'public/js'), {
    dotfiles: 'deny',
    maxAge: '7d', // caché de 7 días en el navegador, es un fichero estático inmutable
}));

// Rutas explícitas del frontend
app.get('/', (req, res) => {
    // Si viene ?v= (videoId), servir el reproductor embebible
    if (req.query.v || req.query.videoId) {
        return res.sendFile(path.join(__dirname, 'index.html'));
    }
    res.redirect('/admin.html');
});
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// ================================================================
//  PLAYBACK API — Capa de comunicación para reproductores externos
//  No modifica ningún endpoint existente.
// ================================================================

const PLAYBACK_SESSION_TTL = 900; // 15 minutos en segundos
const ALLOWED_EVENT_TYPES = new Set([
    'lesson_opened', 'play_started', 'play_paused', 'play_resumed',
    'heartbeat', 'lesson_completed', 'lesson_closed', 'playback_error',
]);

/**
 * POST /api/playback/session
 * Inicia una sesión de reproducción desde un reproductor externo.
 * Valida alumno, dispositivo y acceso al video antes de emitir el token.
 */
app.post('/api/playback/session', (req, res) => {
    const { studentEmail, studentId, deviceId, courseId, lessonId } = req.body || {};

    if (!studentEmail || !studentId || !deviceId || !courseId || !lessonId) {
        return res.status(400).json({ error: 'Faltan campos requeridos: studentEmail, studentId, deviceId, courseId, lessonId' });
    }

    const emailNorm = String(studentEmail).trim().toLowerCase();
    const student = db.findStudentByEmail(emailNorm);

    // Respuesta idéntica para no existente o ID incorrecto (evita enumeración)
    if (!student || student.studentId !== String(studentId).trim()) {
        return res.status(401).json({ error: 'Credenciales incorrectas' });
    }
    if (!student.active) {
        return res.status(403).json({ error: 'Acceso desactivado. Contacta al administrador.' });
    }

    // Validar dispositivo: si ya tiene uno vinculado debe coincidir
    const fp = String(deviceId).slice(0, 64);
    if (student.deviceId && student.deviceId !== fp) {
        return res.status(403).json({ error: 'Dispositivo no autorizado para este acceso.' });
    }

    // Validar acceso al video (lessonId)
    const allowed = student.allowedVideos;
    if (!allowed.includes('*') && !allowed.includes(lessonId)) {
        return res.status(403).json({ error: 'Sin acceso a este contenido.' });
    }

    // Vincular dispositivo si es primer acceso
    if (!student.deviceId) {
        db.bindDevice(student.id, fp, new Date().toISOString());
    }

    const sessionId = uuidv4();
    const now = new Date().toISOString();

    // Guardar sesión en BD
    db.createPlaybackSession({
        sessionId,
        studentId:    student.studentId,
        studentEmail: student.email,
        courseId:     String(courseId),
        lessonId:     String(lessonId),
        deviceId:     fp,
        ttlSeconds:   PLAYBACK_SESSION_TTL,
    });

    // Token de sesión de corta vida (15 min) para autenticar eventos
    const sessionToken = jwt.sign(
        {
            sub:          student.id,
            sessionId,
            studentId:    student.studentId,
            studentEmail: student.email,
            courseId:     String(courseId),
            lessonId:     String(lessonId),
            deviceId:     fp,
            scope:        'playback',
        },
        JWT_SECRET,
        { expiresIn: `${PLAYBACK_SESSION_TTL}s`, issuer: 'reproductor-cursos' }
    );

    res.json({
        sessionId,
        studentId:    student.studentId,
        studentEmail: student.email,
        courseId:     String(courseId),
        lessonId:     String(lessonId),
        deviceId:     fp,
        sessionToken,
        expiresIn:    PLAYBACK_SESSION_TTL,
        timestamp:    now,
    });
});

/**
 * POST /api/playback/event
 * Recibe eventos del reproductor externo.
 * Requiere Authorization: Bearer <sessionToken> emitido por /api/playback/session
 */
app.post('/api/playback/event', (req, res) => {
    // Verificar token de sesión
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return apiError(res, 401, 'UNAUTHORIZED', 'Token de sesión requerido');

    let payload;
    try {
        payload = jwt.verify(token, JWT_SECRET, { issuer: 'reproductor-cursos' });
    } catch {
        return apiError(res, 401, 'TOKEN_EXPIRED', 'Token de sesión inválido o expirado');
    }

    if (payload.scope !== 'playback') {
        return apiError(res, 403, 'ACCESS_DENIED', 'Token no autorizado para este endpoint');
    }

    const { eventType, timestamp, extra, eventId, idempotencyKey } = req.body || {};

    if (!eventType || !ALLOWED_EVENT_TYPES.has(eventType)) {
        return apiError(res, 400, 'INVALID_EVENT_TYPE', `eventType inválido. Permitidos: ${[...ALLOWED_EVENT_TYPES].join(', ')}`);
    }

    const replayKey = String(idempotencyKey || eventId || '').trim();
    if (!replayKey) {
        return apiError(res, 400, 'MISSING_IDEMPOTENCY_KEY', 'idempotencyKey (o eventId) es obligatorio');
    }

    const pbSession = db.getPlaybackSession(payload.sessionId);
    if (!pbSession) {
        return apiError(res, 404, 'SESSION_NOT_FOUND', 'La sesión de playback no existe o expiró');
    }

    const tokenEmail = String(payload.studentEmail || '').trim().toLowerCase();
    if (tokenEmail) {
        const student = db.findStudentByEmail(tokenEmail);
        if (student && !student.active) {
            db.endPlaybackSession(payload.sessionId);
            return apiError(res, 403, 'ACCESS_REVOKED', 'Acceso revocado en tiempo real');
        }
    }

    if (!db.claimPlaybackEventIdempotency(replayKey, payload.sessionId)) {
        return apiError(res, 409, 'REPLAY_DETECTED', 'Evento duplicado (idempotencyKey ya procesado)');
    }

    const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
    const userAgent = (req.headers['user-agent'] || 'unknown').slice(0, 200);

    db.logPlaybackEvent({
        sessionId:    payload.sessionId,
        studentId:    payload.studentId,
        lessonId:     payload.lessonId,
        deviceId:     payload.deviceId,
        ip,
        userAgent,
        eventType,
        extra:        extra || null,
    });

    res.json({
        ok: true,
        sessionId: payload.sessionId,
        eventType,
        idempotencyKey: replayKey,
        timestamp: timestamp || new Date().toISOString(),
    });
});

// ================================================================
//  MONITOR API — Base44 consume estos endpoints para monitoreo
//  en tiempo real de todo lo que pasa en el reproductor.
//  Auth: header  Authorization: Bearer <MONITOR_KEY>
//  La clave se deriva del JWT_SECRET — estable mientras no cambie.
// ================================================================

const MONITOR_KEY = crypto
    .createHmac('sha256', JWT_SECRET)
    .update('campus-monitor-api-2026')
    .digest('hex')
    .slice(0, 40);

// Log al arrancar para que el admin pueda copiarla
console.log(`[monitor] API key: ${MONITOR_KEY}`);

// Timestamp del último acceso exitoso a cualquier endpoint /api/monitor/*
// Se usa para que el botón LIVE sepa si Base44 está conectada activamente
let _lastMonitorAccessAt = 0; // epoch ms

function requireMonitorKey(req, res, next) {
    const auth = req.headers['authorization'] || '';
    const key  = auth.startsWith('Bearer ') ? auth.slice(7) : (req.query.key || '');
    if (!key || key !== MONITOR_KEY) {
        return res.status(401).json({ error: 'Monitor key inválida' });
    }
    _lastMonitorAccessAt = Date.now(); // registrar que Base44 acaba de conectar
    next();
}

/**
 * GET /api/monitor/key
 * Devuelve la monitor key (solo accesible con el token de admin JWT).
 * Base44 llama esto una vez para obtener la clave, luego la guarda en sus secrets.
 */
app.get('/api/monitor/key', requireAdmin, (req, res) => {
    res.json({
        monitorKey: MONITOR_KEY,
        hint: 'Usa este valor como  Authorization: Bearer <monitorKey>  en las llamadas a /api/monitor/*',
        endpoints: [
            'GET /api/monitor/status',
            'GET /api/monitor/events?limit=50',
            'GET /api/monitor/catalog',
            'GET /api/monitor/students',
            'GET /api/monitor/activity?limit=100',
        ],
    });
});

/**
 * GET /api/monitor/status
 * Snapshot en tiempo real del sistema.
 */
app.get('/api/monitor/status', requireMonitorKey, (req, res) => {
    const catalog  = db.loadCatalog();
    const students = db.getAllStudents();
    const courses  = db.getAllCourses();
    const recent   = db.getAuditLog({ limit: 5 });

    const activeStudents = students.filter(s => s.active).length;
    const readyVideos    = catalog.filter(v => v.status === 'ready').length;

    res.json({
        ts:              new Date().toISOString(),
        system:          'campus-digital-pro',
        url:             'https://campus-digital-pro.onrender.com',
        totals: {
            videos:          catalog.length,
            videosReady:     readyVideos,
            courses:         courses.length,
            students:        students.length,
            studentsActive:  activeStudents,
            eventsLogged:    recent.total,
        },
        recentActivity: recent.entries.slice(0, 5).map(e => ({
            studentId:  e.userId,
            videoId:    e.videoId,
            eventType:  e.eventType || 'delivery',
            deviceId:   e.deviceId,
            ip:         e.ip,
            at:         e.deliveredAt,
        })),
    });
});

/**
 * GET /api/monitor/events?limit=50&studentId=X&videoId=Y
 * Últimos eventos de reproducción registrados.
 */
app.get('/api/monitor/events', requireMonitorKey, (req, res) => {
    const limit     = Math.min(parseInt(req.query.limit) || 50, 500);
    const studentId = req.query.studentId || null;
    const videoId   = req.query.videoId   || null;

    const result = db.getAuditLog({ userId: studentId, videoId, limit });

    res.json({
        ts:     new Date().toISOString(),
        total:  result.total,
        count:  result.entries.length,
        events: result.entries.map(e => ({
            studentId:  e.userId,
            videoId:    e.videoId,
            eventType:  e.eventType || 'delivery',
            deviceId:   e.deviceId,
            ip:         e.ip,
            at:         e.deliveredAt,
        })),
    });
});

/**
 * GET /api/monitor/catalog
 * Catálogo completo: todos los cursos con sus videos.
 */
app.get('/api/monitor/catalog', requireMonitorKey, (req, res) => {
    const courses = db.getAllCourses();
    const catalog = db.loadCatalog();

    const courseMap = {};
    for (const c of courses) courseMap[c.id] = { ...c, videos: [] };

    const unassigned = [];
    for (const v of catalog) {
        const entry = {
            videoId:   v.videoId,
            title:     v.title,
            status:    v.status,
            playerUrl: `https://campus-digital-pro.onrender.com/?v=${v.videoId}`,
            sortOrder: v.sortOrder,
            uploadedAt: v.uploadedAt,
        };
        if (v.courseId && courseMap[v.courseId]) {
            courseMap[v.courseId].videos.push(entry);
        } else {
            unassigned.push(entry);
        }
    }

    res.json({
        ts:             new Date().toISOString(),
        totalVideos:    catalog.length,
        totalCourses:   courses.length,
        courses:        Object.values(courseMap).map(c => ({
            id:         c.id,
            name:       c.name,
            author:     c.author,
            totalVideos: c.videos.length,
            videos:     c.videos.sort((a, b) => a.sortOrder - b.sortOrder),
        })),
        videosUnassigned: unassigned,
    });
});

/**
 * GET /api/monitor/students
 * Lista de alumnos con estado y actividad.
 */
app.get('/api/monitor/students', requireMonitorKey, (req, res) => {
    const students = db.getAllStudents();
    res.json({
        ts:    new Date().toISOString(),
        total: students.length,
        students: students.map(s => ({
            studentId:     s.studentId,
            email:         s.email,
            name:          s.name,
            active:        s.active,
            deviceBound:   !!s.deviceId,
            allowsAll:     s.allowedVideos.includes('*'),
            allowedVideos: s.allowedVideos.includes('*') ? ['*'] : s.allowedVideos,
            createdAt:     s.createdAt,
            lastLogin:     s.lastLogin,
        })),
    });
});

/**
 * GET /api/monitor/activity?limit=100
 * Actividad reciente enriquecida con nombres de video y curso.
 */
app.get('/api/monitor/activity', requireMonitorKey, (req, res) => {
    const limit  = Math.min(parseInt(req.query.limit) || 100, 500);
    const result = db.getAuditLog({ limit });
    const catalog = db.loadCatalog();
    const courses = db.getAllCourses();

    // Índices rápidos
    const vidMap    = {};
    const courseMap = {};
    for (const v of catalog) vidMap[v.videoId] = v;
    for (const c of courses) courseMap[c.id]   = c;

    // Mapa de última posición conocida por usuario+video (sesiones activas)
    const currentTimeMap = {};
    for (const e of result.entries) {
        if (!currentTimeMap[e.userId]) {
            try {
                const sessions = db.getActiveSessionsByUser(e.userId);
                for (const s of sessions) {
                    currentTimeMap[`${s.user_id}:${s.video_id}`] = s.current_time || 0;
                }
            } catch {}
        }
    }

    res.json({
        ts:    new Date().toISOString(),
        total: result.total,
        count: result.entries.length,
        activity: result.entries.map(e => {
            const vid    = vidMap[e.videoId];
            const course = vid?.courseId ? courseMap[vid.courseId] : null;
            return {
                studentId:    e.userId,
                studentEmail: e.studentEmail || null,
                videoId:      e.videoId,
                videoTitle:   vid?.title   || e.videoId,
                courseName:   course?.name || 'Sin curso',
                eventType:    e.eventType  || 'delivery',
                playerUrl:    `https://campus-digital-pro.onrender.com/?v=${e.videoId}`,
                deviceId:     e.deviceId,
                ip:           e.ip,
                currentTime:  currentTimeMap[`${e.userId}:${e.videoId}`] ?? null,
                at:           e.deliveredAt,
            };
        }),
    });
});

// ================================================================
//  BASE44 LIVE — Tracking perpetuo del reproductor hacia Base44
//  No modifica ningún endpoint existente.
// ================================================================

const B44_API_KEY = process.env.B44_API_KEY || 'f6863f8255d3411a8b223c1df7ceaee3';
const B44_APP_ID  = process.env.B44_APP_ID  || '69c1c9604918839b67ca03b2';
const B44_ALLOWED_EVENTS = new Set([
    'lesson_opened', 'play_started', 'play_paused', 'play_resumed',
    'heartbeat', 'lesson_completed', 'lesson_closed', 'playback_error',
]);

/**
 * GET /api/b44/ping
 * Health-check público para el botón LIVE del reproductor.
 * Sin autenticación — solo confirma que el servidor responde.
 */
app.get('/api/b44/ping', (_req, res) => {
    res.json({ ok: true, ts: Date.now(), service: 'campus-digital-pro' });
});

/**
 * GET /api/b44/status
 * Sin autenticación. El botón LIVE del reproductor y del admin llama esto.
 * Devuelve connected:true solo si Base44 llamó la Monitor API en los últimos 2 minutos.
 */
app.get('/api/b44/status', (_req, res) => {
    const STALE_MS  = 2 * 60 * 1000; // 2 minutos
    const elapsed   = _lastMonitorAccessAt ? Date.now() - _lastMonitorAccessAt : Infinity;
    const connected = elapsed <= STALE_MS;
    res.json({
        connected,
        lastPullAgo: _lastMonitorAccessAt ? Math.floor(elapsed / 1000) : null,
        ts: Date.now(),
    });
});

/**
 * POST /api/b44/track
 * Recibe eventos del reproductor, los almacena en BD y los reenvía a Base44.
 * Auth: cualquier JWT válido emitido por este servidor (el mismo que usa el reproductor).
 */
app.post('/api/b44/track', (req, res) => {
    const auth  = req.headers['authorization'] || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return apiError(res, 401, 'UNAUTHORIZED', 'Token requerido');

    let payload;
    try { payload = jwt.verify(token, JWT_SECRET); }
    catch { return apiError(res, 401, 'TOKEN_EXPIRED', 'token inválido o expirado'); }

    const { eventType, videoId, deviceId, extra, eventId, idempotencyKey } = req.body || {};

    if (!eventType || !B44_ALLOWED_EVENTS.has(eventType)) {
        return apiError(res, 400, 'INVALID_EVENT_TYPE', `eventType inválido. Permitidos: ${[...B44_ALLOWED_EVENTS].join(', ')}`);
    }

    const replayKey = String(idempotencyKey || eventId || '').trim();
    if (!replayKey) {
        return apiError(res, 400, 'MISSING_IDEMPOTENCY_KEY', 'idempotencyKey (o eventId) es obligatorio');
    }

    const sessionId = String(payload.sessionId || `b44:${payload.sub || 'unknown'}`);
    if (!db.claimPlaybackEventIdempotency(replayKey, sessionId)) {
        return apiError(res, 409, 'REPLAY_DETECTED', 'Evento duplicado (idempotencyKey ya procesado)');
    }

    const vid = String(videoId  || payload.videoId  || 'unknown').slice(0, 100);
    const did = String(deviceId || payload.deviceId || 'unknown').slice(0, 64);
    const ip  = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').split(',')[0].trim().slice(0, 45);
    const ua  = (req.headers['user-agent'] || '').slice(0, 200);

    // 1. Guardar en BD local (siempre, confiable)
    try {
        db.logPlaybackEvent({
            sessionId,
            studentId: did,
            lessonId:  vid,
            deviceId:  did,
            ip,
            userAgent: ua,
            eventType,
            extra: extra ? JSON.stringify(extra) : null,
        });
    } catch {}

    // 2. Responder al reproductor de inmediato (no esperar relay externo)
    res.json({ ok: true, ts: Date.now() });

    // 3. Relay a Base44 (best-effort, async — si falla no rompe nada)
    fetch(`https://${B44_APP_ID}.base44.app/api/Functions/trackPlaybackEvent`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': B44_API_KEY },
        body:    JSON.stringify({ videoId: vid, deviceId: did, eventType, ts: new Date().toISOString() }),
        signal:  AbortSignal.timeout(4000),
    }).catch(() => {}); // silencio intencional — Base44 puede estar en mantenimiento
});

// Catch-all 404
app.use((req, res) => res.status(404).json({ error: 'No encontrado' }));

// ================================================================
//  ARRANQUE
// ================================================================

// Limpiar sesiones expiradas cada 60 segundos
setInterval(() => {
    db.cleanExpiredSessions();
    db.cleanExpiredPlaybackSessions();
    db.cleanOldPlaybackDedupe();
}, 60_000);

app.listen(PORT, () => {
    console.log('');
    console.log('=========================================');
    console.log('  Reproductor DRM — Servidor iniciado');
    console.log(`  Reproductor: http://localhost:${PORT}`);
    console.log(`  Admin panel: http://localhost:${PORT}/admin`);
    console.log(`  Modo: ${LOCAL_MODE ? 'LOCAL (sin B2)' : 'Backblaze B2'}`);
    console.log('');
    console.log('  Credenciales admin:');
    console.log(`  Usuario: ${process.env.ADMIN_USER}`);
    console.log(`  Password: ${process.env.ADMIN_PASS}`);
    console.log('=========================================');
    console.log('');
});

// ================================================================
//  PLAYER TOKEN — Base44 u otro campus llama este endpoint
//  para generar un enlace de acceso corto para un alumno/video.
//
//  POST /api/player/create-token
//  Auth: Admin JWT
//  Body: { email, videoId, courseId? }
//  → { playbackUrl, token, expiresIn }
// ================================================================
app.post('/api/player/create-token', requireAdmin, (req, res) => {
    const { email, videoId, courseId, studentCode } = req.body || {};
    if (!email || !videoId) {
        return apiError(res, 400, 'BAD_REQUEST', 'email y videoId son requeridos');
    }

    const student = db.findStudentByEmail(email.trim().toLowerCase());
    if (!student) return apiError(res, 404, 'NOT_FOUND', 'Alumno no encontrado');
    if (!student.active) return apiError(res, 403, 'ACCESS_DENIED', 'Alumno desactivado');

    // Token de entrada — corto plazo (10 min). No es el JWT de sesión,
    // es solo el "pase de entrada" que el reproductor valida al cargar.
    const playToken = jwt.sign(
        {
            sub:         student.id,
            email:       student.email,
            courseId:    courseId  || null,
            videoId,
            studentCode: studentCode || student.studentId || student.id,
            type:        'playback_entry',
            admin:       false,
        },
        JWT_SECRET,
        { expiresIn: '10m', issuer: 'reproductor-cursos' }
    );

    const baseUrl = (process.env.PUBLIC_URL || 'https://campus-digital-pro.onrender.com').replace(/\/$/, '');
    const playbackUrl = `${baseUrl}/?v=${encodeURIComponent(videoId)}&pt=${playToken}`;

    res.json({ playbackUrl, token: playToken, expiresIn: '10m' });
});

// ================================================================
//  ADMIN METRICS — Dashboard usa este endpoint (auth: admin JWT)
//  GET /api/admin/metrics
//  Devuelve métricas por alumno: cursos, videos, tiempo, último acceso
// ================================================================
app.get('/api/admin/metrics', requireAdmin, (_req, res) => {
    try {
        const metrics = db.getStudentMetrics();
        res.json({ ts: new Date().toISOString(), total: metrics.length, metrics });
    } catch (err) {
        console.error('[admin/metrics]', err);
        apiError(res, 500, 'INTERNAL_ERROR', 'Error calculando métricas');
    }
});

// También exponer vía Monitor API para Base44/Google Sheets
app.get('/api/monitor/metrics', requireMonitorKey, (_req, res) => {
    try {
        const metrics = db.getStudentMetrics();
        res.json({ ts: new Date().toISOString(), total: metrics.length, metrics });
    } catch (err) {
        console.error('[monitor/metrics]', err);
        apiError(res, 500, 'INTERNAL_ERROR', 'Error calculando métricas');
    }
});

// ================================================================
//  HISTORIAL COMPLETO DE UN ALUMNO — Dashboard modal
//  GET /api/admin/student-history/:email
//  Devuelve: info del alumno, videos vistos con tiempo, eventos
// ================================================================
app.get('/api/admin/student-history/:email', requireAdmin, (req, res) => {
    try {
        const emailParam = decodeURIComponent(req.params.email).trim().toLowerCase();
        const student    = db.findStudentByEmail(emailParam);
        if (!student) return apiError(res, 404, 'NOT_FOUND', 'Alumno no encontrado');

        const catalog  = db.loadCatalog();
        const courses  = db.getAllCourses();
        const modules  = db.getAllModules ? db.getAllModules() : [];

        const vidMap    = {};
        const courseMap = {};
        const modMap    = {};
        for (const v of catalog) vidMap[v.videoId]   = v;
        for (const c of courses) courseMap[c.id]      = c;
        for (const m of modules) modMap[m.id]         = m;

        // Todos los eventos del alumno (audit_log)
        const auditResult = db.getAuditLog({ userId: student.id, limit: 500 });

        // Sesiones activas / históricas del alumno
        const sessionsRaw = db.getSessionsByUser ? db.getSessionsByUser(student.id) : [];

        // Mapa de tiempo máximo por video (de sesiones)
        const timeByVideo = {};
        for (const s of sessionsRaw) {
            const cur = timeByVideo[s.video_id] || 0;
            if ((s.current_time || 0) > cur) timeByVideo[s.video_id] = s.current_time;
        }

        // Videos vistos (distintos) con metadata
        const videoIds = [...new Set(auditResult.entries.map(e => e.videoId))];
        const videos = videoIds.map(vId => {
            const v       = vidMap[vId];
            const course  = v?.courseId ? courseMap[v.courseId] : null;
            const module_ = v?.moduleId ? modMap[v.moduleId]   : null;
            // Último acceso a este video
            const entry   = auditResult.entries.find(e => e.videoId === vId);
            return {
                videoId:     vId,
                title:       v?.title     || vId,
                courseName:  course?.name || 'Sin curso',
                moduleName:  module_?.name || '—',
                tiempoSeg:   timeByVideo[vId] || 0,
                ultimoAcceso: entry?.deliveredAt || null,
            };
        }).sort((a, b) => (b.ultimoAcceso || '') > (a.ultimoAcceso || '') ? 1 : -1);

        // Historial de eventos enriquecido
        const events = auditResult.entries.map(e => {
            const v      = vidMap[e.videoId];
            const course = v?.courseId ? courseMap[v.courseId] : null;
            return {
                eventType:  e.eventType || 'delivery',
                videoId:    e.videoId,
                videoTitle: v?.title    || e.videoId,
                courseName: course?.name || 'Sin curso',
                ip:         e.ip        || '—',
                deviceId:   e.deviceId  || '—',
                at:         e.deliveredAt,
            };
        });

        res.json({
            ts:       new Date().toISOString(),
            student:  {
                email:     student.email,
                name:      student.name,
                studentId: student.studentId,
                active:    student.active,
                deviceId:  student.deviceId,
                createdAt: student.createdAt,
                lastLogin: student.lastLogin,
            },
            videos,
            events,
        });
    } catch (err) {
        console.error('[student-history]', err);
        apiError(res, 500, 'INTERNAL_ERROR', 'Error obteniendo historial');
    }
});
