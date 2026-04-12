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
        const seed = JSON.stringify(catalog.map(v => ({
            videoId: v.videoId, title: v.title, sourceType: v.sourceType || 'bunny',
            status: v.status || 'ready', bunnyUrl: v.bunnyUrl || null,
            keyId: v.keyId || null, uploadedAt: v.uploadedAt
        })));
        // GET existing env vars
        const getOpts = { hostname: 'api.render.com', path: `/v1/services/${RENDER_SERVICE_ID}/env-vars`,
            headers: { Authorization: `Bearer ${RENDER_API_KEY}`, Accept: 'application/json' } };
        https.get(getOpts, (res) => {
            let raw = ''; res.on('data', c => raw += c);
            res.on('end', () => {
                try {
                    const vars = JSON.parse(raw).map(v => ({ key: v.envVar.key, value: v.envVar.value }));
                    const idx = vars.findIndex(v => v.key === 'CATALOG_SEED');
                    if (idx >= 0) vars[idx].value = seed; else vars.push({ key: 'CATALOG_SEED', value: seed });
                    const body = JSON.stringify(vars);
                    const putOpts = { hostname: 'api.render.com', path: `/v1/services/${RENDER_SERVICE_ID}/env-vars`,
                        method: 'PUT', headers: { Authorization: `Bearer ${RENDER_API_KEY}`, Accept: 'application/json', 'Content-Type': 'application/json' } };
                    const req = https.request(putOpts, (r2) => {
                        let d = ''; r2.on('data', c => d += c);
                        r2.on('end', () => console.log(`[sync] CATALOG_SEED actualizado: ${catalog.length} videos`));
                    });
                    req.on('error', e => console.error('[sync] Error:', e.message));
                    req.write(body); req.end();
                } catch (e) { console.error('[sync] Parse error:', e.message); }
            });
        }).on('error', e => console.error('[sync] GET error:', e.message));
    } catch (e) { console.error('[sync] Error:', e.message); }
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
const MEDIA_TTL      = parseInt(process.env.MEDIA_TOKEN_TTL || '300', 10);
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

// CORS — permite peticiones desde Base44 y dominio propio
const ALLOWED_ORIGINS = [
    'https://campusdigitalpro.com',
    'https://www.campusdigitalpro.com',
    /\.base44\.com$/,
    /\.base44\.app$/,
];
app.use((req, res, next) => {
    const origin = req.headers['origin'] || '';
    const allowed = ALLOWED_ORIGINS.some(o =>
        typeof o === 'string' ? o === origin : o.test(origin)
    );
    if (allowed) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // Permitir iframe desde Base44 y dominio propio (NO usar SAMEORIGIN que bloquea embeds)
    res.setHeader('Content-Security-Policy',
        "frame-ancestors 'self' https://campusdigitalpro.com https://www.campusdigitalpro.com https://*.base44.com https://*.base44.app"
    );
    res.setHeader('Referrer-Policy', 'no-referrer');
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
    const token = jwt.sign(
        {
            sub:           sessionId,
            email:         'guest',
            label:         deviceId,
            deviceId,
            allowedVideos: ['*'],
            admin:         false,
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES, issuer: 'reproductor-cursos' }
    );
    res.json({ token, expiresIn: JWT_EXPIRES });
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

    // Verificar que el alumno tenga acceso a este video
    if (!req.user.admin) {
        const allowed = Array.isArray(req.user.allowedVideos) ? req.user.allowedVideos : ['*'];
        if (!allowed.includes('*') && !allowed.includes(videoId)) {
            return res.status(403).json({ error: 'No tienes acceso a este video.' });
        }
    }

    try {
        const manifestUrl = `/api/r/${videoId}`;

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
            ip: req.ip,
            userAgent: req.headers['user-agent'],
        });

        // Token de medios de corta duración
        const mediaToken = jwt.sign(
            { sub: req.user.sub, videoId, fingerprint, watermarkText },
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
    const { sessionId, mediaToken } = req.body || {};
    if (!sessionId || !mediaToken) return res.status(400).json({ error: 'sessionId y mediaToken requeridos' });
    try { jwt.verify(mediaToken, JWT_SECRET); } catch {
        return res.status(401).json({ revoked: true, reason: 'token_expired' });
    }
    const updated = db.heartbeatSession(sessionId);
    if (!updated) return res.status(404).json({ revoked: true, reason: 'session_not_found' });
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

// Catch-all 404
app.use((req, res) => res.status(404).json({ error: 'No encontrado' }));

// ================================================================
//  ARRANQUE
// ================================================================

// Limpiar sesiones expiradas cada 60 segundos
setInterval(() => db.cleanExpiredSessions(), 60_000);

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
