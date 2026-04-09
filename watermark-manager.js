'use strict';
/**
 * watermark-manager.js — Sistema de marca de agua forense
 *
 * ESTRATEGIA DE MARCADO:
 *
 *  Toda entrega de un video queda registrada como una "impresión" que vincula:
 *    - userId       → quién recibió el video
 *    - videoId      → qué video se entregó
 *    - fingerprint  → código único de esa entrega (16 caracteres hex)
 *    - ip, userAgent, timestamp → datos de auditoría adicionales
 *
 *  El fingerprint se transmite al reproductor dentro del JWT de medios.
 *  El frontend renderiza el fingerprint en un canvas superpuesto al video:
 *    - Texto semitransparente con el código y/o email del usuario
 *    - Posición que varía aleatoriamente cada N segundos (dificulta recortar)
 *    - Opacidad baja (no molesta visualmente pero es detectable por software)
 *
 *  Cuando un video filtrado es detectado, se extrae el fingerprint visible
 *  y se busca en el log para identificar al usuario responsable.
 *
 * MEJORAS OPCIONALES PARA PRODUCCIÓN:
 *  - Esteganografía invisible en el stream de video (Imatag, Irdeto, NAGRA)
 *  - Variación de segmentos por usuario (A/B segment switching, ej: Axinom Watermarking)
 *  - Migrar el log a una base de datos relacional o time-series
 */

require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const LOG_PATH = path.resolve(process.env.WATERMARK_LOG_PATH || './data/watermark-log.json');

function ensureDataDir() {
    const dir = path.dirname(LOG_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function loadLog() {
    ensureDataDir();
    if (!fs.existsSync(LOG_PATH)) return [];
    try {
        return JSON.parse(fs.readFileSync(LOG_PATH, 'utf-8'));
    } catch {
        return [];
    }
}

function saveLog(log) {
    ensureDataDir();
    fs.writeFileSync(LOG_PATH, JSON.stringify(log, null, 2), { mode: 0o600 });
}

// ================================================================
//  API PÚBLICA
// ================================================================

/**
 * Genera un fingerprint único para una entrega.
 * Usa HMAC-SHA256 sobre (userId + videoId + timestamp + secreto),
 * truncado a 8 bytes (16 caracteres hex) para ser legible en pantalla.
 *
 * @param {string} userId
 * @param {string} videoId
 * @returns {string}  Fingerprint hex de 16 caracteres
 */
function generateFingerprint(userId, videoId) {
    const ts = Date.now().toString();
    const hmac = crypto.createHmac('sha256', process.env.JWT_SECRET || 'secret');
    hmac.update(`${userId}:${videoId}:${ts}:${crypto.randomBytes(4).toString('hex')}`);
    return hmac.digest('hex').slice(0, 16);
}

/**
 * Registra una entrega de video en el log de auditoría.
 *
 * @param {object} params
 * @param {string} params.userId
 * @param {string} params.videoId
 * @param {string} params.fingerprint   Generado por generateFingerprint()
 * @param {string} [params.ip]          IP del cliente
 * @param {string} [params.userAgent]   User-Agent del cliente
 */
function logDelivery({ userId, videoId, fingerprint, deviceId, ip, userAgent }) {
    const log = loadLog();
    log.push({
        fingerprint,
        userId,
        videoId,
        deviceId: deviceId || 'desconocido',
        ip: ip || 'desconocida',
        userAgent: userAgent || 'desconocido',
        deliveredAt: new Date().toISOString(),
    });
    saveLog(log);
}

/**
 * Busca en el log a qué usuario/entrega pertenece un fingerprint detectado
 * en un video filtrado.
 *
 * @param {string} fingerprint  Fingerprint extraído del video filtrado
 * @returns {object|null}       Registro de entrega o null si no se encuentra
 */
function detectLeak(fingerprint) {
    if (!fingerprint || !/^[0-9a-f]{16}$/.test(fingerprint)) return null;
    const log = loadLog();
    return log.find(entry => entry.fingerprint === fingerprint) || null;
}

/**
 * Devuelve el log de auditoría completo.
 * En el servidor, esta función solo debe ser accesible para administradores.
 *
 * @param {object} [filters]
 * @param {string} [filters.userId]   Filtrar por usuario específico
 * @param {string} [filters.videoId]  Filtrar por video específico
 * @param {number} [filters.limit]    Máximo de registros (default 500)
 * @returns {object[]}
 */
function getAuditLog({ userId, videoId, limit = 500 } = {}) {
    let log = loadLog();
    if (userId) log = log.filter(e => e.userId === userId);
    if (videoId) log = log.filter(e => e.videoId === videoId);
    // Más recientes primero
    log.sort((a, b) => new Date(b.deliveredAt) - new Date(a.deliveredAt));
    return log.slice(0, limit);
}

/**
 * Genera el texto que el reproductor insertará en el canvas de marca de agua.
 * Incluye el fingerprint y, opcionalmente, el email/identificador del usuario.
 *
 * @param {string} fingerprint
 * @param {string} [userLabel]  Email u otro identificador legible
 * @returns {string}
 */
function buildWatermarkText(fingerprint, userLabel) {
    const base = `FP:${fingerprint}`;
    return userLabel ? `${base} · ${userLabel}` : base;
}

module.exports = {
    generateFingerprint,
    logDelivery,
    detectLeak,
    getAuditLog,
    buildWatermarkText,
};
