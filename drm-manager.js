'use strict';
/**
 * drm-manager.js — Gestión de claves AES-128 y licencias DRM
 *
 * CAPAS DE PROTECCIÓN IMPLEMENTADAS:
 *
 *  1. AES-128 CBC  — Cifrado nativo de segmentos HLS (RFC 8216 §4.3.2.4).
 *     Funciona en todos los reproductores HLS sin plugins.
 *     Las claves NUNCA viajan al cliente sin un JWT válido y de corta duración.
 *
 *  2. ClearKey EME — Estándar W3C EME con claves simétricas simples.
 *     Soportado de forma nativa en Chrome, Firefox y Edge.
 *     Útil como capa adicional cuando se usa DASH o como fallback web.
 *
 *  3. Hooks para Widevine / FairPlay (a través de EZDRM o BuyDRM):
 *     Ver funciones `buildWidevineLicenseRequest` y `buildFairPlayRequest`.
 *     Para activarlos debes configurar WIDEVINE_ENDPOINT y FAIRPLAY_ASK en .env.
 *
 * IMPORTANTE:
 *  - En producción, migra el almacén de claves (keys.json) a un KMS dedicado
 *    (AWS KMS, HashiCorp Vault, Azure Key Vault, Google Cloud KMS).
 *  - Las claves se almacenan en disco cifradas con la clave MASTER_KEY (derivada
 *    de JWT_SECRET via HKDF). Esto añade una capa incluso si el archivo se roba.
 */

require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---- Almacén de claves (JSON en disco) ----
const KEYS_PATH = path.resolve(process.env.KEYS_STORE_PATH || './data/keys.json');

function ensureDataDir() {
    const dir = path.dirname(KEYS_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function loadStore() {
    ensureDataDir();
    if (!fs.existsSync(KEYS_PATH)) return {};
    try {
        return JSON.parse(fs.readFileSync(KEYS_PATH, 'utf-8'));
    } catch {
        return {};
    }
}

function saveStore(store) {
    ensureDataDir();
    fs.writeFileSync(KEYS_PATH, JSON.stringify(store, null, 2), { mode: 0o600 });
}

// ---- CLAVE MAESTRA para cifrar el almacén ----
// Derivada de JWT_SECRET usando HKDF-SHA256 (nunca se guarda en disco)
function deriveMasterKey() {
    return crypto.hkdfSync(
        'sha256',
        Buffer.from(process.env.JWT_SECRET || 'fallback-inseguro', 'utf-8'),
        Buffer.from('drm-key-store', 'utf-8'),
        Buffer.from('aes-128-key-encryption', 'utf-8'),
        32 // 256 bits
    );
}

function encryptKeyValue(plainHex) {
    const mk = deriveMasterKey();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', mk, iv);
    const encrypted = Buffer.concat([cipher.update(plainHex, 'utf-8'), cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decryptKeyValue(stored) {
    const [ivHex, dataHex] = stored.split(':');
    const mk = deriveMasterKey();
    const decipher = crypto.createDecipheriv('aes-256-cbc', mk, Buffer.from(ivHex, 'hex'));
    const dec = Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]);
    return dec.toString('utf-8');
}

// ================================================================
//  API PÚBLICA
// ================================================================

/**
 * Genera una nueva clave AES-128 para un video y la persiste en el almacén.
 * @param {string} videoId
 * @returns {{ keyId: string, keyHex: string, keyBase64: string }}
 */
function generateKey(videoId) {
    const keyId = crypto.randomUUID();
    const keyBytes = crypto.randomBytes(16); // 128 bits
    const keyHex = keyBytes.toString('hex');

    const store = loadStore();
    store[keyId] = {
        videoId,
        keyEnc: encryptKeyValue(keyHex),
        createdAt: new Date().toISOString(),
    };
    saveStore(store);

    return { keyId, keyHex, keyBase64: keyBytes.toString('base64') };
}

/**
 * Recupera la clave AES-128 en binario para servírsela al reproductor.
 * @param {string} keyId
 * @returns {Buffer|null}
 */
function getKeyBuffer(keyId) {
    const store = loadStore();
    const entry = store[keyId];
    if (!entry) return null;
    const keyHex = decryptKeyValue(entry.keyEnc);
    return Buffer.from(keyHex, 'hex');
}

/**
 * Devuelve la clave en formato hexadecimal (para FFmpeg --hls-key-info).
 * @param {string} keyId
 * @returns {string|null}
 */
function getKeyHex(keyId) {
    const store = loadStore();
    const entry = store[keyId];
    if (!entry) return null;
    return decryptKeyValue(entry.keyEnc);
}

/**
 * Devuelve el videoId asociado a un keyId.
 * @param {string} keyId
 * @returns {string|null}
 */
function getVideoIdForKey(keyId) {
    const store = loadStore();
    return store[keyId]?.videoId || null;
}

/**
 * Lista todos los keyIds asociados a un videoId.
 * @param {string} videoId
 * @returns {string[]}
 */
function listKeysForVideo(videoId) {
    const store = loadStore();
    return Object.entries(store)
        .filter(([, v]) => v.videoId === videoId)
        .map(([k]) => k);
}

/**
 * Revoca (elimina) un keyId. El video deja de ser reproducible con esa clave.
 * @param {string} keyId
 */
function revokeKey(keyId) {
    const store = loadStore();
    delete store[keyId];
    saveStore(store);
}

// ================================================================
//  CLEARKEY EME (W3C — soportado en Chrome, Firefox, Edge)
// ================================================================

/**
 * Genera la respuesta de licencia ClearKey según la especificación W3C EME.
 * El cliente envía { kids: [...], type: 'temporary' }.
 * @param {string[]} kidBase64urlList  Array de key IDs en base64url
 * @returns {object}  Objeto JSON de respuesta ClearKey
 */
function buildClearKeyLicense(kidBase64urlList) {
    const store = loadStore();
    const keys = [];

    for (const kid of kidBase64urlList) {
        // Buscar por kid (base64url del keyId UUID sin guiones)
        const keyIdHex = Buffer.from(kid, 'base64').toString('hex');
        const storeEntry = Object.entries(store).find(([k]) => {
            return Buffer.from(k.replace(/-/g, ''), 'hex').toString('hex') === keyIdHex ||
                   k === kid;
        });
        if (!storeEntry) continue;
        const [, entry] = storeEntry;
        const keyHex = decryptKeyValue(entry.keyEnc);
        keys.push({
            kty: 'oct',
            kid, // base64url
            k: Buffer.from(keyHex, 'hex').toString('base64url'),
        });
    }

    return { keys, type: 'temporary' };
}

// ================================================================
//  WIDEVINE (EZDRM proxy — requiere suscripción)
// ================================================================

/**
 * Redirige la solicitud de licencia Widevine al proxy de EZDRM.
 * El frontend envía el challenge binario; este método lo reenvía autenticado.
 *
 * Para activar: configura WIDEVINE_ENDPOINT, WIDEVINE_USERNAME, WIDEVINE_PASSWORD en .env
 *
 * @param {Buffer} challenge  Mensaje binario enviado por el navegador (Widevine CDM)
 * @returns {Promise<Buffer>} Respuesta de licencia de Widevine
 */
async function proxyWidevineLicense(challenge) {
    if (!process.env.WIDEVINE_ENDPOINT) {
        throw new Error('WIDEVINE_ENDPOINT no configurado en .env');
    }
    const auth = Buffer.from(
        `${process.env.WIDEVINE_USERNAME}:${process.env.WIDEVINE_PASSWORD}`
    ).toString('base64');

    const resp = await fetch(process.env.WIDEVINE_ENDPOINT, {
        method: 'POST',
        headers: {
            Authorization: `Basic ${auth}`,
            'Content-Type': 'application/octet-stream',
        },
        body: challenge,
    });
    if (!resp.ok) throw new Error(`Widevine proxy error: ${resp.status}`);
    return Buffer.from(await resp.arrayBuffer());
}

// ================================================================
//  FAIRPLAY (EZDRM proxy — requiere Apple Developer Program)
// ================================================================

/**
 * Genera la respuesta SKD para FairPlay Streaming.
 * El repositorio de claves usa el mismo almacén local; en producción,
 * deberías firmar y cifrar según la especificación de Apple.
 *
 * Para activar: configura FAIRPLAY_ASK y FAIRPLAY_CERT_PATH en .env
 * Documentación: https://developer.apple.com/streaming/fps/
 *
 * @param {string} keyId
 * @returns {{ ckc: Buffer }}
 */
function buildFairPlayCKC(keyId) {
    if (!process.env.FAIRPLAY_ASK) {
        throw new Error('FAIRPLAY_ASK no configurado en .env');
    }
    const keyBuf = getKeyBuffer(keyId);
    if (!keyBuf) throw new Error('Clave no encontrada');

    // En producción real, aquí va el proceso de cifrado ASK→CKC de Apple.
    // Esta implementación devuelve la clave en crudo (solo para desarrollo/pruebas).
    return { ckc: keyBuf };
}

module.exports = {
    generateKey,
    getKeyBuffer,
    getKeyHex,
    getVideoIdForKey,
    listKeysForVideo,
    revokeKey,
    buildClearKeyLicense,
    proxyWidevineLicense,
    buildFairPlayCKC,
};
