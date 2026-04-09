'use strict';
/**
 * storage.js — Almacenamiento con modo local y Backblaze B2 (S3-compatible)
 *
 * LOCAL_MODE=true  → archivos en ./public/hls/  (sin cuenta B2, ideal para desarrollo)
 * LOCAL_MODE=false → Backblaze B2 (producción)
 */

require('dotenv').config();

const fs   = require('fs');
const path = require('path');

// ---- Detectar modo ----
const LOCAL_MODE =
    process.env.LOCAL_MODE === 'true' ||
    !process.env.B2_KEY_ID ||
    process.env.B2_KEY_ID.trim() === '';

const LOCAL_HLS_DIR = path.resolve('./public/hls');

if (LOCAL_MODE) {
    if (!fs.existsSync(LOCAL_HLS_DIR)) fs.mkdirSync(LOCAL_HLS_DIR, { recursive: true });
    console.log('[Storage] Modo LOCAL - archivos en:', LOCAL_HLS_DIR);
} else {
    console.log('[Storage] Modo B2 -', process.env.B2_ENDPOINT);
}

// ---- Cliente B2 (solo se inicializa si no es modo local) ----
let s3 = null, BUCKET = null;
if (!LOCAL_MODE) {
    const { S3Client } = require('@aws-sdk/client-s3');
    s3 = new S3Client({
        endpoint: process.env.B2_ENDPOINT,
        region: process.env.B2_REGION,
        credentials: {
            accessKeyId: process.env.B2_KEY_ID,
            secretAccessKey: process.env.B2_APP_KEY,
        },
        forcePathStyle: true,
    });
    BUCKET = process.env.B2_BUCKET;
}

// ================================================================
//  API PÚBLICA
// ================================================================

/**
 * Sube un archivo al bucket B2 o al sistema local.
 */
async function uploadFile(source, b2Key, contentType) {
    if (LOCAL_MODE) {
        const dest = path.join(LOCAL_HLS_DIR, b2Key);
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        if (typeof source === 'string') {
            fs.copyFileSync(source, dest);
        } else {
            fs.writeFileSync(dest, source);
        }
        return b2Key;
    }

    const { PutObjectCommand } = require('@aws-sdk/client-s3');
    const body = typeof source === 'string' ? fs.createReadStream(source) : source;
    if (!contentType) {
        const ext = path.extname(b2Key).toLowerCase();
        const map = { '.ts': 'video/mp2t', '.m3u8': 'application/vnd.apple.mpegurl', '.mp4': 'video/mp4', '.key': 'application/octet-stream' };
        contentType = map[ext] || 'application/octet-stream';
    }
    await s3.send(new PutObjectCommand({ Bucket: BUCKET, Key: b2Key, Body: body, ContentType: contentType }));
    return b2Key;
}

/**
 * Devuelve la URL para acceder al manifest/segmento.
 * Local: ruta estática /hls/<b2Key>
 * B2: URL pre-firmada de corta duración
 */
async function getPresignedUrl(b2Key, expiresIn = 300) {
    if (LOCAL_MODE) {
        return `/hls/${b2Key}`;
    }
    const { GetObjectCommand } = require('@aws-sdk/client-s3');
    const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
    const cmd = new GetObjectCommand({ Bucket: BUCKET, Key: b2Key });
    return getSignedUrl(s3, cmd, { expiresIn });
}

/**
 * Descarga el contenido como Buffer.
 */
async function downloadBuffer(b2Key) {
    if (LOCAL_MODE) {
        const p = path.join(LOCAL_HLS_DIR, b2Key);
        return fs.readFileSync(p);
    }
    const { GetObjectCommand } = require('@aws-sdk/client-s3');
    const resp = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: b2Key }));
    const chunks = [];
    for await (const chunk of resp.Body) chunks.push(chunk);
    return Buffer.concat(chunks);
}

/**
 * Elimina un objeto.
 */
async function deleteFile(b2Key) {
    if (LOCAL_MODE) {
        const p = path.join(LOCAL_HLS_DIR, b2Key);
        if (fs.existsSync(p)) fs.unlinkSync(p);
        return;
    }
    const { DeleteObjectCommand } = require('@aws-sdk/client-s3');
    await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: b2Key }));
}

/**
 * Comprueba si un objeto existe.
 */
async function exists(b2Key) {
    if (LOCAL_MODE) {
        return fs.existsSync(path.join(LOCAL_HLS_DIR, b2Key));
    }
    const { HeadObjectCommand } = require('@aws-sdk/client-s3');
    try {
        await s3.send(new HeadObjectCommand({ Bucket: BUCKET, Key: b2Key }));
        return true;
    } catch (e) {
        if (e.name === 'NotFound' || e.$metadata?.httpStatusCode === 404) return false;
        throw e;
    }
}

/**
 * Lista objetos con un prefijo.
 */
async function listFiles(prefix) {
    if (LOCAL_MODE) {
        const base = path.join(LOCAL_HLS_DIR, prefix);
        if (!fs.existsSync(base)) return [];
        function walk(dir, rel) {
            const keys = [];
            for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
                const relPath = rel ? rel + '/' + entry.name : prefix + entry.name;
                if (entry.isDirectory()) keys.push(...walk(path.join(dir, entry.name), relPath));
                else keys.push(relPath);
            }
            return keys;
        }
        return walk(base, '');
    }
    const { ListObjectsV2Command } = require('@aws-sdk/client-s3');
    const keys = [];
    let continuationToken;
    do {
        const resp = await s3.send(new ListObjectsV2Command({ Bucket: BUCKET, Prefix: prefix, ContinuationToken: continuationToken }));
        for (const obj of (resp.Contents || [])) keys.push(obj.Key);
        continuationToken = resp.IsTruncated ? resp.NextContinuationToken : undefined;
    } while (continuationToken);
    return keys;
}

module.exports = { uploadFile, getPresignedUrl, downloadBuffer, deleteFile, exists, listFiles, LOCAL_MODE };
