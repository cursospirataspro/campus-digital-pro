'use strict';
/**
 * hls-processor.js — Pipeline de procesamiento HLS con cifrado AES-128
 *
 * FLUJO DE TRABAJO:
 *  1. Recibe la ruta del video original (subido a /tmp/uploads/)
 *  2. Genera una clave AES-128 única para el video (via drm-manager)
 *  3. Crea el manifesto de claves que FFmpeg necesita (keyinfo file)
 *  4. Ejecuta FFmpeg: MP4 → segmentos .ts cifrados + manifest .m3u8
 *  5. Sube todos los archivos a Backblaze B2 (vía storage.js)
 *  6. Limpia archivos temporales locales
 *
 * CIFRADO:
 *  FFmpeg genera HLS con EXT-X-KEY que apunta a nuestro endpoint:
 *    /api/drm/key/<keyId>
 *  El servidor valida el JWT antes de devolver la clave binaria.
 *  Sin una clave válida el reproductor no puede descifrar los segmentos.
 *
 * REQUISITO: tener FFmpeg instalado en el sistema.
 *   Linux/macOS:  apt install ffmpeg  /  brew install ffmpeg
 *   Windows:      https://ffmpeg.org/download.html  (agregar bin/ al PATH)
 *
 * USO DIRECTO (CLI):
 *   node hls-processor.js <ruta-video> <videoId>
 */

require('dotenv').config();

const ffmpeg = require('fluent-ffmpeg');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { generateKey } = require('./drm-manager');
const { uploadFile } = require('./storage');

// Duración de cada segmento en segundos (RFC 8216 §4.3.3.1 recomienda 6-10 s)
const HLS_SEGMENT_DURATION = 10;

/**
 * Genera el archivo keyinfo temporal que FFmpeg requiere para cifrado HLS.
 * Formato:   <URI de la clave>\n<ruta local del archivo .key>\n<IV hex (opcional)>
 *
 * @param {string} keyUri  URL pública donde el reproductor solicitará la clave
 * @param {string} keyHex  Clave AES-128 en hexadecimal
 * @param {string} tmpDir  Directorio temporal de trabajo
 * @returns {{ keyInfoPath: string, keyFilePath: string }}
 */
function writeKeyInfoFile(keyUri, keyHex, tmpDir) {
    const keyFilePath = path.join(tmpDir, 'enc.key');
    const keyInfoPath = path.join(tmpDir, 'enc.keyinfo');

    // Escribir clave binaria
    fs.writeFileSync(keyFilePath, Buffer.from(keyHex, 'hex'), { mode: 0o600 });

    // Archivo keyinfo: URI \n ruta_local \n (sin IV → FFmpeg auto-genera IV incremental)
    fs.writeFileSync(keyInfoPath, `${keyUri}\n${keyFilePath}\n`, { mode: 0o600 });

    return { keyInfoPath, keyFilePath };
}

/**
 * Ejecuta FFmpeg en un solo paso generando 3 calidades HLS (360p, 720p, 1080p).
 * Todos los renditions comparten la misma clave AES-128.
 * HLS.js elige la calidad automáticamente según el ancho de banda del alumno.
 *
 * @param {string} inputPath    Ruta del archivo de video de entrada
 * @param {string} outputDir    Directorio donde se guardan los segmentos y manifests
 * @param {string} keyInfoPath  Ruta al archivo keyinfo (mismo para los 3 renditions)
 * @returns {Promise<void>}
 */
function runFfmpegMultiBitrate(inputPath, outputDir, keyInfoPath) {
    return new Promise((resolve, reject) => {
        const ffmpegBin = process.env.FFMPEG_PATH || 'ffmpeg';
        const args = [
            '-i', inputPath,
            // Dividir entrada en 3 flujos de video para escalar cada uno
            '-filter_complex',
            '[0:v]split=3[v1][v2][v3];[v1]scale=-2:360[s360];[v2]scale=-2:720[s720];[v3]scale=-2:1080[s1080]',
            // ---- 360p (SD) ----
            '-map', '[s360]', '-map', '0:a:0',
            '-c:v', 'libx264', '-b:v', '800k', '-preset', 'fast', '-profile:v', 'main', '-level', '3.1',
            '-c:a', 'aac', '-b:a', '96k',
            '-hls_time', String(HLS_SEGMENT_DURATION), '-hls_list_size', '0',
            '-hls_key_info_file', keyInfoPath,
            '-hls_segment_filename', path.join(outputDir, 'seg360_%05d.ts'),
            '-f', 'hls', path.join(outputDir, '360p.m3u8'),
            // ---- 720p (HD) ----
            '-map', '[s720]', '-map', '0:a:0',
            '-c:v', 'libx264', '-b:v', '2500k', '-preset', 'fast', '-profile:v', 'high', '-level', '4.0',
            '-c:a', 'aac', '-b:a', '128k',
            '-hls_time', String(HLS_SEGMENT_DURATION), '-hls_list_size', '0',
            '-hls_key_info_file', keyInfoPath,
            '-hls_segment_filename', path.join(outputDir, 'seg720_%05d.ts'),
            '-f', 'hls', path.join(outputDir, '720p.m3u8'),
            // ---- 1080p (FHD) ----
            '-map', '[s1080]', '-map', '0:a:0',
            '-c:v', 'libx264', '-b:v', '5000k', '-preset', 'fast', '-profile:v', 'high', '-level', '4.2',
            '-c:a', 'aac', '-b:a', '128k',
            '-hls_time', String(HLS_SEGMENT_DURATION), '-hls_list_size', '0',
            '-hls_key_info_file', keyInfoPath,
            '-hls_segment_filename', path.join(outputDir, 'seg1080_%05d.ts'),
            '-f', 'hls', path.join(outputDir, '1080p.m3u8'),
        ];
        const proc = spawn(ffmpegBin, args);
        proc.stderr.on('data', chunk => process.stdout.write(chunk.toString()));
        proc.on('close', code => {
            if (code === 0) { console.log('\n[FFmpeg] Multi-bitrate completado.'); resolve(); }
            else reject(new Error(`FFmpeg terminó con código ${code}`));
        });
        proc.on('error', err => reject(new Error(
            `FFmpeg no encontrado: ${err.message}. Instálalo y agrégalo al PATH.`
        )));
    });
}

/**
 * Procesa un video al completo: cifrado HLS + subida a B2.
 *
 * @param {string} localVideoPath  Ruta completa del video fuente
 * @param {string} videoId         ID único del video (UUID o slug)
 * @param {string} keyServerBase   Base URL del servidor de claves
 *                                 (ej: "https://tu-dominio.com")
 * @returns {Promise<{
 *   videoId: string,
 *   keyId: string,
 *   manifestB2Key: string,
 *   segmentCount: number
 * }>}
 */
async function processVideo(localVideoPath, videoId, keyServerBase) {
    console.log(`[HLS] Iniciando procesamiento de video: ${videoId}`);

    // 1. Generar clave AES-128 única
    const { keyId, keyHex } = generateKey(videoId);
    console.log(`[HLS] Clave generada: keyId=${keyId}`);

    // 2. Crear directorio temporal de trabajo
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `hls-${videoId}-`));
    console.log(`[HLS] Directorio temporal: ${tmpDir}`);

    try {
        // 3. Escribir archivos de claves para FFmpeg
        const keyUri = `${keyServerBase}/api/drm/key/${keyId}`;
        const { keyInfoPath } = writeKeyInfoFile(keyUri, keyHex, tmpDir);

        // 4. Ejecutar FFmpeg (un solo paso: 360p + 720p + 1080p cifrados con AES-128)
        await runFfmpegMultiBitrate(localVideoPath, tmpDir, keyInfoPath);

        // 5. Generar master manifest HLS — HLS.js elige calidad según ancho de banda
        const masterContent = [
            '#EXTM3U',
            '#EXT-X-VERSION:3',
            '#EXT-X-STREAM-INF:BANDWIDTH=928000,RESOLUTION=640x360,NAME="360p"',
            '360p.m3u8',
            '#EXT-X-STREAM-INF:BANDWIDTH=2628000,RESOLUTION=1280x720,NAME="720p"',
            '720p.m3u8',
            '#EXT-X-STREAM-INF:BANDWIDTH=5128000,RESOLUTION=1920x1080,NAME="1080p"',
            '1080p.m3u8',
        ].join('\n');
        fs.writeFileSync(path.join(tmpDir, 'master.m3u8'), masterContent);

        // 6. Recopilar archivos generados (3 manifests de rendión + master + todos los .ts)
        const files = fs.readdirSync(tmpDir).filter(f =>
            f.endsWith('.m3u8') || f.endsWith('.ts')
        );
        console.log(`[HLS] Archivos generados: ${files.length} (${files.filter(f => f.endsWith('.ts')).length} segmentos)`);

        // 7. Subir a B2 en paralelo (master.m3u8 + renditions + segmentos cifrados)
        console.log('[B2] Subiendo archivos al bucket...');
        const uploadPromises = files.map(file => {
            const localPath = path.join(tmpDir, file);
            const b2Key = `hls/${videoId}/${file}`;
            return uploadFile(localPath, b2Key);
        });
        await Promise.all(uploadPromises);
        console.log('[B2] Subida completada.');

        const segmentCount = files.filter(f => f.endsWith('.ts')).length;
        const manifestB2Key = `hls/${videoId}/master.m3u8`;

        return { videoId, keyId, manifestB2Key, segmentCount };
    } finally {
        // 8. Limpiar archivos temporales de forma segura
        try {
            fs.rmSync(tmpDir, { recursive: true, force: true });
            console.log('[HLS] Archivos temporales eliminados.');
        } catch (cleanErr) {
            console.warn('[HLS] No se pudieron eliminar temporales:', cleanErr.message);
        }
    }
}

// ---- CLI ----
if (require.main === module) {
    const [, , inputPath, videoId] = process.argv;
    const base = process.env.PUBLIC_URL || `http://localhost:${process.env.PORT || 3000}`;

    if (!inputPath || !videoId) {
        console.error('Uso: node hls-processor.js <ruta-video> <videoId>');
        process.exit(1);
    }
    if (!fs.existsSync(inputPath)) {
        console.error(`Archivo no encontrado: ${inputPath}`);
        process.exit(1);
    }

    processVideo(inputPath, videoId, base)
        .then(result => {
            console.log('\n== RESULTADO ==');
            console.log(JSON.stringify(result, null, 2));
            process.exit(0);
        })
        .catch(err => {
            console.error('Error en el procesamiento:', err);
            process.exit(1);
        });
}

module.exports = { processVideo };
