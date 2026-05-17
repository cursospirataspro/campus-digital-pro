/**
 * Script de restauración — restaura cursos y catálogo en el servidor en vivo
 * y sincroniza todo a Google Sheets en un solo batch (evita rate limit).
 * Uso: node _restore_backup.js
 */
const https = require('https');
const fs = require('fs');
const path = require('path');

const BASE_URL = 'https://campus-digital-pro.onrender.com';
const ADMIN_USER = 'admin@campusdigitalpro.com';
const ADMIN_PASS = '123456789';
const BACKUP_FILE = path.join(__dirname, 'backup_render_1285videos_2026-05-15.json');
const CHUNK_SIZE = 100; // videos por petición a SQLite

function request(method, urlPath, body, token) {
    return new Promise((resolve, reject) => {
        const data = body ? JSON.stringify(body) : null;
        const url = new URL(BASE_URL + urlPath);
        const options = {
            hostname: url.hostname,
            path: url.pathname + url.search,
            method,
            headers: {
                'Content-Type': 'application/json',
                ...(token ? { Authorization: `Bearer ${token}` } : {}),
                ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
            },
            timeout: 120000,
        };
        const req = https.request(options, (res) => {
            let raw = '';
            res.on('data', (c) => raw += c);
            res.on('end', () => {
                try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
                catch { resolve({ status: res.statusCode, body: raw }); }
            });
        });
        req.on('error', reject);
        req.on('timeout', () => req.destroy(new Error('Request timeout')));
        if (data) req.write(data);
        req.end();
    });
}

async function main() {
    console.log('1. Iniciando sesión admin...');
    const loginRes = await request('POST', '/api/auth/admin-login', {
        username: ADMIN_USER,
        password: ADMIN_PASS,
    });
    if (!loginRes.body.token) {
        console.error('Error al iniciar sesión:', loginRes.body);
        process.exit(1);
    }
    const token = loginRes.body.token;
    console.log('   ✓ Token obtenido\n');

    // Leer backup (strip BOM si existe)
    const raw = fs.readFileSync(BACKUP_FILE, 'utf8').replace(/^\uFEFF/, '');
    const backup = JSON.parse(raw);
    // El backup fue exportado con PowerShell que envuelve arrays: { value: [...], Count: N }
    const catalog = Array.isArray(backup.catalog) ? backup.catalog : (backup.catalog?.value || []);
    console.log(`2. Backup cargado: ${backup.courses?.length || 0} cursos, ${catalog.length} videos\n`);

    // --- Borrar todo antes de restaurar ---
    console.log('3. Limpiando cursos existentes en servidor...');
    const delRes = await request('DELETE', '/api/courses/all', null, token);
    console.log(`   ✓ Eliminados: ${delRes.body.deleted || 0} cursos\n`);

    // --- Restaurar cursos ---
    console.log('4. Restaurando cursos...');
    const coursesPayload = backup.courses.map(c => ({
        id: c.id,
        name: c.name,
        author: c.author || '',
    }));
    const coursesRes = await request('POST', '/api/courses/restore-bulk', { courses: coursesPayload }, token);
    console.log(`   ✓ Cursos: ${coursesRes.body.inserted} insertados, ${coursesRes.body.skipped} ya existían\n`);

    // --- Restaurar catálogo en chunks (SQLite) ---
    console.log('5. Restaurando catálogo de videos en SQLite...');
    let totalInserted = 0, totalSkipped = 0;
    for (let i = 0; i < catalog.length; i += CHUNK_SIZE) {
        const chunk = catalog.slice(i, i + CHUNK_SIZE);
        const res = await request('POST', '/api/catalog/restore-bulk', { videos: chunk }, token);
        totalInserted += res.body.inserted || 0;
        totalSkipped  += res.body.skipped  || 0;
        process.stdout.write(`   Chunk ${Math.floor(i / CHUNK_SIZE) + 1}/${Math.ceil(catalog.length / CHUNK_SIZE)} — insertados: ${totalInserted}, saltados: ${totalSkipped}\r`);
    }
    console.log(`\n   ✓ Videos: ${totalInserted} insertados, ${totalSkipped} ya existían\n`);

    // --- Sincronizar TODO a Google Sheets en bulk (1 sola llamada por tab) ---
    console.log('6. Sincronizando todo a Google Sheets (bulk)...');
    console.log('   ⌛ Esto puede tardar ~30 segundos...');
    const syncRes = await request('POST', '/api/admin/sync-sheets', null, token);
    if (syncRes.body.ok) {
        const s = syncRes.body.synced;
        console.log(`   ✓ Sheets actualizado — Videos: ${s.videos} | Cursos: ${s.courses} | Alumnos: ${s.students}\n`);
    } else {
        console.error('   ❌ Error en sync-sheets:', syncRes.body.error);
    }

    // --- Verificar estado final ---
    console.log('7. Verificando estado final...');
    const statusRes = await request('GET', '/api/monitor/status?key=a82af720bdfbc9d6a9fa70880b707b7bdedf18aa');
    const t = statusRes.body.totals || {};
    console.log(`   Videos:  ${t.videos}`);
    console.log(`   Cursos:  ${t.courses}`);
    console.log(`   Alumnos: ${t.students}`);
    console.log('\n✅ Restauración completa. Sheets queda con todos los datos para futuros reinicios.');
}

main().catch(console.error);


function request(method, urlPath, body, token) {
    return new Promise((resolve, reject) => {
        const data = body ? JSON.stringify(body) : null;
        const url = new URL(BASE_URL + urlPath);
        const options = {
            hostname: url.hostname,
            path: url.pathname,
            method,
            headers: {
                'Content-Type': 'application/json',
                ...(token ? { Authorization: `Bearer ${token}` } : {}),
                ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
            },
        };
        const req = https.request(options, (res) => {
            let raw = '';
            res.on('data', (c) => raw += c);
            res.on('end', () => {
                try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
                catch { resolve({ status: res.statusCode, body: raw }); }
            });
        });
        req.on('error', reject);
        if (data) req.write(data);
        req.end();
    });
}

async function main() {
    console.log('1. Iniciando sesión admin...');
    const loginRes = await request('POST', '/api/auth/admin-login', {
        username: ADMIN_USER,
        password: ADMIN_PASS,
    });
    if (!loginRes.body.token) {
        console.error('Error al iniciar sesión:', loginRes.body);
        process.exit(1);
    }
    const token = loginRes.body.token;
    console.log('   ✓ Token obtenido\n');

    // Leer backup (strip BOM si existe)
    const raw = fs.readFileSync(BACKUP_FILE, 'utf8').replace(/^\uFEFF/, '');
    const backup = JSON.parse(raw);
    // El backup fue exportado con PowerShell que envuelve arrays: { value: [...], Count: N }
    const catalog = Array.isArray(backup.catalog) ? backup.catalog : (backup.catalog?.value || []);
    console.log(`2. Backup cargado: ${backup.courses?.length || 0} cursos, ${catalog.length} videos\n`);

    // --- Restaurar cursos ---
    console.log('3. Restaurando cursos...');
    const coursesPayload = backup.courses.map(c => ({
        id: c.id,
        name: c.name,
        author: c.author || '',
    }));
    const coursesRes = await request('POST', '/api/courses/restore-bulk', { courses: coursesPayload }, token);
    console.log(`   ✓ Cursos: ${coursesRes.body.inserted} insertados, ${coursesRes.body.skipped} ya existían\n`);

    // --- Restaurar catálogo en chunks ---
    console.log('4. Restaurando catálogo de videos...');
    let totalInserted = 0, totalSkipped = 0;
    for (let i = 0; i < catalog.length; i += CHUNK_SIZE) {
        const chunk = catalog.slice(i, i + CHUNK_SIZE);
        const res = await request('POST', '/api/catalog/restore-bulk', { videos: chunk }, token);
        totalInserted += res.body.inserted || 0;
        totalSkipped  += res.body.skipped  || 0;
        process.stdout.write(`   Chunk ${Math.floor(i / CHUNK_SIZE) + 1}/${Math.ceil(catalog.length / CHUNK_SIZE)} — insertados: ${totalInserted}, saltados: ${totalSkipped}\r`);
    }
    console.log(`\n   ✓ Videos: ${totalInserted} insertados, ${totalSkipped} ya existían\n`);

    // --- Verificar estado final ---
    console.log('5. Verificando estado en servidor...');
    const statusRes = await request('GET', '/api/monitor/status?key=a82af720bdfbc9d6a9fa70880b707b7bdedf18aa');
    const t = statusRes.body.totals || {};
    console.log(`   Videos:  ${t.videos}`);
    console.log(`   Cursos:  ${t.courses}`);
    console.log(`   Alumnos: ${t.students}`);
    console.log('\n✅ Restauración completa.');
}

main().catch(console.error);
