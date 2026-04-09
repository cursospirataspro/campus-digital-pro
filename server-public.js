const http = require('http');
const fs = require('fs');
const path = require('path');
const localtunnel = require('localtunnel');

const PORT = 3000;

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon'
};

const urlModule = require('url');

const server = http.createServer((req, res) => {
    const parsed = urlModule.parse(req.url, true);
    const pathname = parsed.pathname;

    // /watch?vid=VIDEO_ID
    if (pathname === '/watch' && parsed.query.vid) {
        const vid = parsed.query.vid;
        if (!/^[a-zA-Z0-9_-]{11}$/.test(vid)) {
            res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('ID de video invalido');
            return;
        }
        const htmlPath = path.join(__dirname, 'reproductor.html');
        fs.readFile(htmlPath, 'utf-8', (err, data) => {
            if (err) { res.writeHead(500); res.end('Error interno'); return; }
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(data);
        });
        return;
    }

    // /api/generate-link?videoId=URL_O_ID
    if (pathname === '/api/generate-link' && parsed.query.videoId) {
        const input = decodeURIComponent(parsed.query.videoId).trim();
        const videoId = extractYouTubeId(input);
        if (!videoId) {
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ error: 'No se pudo extraer un ID de YouTube valido' }));
            return;
        }
        const link = `${global.publicUrl || 'http://localhost:' + PORT}/watch?vid=${videoId}`;
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ videoId, link }));
        return;
    }

    // Archivos estáticos
    let filePath = pathname === '/' ? '/reproductor.html' : pathname;
    filePath = path.join(__dirname, filePath);
    const ext = path.extname(filePath);
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(filePath, (err, data) => {
        if (err) { res.writeHead(404); res.end('No encontrado'); return; }
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(data);
    });
});

function extractYouTubeId(input) {
    const patterns = [
        /(?:youtube\.com\/watch\?.*v=)([a-zA-Z0-9_-]{11})/,
        /(?:youtube\.com\/embed\/)([a-zA-Z0-9_-]{11})/,
        /(?:youtube\.com\/v\/)([a-zA-Z0-9_-]{11})/,
        /(?:youtube\.com\/shorts\/)([a-zA-Z0-9_-]{11})/,
        /(?:youtu\.be\/)([a-zA-Z0-9_-]{11})/,
        /^([a-zA-Z0-9_-]{11})$/
    ];
    for (const p of patterns) {
        const m = input.match(p);
        if (m) return m[1];
    }
    return null;
}

server.listen(PORT, async () => {
    console.log(`Servidor local: http://localhost:${PORT}`);
    console.log('');
    console.log('Conectando tunel publico...');
    
    try {
        const tunnel = await localtunnel({ port: PORT });
        global.publicUrl = tunnel.url;
        
        console.log('');
        console.log('==========================================');
        console.log('  URL PUBLICA (usar esta en tu pagina):');
        console.log(`  ${tunnel.url}`);
        console.log('');
        console.log('  Ejemplo enlace directo a video:');
        console.log(`  ${tunnel.url}/watch?vid=UrGU4Dg2FJM`);
        console.log('==========================================');
        console.log('');
        console.log('Copia la URL de arriba y pegala en tu pagina Base44.');
        console.log('Mientras esta ventana este abierta, el enlace funciona.');
        
        tunnel.on('close', () => {
            console.log('Tunel cerrado.');
        });
    } catch (err) {
        console.error('Error al crear tunel:', err.message);
        console.log('El servidor sigue funcionando en localhost:' + PORT);
    }
});
