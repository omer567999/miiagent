const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Groq = require('groq-sdk');
const { tavily } = require('@tavily/core');
const Stripe = require('stripe');
const path = require('path');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });
const tavilyClient = tavily({ apiKey: process.env.TAVILY_API_KEY });
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// GÜVENLİK AYARI (Butonların çalışması için bunu kapatmalıyız şimdilik)
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors());
app.use(express.json());

// BURASI ÇOK ÖNEMLİ: Dosya yoluna ../ ekledik
app.use(express.static('public'));

// ANA SAYFAYI ÇAĞIRMA: Bu blok sende yoktu, ekle mutlaka
app.get('/', (req, res) => {
    res.sendFile(path.resolve('public/index.html'));
});

app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));


async function setupDatabase() {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        full_name VARCHAR(255),
        plan VARCHAR(20) DEFAULT 'free',
        reports_used INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
        await client.query(`
      CREATE TABLE IF NOT EXISTS reports (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        content TEXT,
        status VARCHAR(20) DEFAULT 'processing',
        source_count INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
        await client.query('COMMIT');
        console.log('✅ Veritabanı hazır');
    } catch (err) {
        await client.query('ROLLBACK');
        throw err;
    } finally {
        client.release();
    }
}

function tokenOlustur(userId) {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

async function authMiddleware(req, res, next) {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'Token gerekli' });
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const result = await pool.query(
            'SELECT id, email, full_name, plan, reports_used FROM users WHERE id = $1',
            [decoded.userId]
        );
        if (!result.rows[0]) return res.status(401).json({ error: 'Kullanıcı bulunamadı' });
        req.user = result.rows[0];
        next();
    } catch {
        res.status(401).json({ error: 'Geçersiz token' });
    }
}

app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, fullName } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email ve şifre zorunlu' });
        if (password.length < 8) return res.status(400).json({ error: 'Şifre en az 8 karakter olmalı' });
        const hash = await bcrypt.hash(password, 12);
        const result = await pool.query(
            'INSERT INTO users (email, password_hash, full_name) VALUES ($1, $2, $3) RETURNING id, email, full_name, plan',
            [email.toLowerCase(), hash, fullName]
        );
        const token = tokenOlustur(result.rows[0].id);
        res.status(201).json({ token, user: result.rows[0] });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'Bu email zaten kayıtlı' });
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
        const user = result.rows[0];
        if (!user || !await bcrypt.compare(password, user.password_hash)) {
            return res.status(401).json({ error: 'Email veya şifre hatalı' });
        }
        const token = tokenOlustur(user.id);
        res.json({ token, user: { id: user.id, email: user.email, fullName: user.full_name, plan: user.plan } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/auth/me', authMiddleware, (req, res) => res.json({ user: req.user }));

app.post('/api/reports', authMiddleware, async (req, res) => {
    try {
        const { konu } = req.body;
        const user = req.user;
        if (user.plan === 'free' && user.reports_used >= 3) {
            return res.status(403).json({ error: 'Ücretsiz planda 3 rapor hakkınız var.', upgrade: true });
        }
        const result = await pool.query(
            'INSERT INTO reports (user_id, title, status) VALUES ($1, $2, $3) RETURNING id',
            [user.id, konu, 'processing']
        );
        res.json({ reportId: result.rows[0].id, mesaj: 'Rapor oluşturuluyor...' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/reports', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, title, status, source_count, created_at FROM reports WHERE user_id = $1 ORDER BY created_at DESC',
            [req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/reports/:id', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM reports WHERE id = $1 AND user_id = $2',
            [req.params.id, req.user.id]
        );
        if (!result.rows[0]) return res.status(404).json({ error: 'Rapor bulunamadı' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use((err, req, res, next) => {
    res.status(500).json({ error: err.message });
});

function wsBildir(ws, tip, veri) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ tip, veri }));
    }
}

async function arastir(konu, ws) {
    wsBildir(ws, 'adim', '🔍 İnternette araştırılıyor...');
    try {
        const r1 = await tavilyClient.search(konu, { maxResults: 3 });
        const r2 = await tavilyClient.search(konu + ' 2026', { maxResults: 3 });
        const r3 = await tavilyClient.search(konu + ' analiz', { maxResults: 2 });
        const tumVeriler = [...r1.results, ...r2.results, ...r3.results];
        wsBildir(ws, 'adim', `✅ ${tumVeriler.length} kaynak bulundu`);
        return tumVeriler;
    } catch (err) {
        wsBildir(ws, 'adim', '⚠️ Arama hatası, devam ediliyor...');
        return [];
    }
}

async function raporYaz(konu, veriler, ws, reportId, userId) {
    wsBildir(ws, 'adim', '📝 Rapor yazılıyor...');

    const veriMetni = veriler
        .slice(0, 8)
        .map((v, i) => `[${i + 1}] ${v.title}\n${v.content?.slice(0, 300)}`)
        .join('\n\n');

    const stream = await groq.chat.completions.create({
        model: 'llama-3.3-70b-versatile',
        max_tokens: 2000,
        stream: true,
        messages: [
            {
                role: 'system',
                content: 'Sen profesyonel bir araştırma ve rapor yazarısın. Markdown formatında, Türkçe, kapsamlı raporlar yazarsın.'
            },
            {
                role: 'user',
                content: `Konu: "${konu}"\n\nAraştırma Verileri:\n${veriMetni}\n\nBu konuda profesyonel, detaylı bir rapor yaz. Şu bölümleri içersin:\n# ${konu}\n## Özet\n## Detaylı Analiz\n## Önemli Bulgular\n## Sonuç ve Öneriler`
            }
        ]
    });

    let tamRapor = '';
    for await (const chunk of stream) {
        const text = chunk.choices[0]?.delta?.content || '';
        if (text) {
            tamRapor += text;
            wsBildir(ws, 'kelime', text);
        }
    }

    await pool.query(
        'UPDATE reports SET content = $1, status = $2, source_count = $3 WHERE id = $4',
        [tamRapor, 'done', veriler.length, reportId]
    );

    await pool.query(
        'UPDATE users SET reports_used = reports_used + 1 WHERE id = $1',
        [userId]
    );

    wsBildir(ws, 'tamamlandi', { reportId, kaynakSayisi: veriler.length });
}

wss.on('connection', (ws) => {
    ws.on('message', async (data) => {
        try {
            const mesaj = JSON.parse(data);
            if (mesaj.tip === 'rapor_olustur') {
                const { reportId, konu, token } = mesaj;
                const decoded = jwt.verify(token, process.env.JWT_SECRET);
                wsBildir(ws, 'basladi', `"${konu}" araştırılıyor...`);
                const veriler = await arastir(konu, ws);
                await raporYaz(konu, veriler, ws, reportId, decoded.userId);
            }
        } catch (err) {
            wsBildir(ws, 'hata', err.message);
        }
    });
});

const PORT = process.env.PORT || 3000;
setupDatabase().then(() => {
    server.listen(PORT, () => {
        console.log(`🚀 MiiAgent: http://localhost:${PORT}`);
        console.log(`🔌 WebSocket: ws://localhost:${PORT}`);
    });
}).catch(err => {
    console.error('❌ Hata:', err.message);
    process.exit(1);
});