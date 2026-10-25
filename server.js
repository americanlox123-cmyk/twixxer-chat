const express = require('express');
const http = require('http');
const crypto = require('crypto');
const { Server } = require('socket.io');
const { Pool } = require('pg');

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `scrypt:${salt}:${hash}`;
}

function verifyPassword(password, stored) {
    if (!stored) return false;
    if (stored.startsWith('scrypt:')) {
        const parts = stored.split(':');
        if (parts.length < 3) return false;
        const salt = parts[1];
        const hash = parts[2];
        try {
            const verify = crypto.scryptSync(password, salt, 64).toString('hex');
            if (hash.length !== verify.length) return false;
            return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(verify, 'hex'));
        } catch (e) {
            return false;
        }
    }
    return stored === password;
}

const app = express();
const server = http.createServer(app);
const io = require("socket.io")(server, {
  maxHttpBufferSize: 8e6, // голосовые и фото в base64 не должны рвать соединение
  cors: {
    origin: "*", // Разрешает подключения с любых сайтов (включая Netlify)
    methods: ["GET", "POST"]
  }
});
app.use(express.static('public'));
app.use('/node_modules/@timephy/rnnoise-wasm', express.static(
  require('path').join(__dirname, 'node_modules', '@timephy', 'rnnoise-wasm', 'dist')
));

// Раздаём worklet-файл
app.use('/rnnoise-worklet.js', express.static(
  require('path').join(__dirname, 'public', 'rnnoise-worklet.js')
));

const DATABASE_URL = process.env.DATABASE_URL;

let pool;
if (!DATABASE_URL) {
    console.error("КРИТИЧЕСКАЯ ОШИБКА: Секрет DATABASE_URL не задан!");
} else {
    pool = new Pool({
        connectionString: DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });

    pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(15) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            color VARCHAR(7) NOT NULL,
            status_emoji VARCHAR(5) DEFAULT '',
            avatar TEXT DEFAULT '',
            bio VARCHAR(100) DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS rooms (
            id VARCHAR(50) PRIMARY KEY,
            name VARCHAR(50) NOT NULL,
            type VARCHAR(10) NOT NULL, 
            creator_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            description VARCHAR(200) DEFAULT '',
            avatar TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS room_members (
            room_id VARCHAR(50) REFERENCES rooms(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            role VARCHAR(20) DEFAULT 'member',
            PRIMARY KEY (room_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            room_id VARCHAR(50) REFERENCES rooms(id) ON DELETE CASCADE,
            sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            sender_name VARCHAR(15) NOT NULL,
            sender_color VARCHAR(7) NOT NULL,
            text TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS friends (
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            friend_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            status VARCHAR(10) NOT NULL,
            PRIMARY KEY (user_id, friend_id)
        );
    `)
    .then(async () => {
        console.log('Таблицы в Supabase успешно проверены и инициализированы!');
        await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS bio VARCHAR(100) DEFAULT '';").catch(() => {});
        await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT DEFAULT '';").catch(() => {});
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS banner TEXT DEFAULT '';").catch(() => {});
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ;").catch(() => {});
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;").catch(() => {});
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_norm TEXT;").catch(() => {});
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT;").catch(() => {});
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN DEFAULT FALSE;").catch(() => {});
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_recovery TEXT;").catch(() => {});
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last BIGINT DEFAULT 0;").catch(() => {});
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS twofa_email BOOLEAN DEFAULT FALSE;").catch(() => {});
    await pool.query("CREATE TABLE IF NOT EXISTS email_actions (user_id INTEGER NOT NULL, kind VARCHAR(10) NOT NULL, email_norm TEXT, email TEXT, code_hash TEXT NOT NULL, attempts INTEGER DEFAULT 0, expires_at TIMESTAMPTZ NOT NULL, last_sent TIMESTAMPTZ NOT NULL, sent_count INTEGER DEFAULT 1, window_start TIMESTAMPTZ NOT NULL, PRIMARY KEY (user_id, kind));").catch(() => {});
    await pool.query("CREATE UNIQUE INDEX IF NOT EXISTS users_email_norm_idx ON users (email_norm) WHERE email_norm IS NOT NULL;").catch(() => {});
    await pool.query("CREATE TABLE IF NOT EXISTS email_codes (email_norm TEXT PRIMARY KEY, email TEXT NOT NULL, username TEXT NOT NULL, password_hash TEXT NOT NULL, color TEXT, code_hash TEXT NOT NULL, attempts INTEGER DEFAULT 0, expires_at TIMESTAMPTZ NOT NULL, last_sent TIMESTAMPTZ NOT NULL, sent_count INTEGER DEFAULT 1, window_start TIMESTAMPTZ NOT NULL);").catch(() => {});
    await pool.query("ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to INTEGER;").catch(() => {});
    await pool.query("ALTER TABLE messages ADD COLUMN IF NOT EXISTS edited BOOLEAN DEFAULT FALSE;").catch(() => {});
    await pool.query("ALTER TABLE rooms ADD COLUMN IF NOT EXISTS pinned_message_id INTEGER;").catch(() => {});
    await pool.query("CREATE TABLE IF NOT EXISTS message_reactions (message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, emoji VARCHAR(16) NOT NULL, created_at TIMESTAMP DEFAULT NOW(), PRIMARY KEY (message_id, user_id, emoji));").catch(() => {});
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_sub TEXT;").catch(() => {});
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS google_email TEXT DEFAULT '';").catch(() => {});
    await pool.query("CREATE UNIQUE INDEX IF NOT EXISTS users_google_sub_idx ON users (google_sub) WHERE google_sub IS NOT NULL;").catch(() => {});
    await pool.query("CREATE TABLE IF NOT EXISTS login_tokens (token_hash TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, created_at TIMESTAMP DEFAULT NOW());").catch(() => {});
        
        // Новое: Миграция БД для сохранения настроек тем
        await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS theme_base VARCHAR(10) DEFAULT 'dark';").catch(() => {});
        await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS theme_preset VARCHAR(20) DEFAULT 'default';").catch(() => {});
        await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS theme_custom TEXT DEFAULT '';").catch(() => {});
        
        // Новое: Миграция под архивацию чатов
        await pool.query("ALTER TABLE room_members ADD COLUMN IF NOT EXISTS is_archived BOOLEAN DEFAULT FALSE;").catch(() => {});
        await pool.query("ALTER TABLE room_members ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'member';").catch(() => {});
        await pool.query("ALTER TABLE rooms ADD COLUMN IF NOT EXISTS description VARCHAR(200) DEFAULT '';").catch(() => {});
        await pool.query("ALTER TABLE rooms ADD COLUMN IF NOT EXISTS avatar TEXT DEFAULT '';").catch(() => {});
        await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key TEXT DEFAULT '';").catch(() => {});
        await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS key_backup TEXT DEFAULT '';").catch(() => {});
        await pool.query(`CREATE TABLE IF NOT EXISTS room_reads (
            room_id VARCHAR(50) REFERENCES rooms(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            last_read_id INTEGER DEFAULT 0,
            PRIMARY KEY (room_id, user_id)
        )`).catch((e) => console.error('room_reads:', e.message));
        await pool.query("ALTER TABLE users ALTER COLUMN password TYPE VARCHAR(255);").catch(() => {});
        await pool.query("ALTER TABLE users ALTER COLUMN status_emoji TYPE VARCHAR(30);").catch(() => {});

        await pool.query("CREATE INDEX IF NOT EXISTS idx_messages_room_id ON messages(room_id);").catch(() => {});
        await pool.query("CREATE INDEX IF NOT EXISTS idx_room_members_user_id ON room_members(user_id);").catch(() => {});
        // Удаление аккаунтов (мягкое), удаление чатов «у себя» и ускорение выборок сообщений
        await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;").catch(() => {});
        await pool.query("ALTER TABLE room_members ADD COLUMN IF NOT EXISTS hidden BOOLEAN DEFAULT FALSE;").catch(() => {});
        await pool.query("ALTER TABLE room_members ADD COLUMN IF NOT EXISTS cleared_before INTEGER DEFAULT 0;").catch(() => {});
        await pool.query("CREATE INDEX IF NOT EXISTS idx_messages_room_created ON messages(room_id, created_at DESC, id DESC);").catch(() => {});
        await pool.query("CREATE INDEX IF NOT EXISTS idx_messages_room_id_id ON messages(room_id, id DESC);").catch(() => {});
        // Приватность: кто видит аватарку и время захода (all / friends / none), можно ли добавлять в группы без ссылки
        await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS privacy_avatar VARCHAR(8) DEFAULT 'all';").catch(() => {});
        await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS privacy_seen VARCHAR(8) DEFAULT 'all';").catch(() => {});
        await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS allow_invites BOOLEAN DEFAULT TRUE;").catch(() => {});
        // Хэш аватарки: по нему отдаём картинку отдельным кэшируемым запросом, а не внутри каждого сообщения
        await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_hash TEXT;").catch(() => {});
        await pool.query("CREATE INDEX IF NOT EXISTS idx_users_avatar_hash ON users(avatar_hash);").catch(() => {});
        // Сессии: устройство и последняя активность (список устройств в настройках)
        await pool.query("ALTER TABLE login_tokens ADD COLUMN IF NOT EXISTS user_agent TEXT DEFAULT '';").catch(() => {});
        await pool.query("ALTER TABLE login_tokens ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMP DEFAULT NOW();").catch(() => {});
        // Чёрные списки, жалобы и блокировка аккаунтов администрацией
        await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_at TIMESTAMPTZ;").catch(() => {});
        await pool.query("CREATE TABLE IF NOT EXISTS blocks (user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, blocked_id INTEGER REFERENCES users(id) ON DELETE CASCADE, created_at TIMESTAMPTZ DEFAULT NOW(), PRIMARY KEY (user_id, blocked_id));").catch((e) => console.error('blocks:', e.message));
        await pool.query("CREATE INDEX IF NOT EXISTS idx_blocks_blocked ON blocks(blocked_id);").catch(() => {});
        await pool.query("CREATE TABLE IF NOT EXISTS reports (id SERIAL PRIMARY KEY, reporter_id INTEGER REFERENCES users(id) ON DELETE SET NULL, reported_id INTEGER REFERENCES users(id) ON DELETE CASCADE, room_id TEXT, reason VARCHAR(20) NOT NULL, comment TEXT DEFAULT '', evidence TEXT DEFAULT '', status VARCHAR(10) DEFAULT 'open', created_at TIMESTAMPTZ DEFAULT NOW(), handled_by INTEGER, handled_at TIMESTAMPTZ);").catch((e) => console.error('reports:', e.message));
        await pool.query("CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);").catch(() => {});
        await pool.query("UPDATE users SET avatar_hash = encode(sha256(convert_to(avatar, 'UTF8')), 'hex') WHERE avatar LIKE 'data:image/%' AND avatar_hash IS NULL;").catch((e) => console.error('avatar_hash:', e.message));
        if (process.env.PURGE_LEGACY === '1') await purgeLegacyMessages().catch((e) => console.error('purgeLegacy:', e.message));
        if (process.env.ENCRYPT_EXISTING === '1') await encryptExistingMessages().catch((e) => console.error('encryptExisting:', e.message));
    })
    .catch(err => console.error('Ошибка инициализации таблиц Supabase:', err));
}

const authRateLimiter = {}; 
const mutedUsers = {}; 
const MUTE_DURATION = 30 * 60 * 1000; 
const SPAM_LIMIT = 5; 

// Хранилище активных и ожидающих вызовов
const activeCalls = {};

// Проверка онлайн-статуса
function isUserOnline(userId) {
    for (let [id, s] of io.of("/").sockets) {
        if (s.userId === userId) return true;
    }
    return false;
}

// Проверка и отправка ожидающих звонков при входе пользователя
// ===== Статус «в сети» =====
// Крупные аватарки отдаём ссылкой /a/<sha256>: браузер скачивает каждую один раз и кэширует
function avatarUrl(a) {
    if (typeof a === 'string' && a.startsWith('data:image/') && a.length > 1500) return '/a/' + sha256(a);
    return a || '';
}
app.get('/a/:hash', async (req, res) => {
    const h = String(req.params.hash || '');
    if (!pool || !/^[0-9a-f]{64}$/.test(h)) return res.status(404).end();
    try {
        const r = await pool.query('SELECT avatar FROM users WHERE avatar_hash = $1 LIMIT 1', [h]);
        const m = r.rows.length ? /^data:(image\/(?:png|jpeg|webp|gif));base64,([A-Za-z0-9+\/=]+)$/.exec(r.rows[0].avatar) : null;
        if (!m) return res.status(404).end();
        res.set({
            'Content-Type': m[1],
            'Cache-Control': 'public, max-age=31536000, immutable',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': "default-src 'none'",
            'Access-Control-Allow-Origin': '*',
            'Cross-Origin-Resource-Policy': 'cross-origin'
        });
        res.send(Buffer.from(m[2], 'base64'));
    } catch (e) { res.status(500).end(); }
});

async function friendIdSet(userId) {
    if (!userId) return new Set();
    const [f, bl] = await Promise.all([
        pool.query("SELECT friend_id FROM friends WHERE user_id = $1 AND status = 'accepted'", [userId]),
        pool.query('SELECT user_id, blocked_id FROM blocks WHERE user_id = $1 OR blocked_id = $1', [userId])
    ]);
    const s = new Set(f.rows.map((x) => x.friend_id));
    s.blockedBy = new Set(bl.rows.filter((x) => x.blocked_id === userId).map((x) => x.user_id)); // кто заблокировал меня
    s.blockedByMe = new Set(bl.rows.filter((x) => x.user_id === userId).map((x) => x.blocked_id)); // кого заблокировал я
    return s;
}
// Состояние блокировки между двумя пользователями: byMe — a заблокировал b, byThem — b заблокировал a
async function blockState(a, b) {
    const r = await pool.query('SELECT user_id FROM blocks WHERE (user_id = $1 AND blocked_id = $2) OR (user_id = $2 AND blocked_id = $1)', [a, b]);
    return { byMe: r.rows.some((x) => x.user_id === a), byThem: r.rows.some((x) => x.user_id === b) };
}
// Может ли viewer видеть данные владельца при уровне all / friends / none
function canSee(viewerId, ownerId, level, friendSet) {
    if (viewerId && viewerId === ownerId) return true;
    if (friendSet && friendSet.blockedBy && friendSet.blockedBy.has(ownerId)) return false; // заблокировавший не виден
    if (!level || level === 'all') return true;
    if (level === 'friends') return !!(friendSet && friendSet.has(ownerId));
    return false;
}
async function avatarFor(viewerId, ownerId, avatar) {
    if (!avatar || viewerId === ownerId) return avatar || '';
    const r = await pool.query(
        "SELECT privacy_avatar, EXISTS(SELECT 1 FROM friends WHERE user_id = $1 AND friend_id = $2 AND status = 'accepted') AS fr FROM users WHERE id = $2",
        [viewerId, ownerId]);
    if (!r.rows.length) return '';
    return canSee(viewerId, ownerId, r.rows[0].privacy_avatar, r.rows[0].fr ? new Set([ownerId]) : new Set()) ? avatarUrl(avatar) : '';
}
// Администраторы: ADMIN_USERNAMES=Twixxer,Helper  Письма о жалобах: ADMIN_EMAIL=me@example.com (можно несколько через запятую)
const ADMIN_NAMES = (process.env.ADMIN_USERNAMES || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
const ADMIN_EMAILS = (process.env.ADMIN_EMAIL || '').split(',').map((s) => s.trim()).filter(Boolean);
function isAdminName(name) { return !!name && ADMIN_NAMES.includes(String(name).toLowerCase()); }
function privacyOf(u) {
    return { avatar: u.privacy_avatar || 'all', seen: u.privacy_seen || 'all', invites: u.allow_invites !== false };
}
async function ensurePrivacy(sock) {
    if (!sock.privacy) {
        const r = await pool.query('SELECT privacy_avatar, privacy_seen, allow_invites FROM users WHERE id = $1', [sock.userId]);
        sock.privacy = privacyOf(r.rows[0] || {});
    }
    return sock.privacy;
}
async function announcePresence(userId, online, lastSeen) {
    const evt = { userId, online, lastSeen: lastSeen || null };
    try {
        const r = await pool.query('SELECT privacy_seen FROM users WHERE id = $1', [userId]);
        const lvl = (r.rows[0] && r.rows[0].privacy_seen) || 'all';
        if (lvl === 'all' || online) return io.emit('presence', evt);
        // Время захода скрыто: все видят «был(а) недавно», а друзья (если выбран такой уровень) настоящее время
        io.emit('presence', { userId, online: false, lastSeen: null, seenHidden: true });
        if (lvl === 'friends') (await friendIdSet(userId)).forEach((fid) => io.to(`user-${fid}`).emit('presence', evt));
    } catch (e) { console.error('presence:', e.message); }
}

// ===== Жалобы: список для администраторов и письма =====
const REPORT_REASONS = { spam: 'Спам', abuse: 'Оскорбления или угрозы', scam: 'Мошенничество', other: 'Другое' };
async function getOpenReports() {
    const r = await pool.query(
        `SELECT r.id, r.reason, r.comment, r.evidence, r.created_at, r.room_id, rep.username AS reporter_name,
                ru.id AS reported_id, ru.username AS reported_name, (ru.banned_at IS NOT NULL) AS banned
         FROM reports r
         LEFT JOIN users rep ON rep.id = r.reporter_id
         JOIN users ru ON ru.id = r.reported_id
         WHERE r.status = 'open' ORDER BY r.created_at ASC LIMIT 200`);
    return r.rows.map((x) => {
        let ev = [];
        try { ev = JSON.parse(x.evidence || '[]'); } catch (e) { ev = []; }
        return { id: x.id, reason: x.reason, comment: x.comment || '', evidence: ev, created_at: x.created_at,
                 reporter_name: x.reporter_name || 'удалён', reported_id: x.reported_id, reported_name: x.reported_name, banned: !!x.banned };
    });
}
async function pushReportsToAdmins() {
    try {
        const list = await getOpenReports();
        for (const [, s] of io.of('/').sockets) { if (s.userId && isAdminName(s.username)) s.emit('reports list', list); }
    } catch (e) { console.error('pushReports:', e.message); }
}
function mailAdminsAboutReport(rep) {
    if (!ADMIN_EMAILS.length) return;
    const esc = (v) => String(v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const reason = REPORT_REASONS[rep.reason] || rep.reason;
    const lines = rep.evidence.map((e) => '  ' + e.n + ': ' + e.t);
    const text = 'Жалоба #' + rep.id + '\nОт: ' + rep.reporter + '\nНа: ' + rep.reported + '\nПричина: ' + reason
        + (rep.comment ? '\nКомментарий: ' + rep.comment : '')
        + (lines.length ? '\n\nПоследние сообщения:\n' + lines.join('\n') : '')
        + '\n\nРазобрать жалобу можно в TwixxerChat: список чатов, папка «Жалобы».';
    const html = '<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:20px;color:#222">'
        + '<h2 style="margin:0 0 12px">Жалоба #' + rep.id + '</h2>'
        + '<p><b>От:</b> ' + esc(rep.reporter) + '<br><b>На:</b> ' + esc(rep.reported) + '<br><b>Причина:</b> ' + esc(reason) + '</p>'
        + (rep.comment ? '<p><b>Комментарий:</b> ' + esc(rep.comment) + '</p>' : '')
        + (lines.length ? '<p><b>Последние сообщения:</b></p><div style="background:#f4f4f6;border-radius:8px;padding:10px;font-size:13px">' + rep.evidence.map((e) => '<div><b>' + esc(e.n) + ':</b> ' + esc(e.t) + '</div>').join('') + '</div>' : '')
        + '<p style="color:#666;font-size:13px">Разобрать жалобу можно в TwixxerChat: список чатов, папка «Жалобы».</p></div>';
    ADMIN_EMAILS.forEach((to) => sendMail(to, 'Жалоба #' + rep.id + ' на ' + rep.reported, text, html).catch((e) => console.error('mail report:', e.message)));
}

// ===== Права в комнате и реакции =====
const ALLOWED_REACTIONS = ['👍', '❤️', '😂', '😮', '😢', '🔥'];
async function roomAccess(userId, roomId) {
    if (typeof roomId !== 'string') return { ok: false };
    if (roomId === 'global') return { ok: true, type: 'global', mod: false };
    const r = await pool.query(
        'SELECT r.type, r.creator_id, rm.role FROM rooms r JOIN room_members rm ON rm.room_id = r.id AND rm.user_id = $2 WHERE r.id = $1',
        [roomId, userId]
    );
    if (!r.rows.length) return { ok: false };
    const row = r.rows[0];
    return { ok: true, type: row.type, mod: row.creator_id === userId || row.role === 'admin' || row.role === 'owner' };
}
async function reactionsFor(messageIds) {
    const out = {};
    if (!messageIds.length) return out;
    const r = await pool.query(
        'SELECT mr.message_id, mr.emoji, u.username FROM message_reactions mr JOIN users u ON u.id = mr.user_id WHERE mr.message_id = ANY($1) ORDER BY mr.created_at ASC',
        [messageIds]
    );
    for (const row of r.rows) {
        const m = (out[row.message_id] = out[row.message_id] || {});
        (m[row.emoji] = m[row.emoji] || []).push(row.username);
    }
    return out;
}

// ===== Шифрование сообщений в базе (AES-256-GCM, ключ из переменной окружения MESSAGE_KEY) =====
const MESSAGE_KEY = process.env.MESSAGE_KEY ? crypto.createHash('sha256').update(String(process.env.MESSAGE_KEY)).digest() : null;
if (!MESSAGE_KEY) console.warn('ВНИМАНИЕ: MESSAGE_KEY не задан, сообщения хранятся в базе без шифрования!');
const ENC_PREFIX = 'enc1:';
function encText(roomId, text) {
    if (!MESSAGE_KEY || typeof text !== 'string' || text.startsWith('data:') || text.startsWith('e2e2:')) return text;
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', MESSAGE_KEY, iv);
    c.setAAD(Buffer.from(String(roomId)));
    const ct = Buffer.concat([c.update(text, 'utf8'), c.final()]);
    return ENC_PREFIX + Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
function decText(roomId, text) {
    if (typeof text !== 'string' || !text.startsWith(ENC_PREFIX)) return text;
    if (!MESSAGE_KEY) return '🔒 Не удалось расшифровать';
    try {
        const raw = Buffer.from(text.slice(ENC_PREFIX.length), 'base64');
        const d = crypto.createDecipheriv('aes-256-gcm', MESSAGE_KEY, raw.subarray(0, 12));
        d.setAAD(Buffer.from(String(roomId)));
        d.setAuthTag(raw.subarray(12, 28));
        return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8');
    } catch (e) { return '🔒 Не удалось расшифровать'; }
}
// Разово удалить старые сообщения прежнего сквозного шифрования (их больше нельзя расшифровать без пароля).
// Запустить с PURGE_LEGACY=1, дождаться записи в логе и убрать переменную. Действие необратимо.
async function purgeLegacyMessages() {
    const r = await pool.query("DELETE FROM messages WHERE text LIKE 'e2e2:%'");
    console.log('Удалено старых сообщений:', r.rowCount);
}
// Разово зашифровать уже сохранённые сообщения: запустить с переменной ENCRYPT_EXISTING=1, затем убрать её
async function encryptExistingMessages() {
    if (!MESSAGE_KEY) return;
    let lastId = 0, total = 0;
    for (;;) {
        const r = await pool.query("SELECT id, room_id, text FROM messages WHERE id > $1 AND text NOT LIKE 'enc1:%' AND text NOT LIKE 'e2e2:%' AND text NOT LIKE 'data:%' ORDER BY id LIMIT 300", [lastId]);
        if (!r.rows.length) break;
        for (const m of r.rows) {
            await pool.query('UPDATE messages SET text = $1 WHERE id = $2', [encText(m.room_id, m.text), m.id]);
            lastId = m.id; total++;
        }
    }
    console.log('Зашифровано старых сообщений:', total);
}

// ===== Вход через Google =====
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '848406632911-lqlg0dgrljmqdv08jp9dpq9t7p3k01ev.apps.googleusercontent.com';
const https = require('https');
const sha256 = (x) => crypto.createHash('sha256').update(String(x)).digest('hex');

// Проверка Google ID-токена через официальный tokeninfo (без внешних библиотек)
function verifyGoogleToken(credential) {
    return new Promise((resolve) => {
        if (typeof credential !== 'string' || credential.length < 20 || credential.length > 4096) return resolve(null);
        const req = https.get('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(credential), (res) => {
            let body = '';
            res.on('data', (d) => { body += d; if (body.length > 20000) req.destroy(); });
            res.on('end', () => {
                try {
                    const j = JSON.parse(body);
                    const okIss = j.iss === 'accounts.google.com' || j.iss === 'https://accounts.google.com';
                    const verified = j.email_verified === true || j.email_verified === 'true';
                    if (res.statusCode !== 200 || j.aud !== GOOGLE_CLIENT_ID || !okIss || !verified || !j.sub || Number(j.exp) * 1000 < Date.now()) return resolve(null);
                    resolve({ sub: String(j.sub), email: String(j.email || '') });
                } catch (e) { resolve(null); }
            });
        });
        req.setTimeout(8000, () => req.destroy());
        req.on('error', () => resolve(null));
    });
}

// Завершение входа без пароля (Google / сохранённый токен)
// Список сессий пользователя для его клиента (ключ — хэш токена, сам токен не отдаётся)
async function sendSessions(sock) {
    const r = await pool.query(
        "SELECT token_hash, user_agent, created_at, last_used_at FROM login_tokens WHERE user_id = $1 AND created_at > NOW() - INTERVAL '90 days' ORDER BY COALESCE(last_used_at, created_at) DESC LIMIT 50",
        [sock.userId]);
    sock.emit('sessions list', r.rows.map((x) => ({
        key: x.token_hash,
        ua: (x.user_agent || '').slice(0, 300),
        created: x.created_at,
        last: x.last_used_at || x.created_at,
        current: x.token_hash === sock.tokenHash
    })));
}
// Завершает подключённые сокеты пользователя, у которых токен подходит под условие match
function kickSessions(userId, match) {
    for (const [, s] of io.of('/').sockets) {
        if (s.userId === userId && s.tokenHash && match(s.tokenHash)) {
            s.emit('session revoked');
            setTimeout(() => s.disconnect(true), 300);
        }
    }
}
async function completeLogin(socket, user, extra) {
    if (user.banned_at) { socket.emit('auth error', 'Аккаунт заблокирован администрацией.'); return; }
    socket.userId = user.id;
    socket.username = user.username;
    socket.color = user.color;
    socket.status_emoji = user.status_emoji || '';
    socket.avatar = user.avatar || '';
    socket.banner = user.banner || '';
    socket.bio = user.username.toLowerCase() === 'twixxer' ? 'Создатель TwixxerChat' : (user.bio || '');
    socket.join(`user-${socket.userId}`);
    announcePresence(socket.userId, true);
    deliverPendingCalls(socket.userId);
    // Сессия: при обычном входе создаём новую, при входе по сохранённому токену обновляем её
    const sessionOpts = Object.assign({}, extra || {});
    delete sessionOpts.password;
    delete sessionOpts.existingToken;
    const ua = String((socket.handshake && socket.handshake.headers && socket.handshake.headers['user-agent']) || '').slice(0, 300);
    try {
        if (extra && (extra.existingToken || extra.loginToken)) {
            socket.tokenHash = sha256(extra.existingToken || extra.loginToken);
            await pool.query('UPDATE login_tokens SET user_agent = $2, last_used_at = NOW() WHERE token_hash = $1', [socket.tokenHash, ua]);
        } else {
            const raw = crypto.randomBytes(32).toString('hex');
            socket.tokenHash = sha256(raw);
            await pool.query('INSERT INTO login_tokens (token_hash, user_id, user_agent, last_used_at) VALUES ($1, $2, $3, NOW())', [socket.tokenHash, user.id, ua]);
            sessionOpts.loginToken = raw;
        }
    } catch (e) { console.error('session:', e.message); }
    socket.emit('auth success', Object.assign({
        id: user.id, username: user.username, color: user.color,
        status_emoji: socket.status_emoji, avatar: socket.avatar, banner: socket.banner, bio: socket.bio,
        theme_base: user.theme_base || 'dark', theme_preset: user.theme_preset || 'default', theme_custom: user.theme_custom || '',
        googleEmail: user.google_email || '', email: user.email || '', twofa: !!user.twofa_email, privacy: privacyOf(user), isAdmin: isAdminName(user.username)
    }, sessionOpts));
}

// ===== Регистрация по почте: отправка писем и защита от массового создания аккаунтов =====
const MAIL_FROM = process.env.MAIL_FROM || '';
const BREVO_API_KEY = process.env.BREVO_API_KEY || '';
const DISPOSABLE_DOMAINS = new Set([
    'mailinator.com', 'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org', 'sharklasers.com', '10minutemail.com', '10minutemail.net',
    'tempmail.com', 'temp-mail.org', 'temp-mail.io', 'tempmail.net', 'tempr.email', 'yopmail.com', 'yopmail.net', 'trashmail.com', 'trashmail.net',
    'getnada.com', 'nada.email', 'dispostable.com', 'maildrop.cc', 'throwawaymail.com', 'fakeinbox.com', 'mohmal.com', 'tempail.com',
    'emailondeck.com', 'moakt.com', 'tmpmail.org', 'mintemail.com', 'spamgourmet.com', 'burnermail.io', 'discard.email', '1secmail.com',
    '1secmail.net', '1secmail.org', 'mailnesia.com', 'mytemp.email', 'tempinbox.com', 'inboxkitten.com', 'mail.tm', 'emailfake.com', 'fakemail.net'
]);
const regIpLog = new Map();

function normalizeEmail(raw) {
    const e = String(raw || '').trim().toLowerCase();
    if (e.length > 120 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e)) return null;
    let [local, domain] = e.split('@');
    if (domain === 'googlemail.com') domain = 'gmail.com';
    local = local.split('+')[0];
    if (domain === 'gmail.com') local = local.replace(/\./g, '');
    if (!local) return null;
    return { email: e, norm: local + '@' + domain, domain };
}

function sendMail(to, subject, text, html) {
    return new Promise((resolve, reject) => {
        if (!BREVO_API_KEY || !MAIL_FROM) return reject(new Error('mail not configured'));
        const body = JSON.stringify({ sender: { name: 'TwixxerChat', email: MAIL_FROM }, to: [{ email: to }], subject, textContent: text, htmlContent: html });
        const req = https.request({
            hostname: 'api.brevo.com', path: '/v3/smtp/email', method: 'POST',
            headers: { 'api-key': BREVO_API_KEY, 'content-type': 'application/json', 'accept': 'application/json', 'content-length': Buffer.byteLength(body) }
        }, (res) => {
            let b = '';
            res.on('data', (d) => { b += d; });
            res.on('end', () => (res.statusCode >= 200 && res.statusCode < 300) ? resolve() : reject(new Error('brevo ' + res.statusCode + ' ' + b.slice(0, 200))));
        });
        req.setTimeout(10000, () => req.destroy(new Error('timeout')));
        req.on('error', reject);
        req.write(body);
        req.end();
    });
}

// ===== Двухфакторная аутентификация (TOTP), коды из писем, шифрование секретов =====
const GOOGLE_LOGIN_ENABLED = process.env.GOOGLE_LOGIN_ENABLED !== '0'; // отключить: GOOGLE_LOGIN_ENABLED=0
function maskEmail(email) {
    const [local, domain] = String(email || '').split('@');
    if (!domain) return '';
    return local.slice(0, 1) + '***@' + domain;
}
function makeCode() { return String(crypto.randomInt(0, 1000000)).padStart(6, '0'); }

async function bumpEmailAction(userId, kind) {
    const r = await pool.query('SELECT last_sent, sent_count, window_start FROM email_actions WHERE user_id = $1 AND kind = $2', [userId, kind]);
    let sentCount = 1, windowStart = new Date();
    const now = Date.now();
    if (r.rows.length) {
        const row = r.rows[0];
        const since = now - new Date(row.last_sent).getTime();
        if (since < 60000) return { ok: false, error: 'Подождите ' + Math.ceil((60000 - since) / 1000) + ' сек. перед повторной отправкой.' };
        if (now - new Date(row.window_start).getTime() < 3600000) {
            if (row.sent_count >= 5) return { ok: false, error: 'Слишком много кодов. Попробуйте через час.' };
            sentCount = row.sent_count + 1;
            windowStart = row.window_start;
        }
    }
    return { ok: true, sentCount, windowStart };
}
async function saveEmailAction(userId, kind, em, code, sentCount, windowStart) {
    await pool.query(
        `INSERT INTO email_actions (user_id, kind, email_norm, email, code_hash, attempts, expires_at, last_sent, sent_count, window_start)
         VALUES ($1, $2, $3, $4, $5, 0, NOW() + INTERVAL '10 minutes', NOW(), $6, $7)
         ON CONFLICT (user_id, kind) DO UPDATE SET email_norm = $3, email = $4, code_hash = $5, attempts = 0,
           expires_at = NOW() + INTERVAL '10 minutes', last_sent = NOW(), sent_count = $6, window_start = $7`,
        [userId, kind, em.norm, em.email, sha256(code), sentCount, windowStart]
    );
}
async function checkEmailAction(userId, kind, code) {
    const r = await pool.query('SELECT * FROM email_actions WHERE user_id = $1 AND kind = $2', [userId, kind]);
    if (!r.rows.length) return { status: 'none' };
    const row = r.rows[0];
    if (new Date(row.expires_at).getTime() < Date.now()) {
        await pool.query('DELETE FROM email_actions WHERE user_id = $1 AND kind = $2', [userId, kind]);
        return { status: 'expired' };
    }
    if (row.attempts >= 5) {
        await pool.query('DELETE FROM email_actions WHERE user_id = $1 AND kind = $2', [userId, kind]);
        return { status: 'locked' };
    }
    if (sha256(code) !== row.code_hash) {
        await pool.query('UPDATE email_actions SET attempts = attempts + 1 WHERE user_id = $1 AND kind = $2', [userId, kind]);
        return { status: 'wrong' };
    }
    return { status: 'ok', row };
}
const ACTION_ERRORS = {
    none: 'Код не найден. Запросите новый.',
    expired: 'Код истёк. Запросите новый.',
    locked: 'Слишком много неверных попыток. Запросите новый код.',
    wrong: 'Неверный код.'
};
function sendCodeMail(to, code, subject, lead) {
    const text = lead + '\n\nКод: ' + code + '\n\nОн действует 10 минут. Если это были не вы, просто проигнорируйте письмо.';
    const html = '<div style="font-family:Arial,sans-serif;max-width:420px;margin:0 auto;padding:24px;color:#222">'
        + '<h2 style="margin:0 0 12px">TwixxerChat</h2><p>' + lead + '</p>'
        + '<p style="font-size:34px;font-weight:700;letter-spacing:8px;margin:12px 0">' + code + '</p>'
        + '<p style="color:#666;font-size:13px">Код действует 10 минут. Если это были не вы, просто проигнорируйте письмо.</p></div>';
    return sendMail(to, subject, text, html);
}
const resetCooldown = new Map();

function deliverPendingCalls(userId) {
    for (const roomId in activeCalls) {
        const call = activeCalls[roomId];
        if (call.status === 'pending' && call.receiverId === userId) {
            pool.query('SELECT username, color, avatar FROM users WHERE id = $1', [call.callerId])
                .then(async result => {
                    if (result.rows.length === 0) return;
                    const caller = result.rows[0];
                    io.to(`user-${userId}`).emit('call-request', {
                        roomId,
                        callerId: call.callerId,
                        callerName: caller.username,
                        callerColor: caller.color,
                        callerAvatar: await avatarFor(userId, call.callerId, caller.avatar)
                    });
                })
                .catch(console.error);
        }
    }
}

// Извлечение ID второго пользователя в ЛС (из формата dm-X-Y)
function getTargetUserIdFromDmRoom(roomId, currentUserId) {
    if (!roomId || !roomId.startsWith('dm-')) return null;
    const parts = roomId.split('-');
    const id1 = parseInt(parts[1]);
    const id2 = parseInt(parts[2]);
    if (isNaN(id1) || isNaN(id2)) return null;
    if (currentUserId !== id1 && currentUserId !== id2) return null;
    return (currentUserId === id1) ? id2 : id1;
}

// Удалён ли собеседник в ЛС
async function dmPeerDeleted(roomId, userId) {
    const otherId = getTargetUserIdFromDmRoom(roomId, userId);
    if (!otherId) return false;
    const r = await pool.query('SELECT deleted_at, banned_at FROM users WHERE id = $1', [otherId]);
    return r.rows.length > 0 && !!(r.rows[0].deleted_at || r.rows[0].banned_at);
}

// Убрать сокеты пользователей из socket.io-комнаты (чтобы после удаления чата сообщения туда не шли)
function evictFromRoom(roomId, userIds) {
    for (const [, s] of io.of('/').sockets) {
        if (userIds.includes(s.userId)) s.leave(roomId);
    }
}

// Мягкое удаление аккаунта: строка users остаётся (ник занят, сообщения подписаны), все личные данные стираются.
// Публичный ключ остаётся, чтобы собеседники могли расшифровать старую переписку. Возвращает id собеседников по ЛС.
async function deleteAccountData(userId) {
    const dmRooms = await pool.query("SELECT room_id FROM room_members WHERE user_id = $1 AND room_id LIKE 'dm-%'", [userId]);
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query(
            `UPDATE users SET deleted_at = NOW(), password = 'scrypt:deleted:00', email = NULL, email_norm = NULL,
                google_sub = NULL, google_email = '', avatar = '', avatar_hash = NULL, banner = '', bio = '', status_emoji = '', key_backup = '',
                totp_secret = NULL, totp_enabled = FALSE, totp_recovery = NULL, twofa_email = FALSE
             WHERE id = $1`, [userId]);
        await client.query('DELETE FROM login_tokens WHERE user_id = $1', [userId]);
        await client.query('DELETE FROM email_actions WHERE user_id = $1', [userId]);
        await client.query('DELETE FROM friends WHERE user_id = $1 OR friend_id = $1', [userId]);
        await client.query("DELETE FROM room_members WHERE user_id = $1 AND room_id IN (SELECT id FROM rooms WHERE type <> 'dm')", [userId]);
        await client.query('COMMIT');
    } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        throw e;
    } finally {
        client.release();
    }
    return dmRooms.rows.map((r) => getTargetUserIdFromDmRoom(r.room_id, userId)).filter(Boolean);
}

// Универсальная запись пропущенных или отклоненных вызовов
async function logCallStatus(roomId, callerId, receiverId, text) {
    try {
        const callerQuery = await pool.query('SELECT username, color, avatar, status_emoji FROM users WHERE id = $1', [callerId]);
        if (callerQuery.rows.length === 0) return;
        const caller = callerQuery.rows[0];

        await pool.query(
            'INSERT INTO messages (room_id, sender_id, sender_name, sender_color, text) VALUES ($1, $2, $3, $4, $5)',
            [roomId, callerId, caller.username, caller.color, text]
        );

        io.to(`user-${callerId}`).emit('rooms list updated');
        io.to(`user-${receiverId}`).emit('rooms list updated');
        
        const displayUsername = caller.username + (caller.status_emoji ? ' ' + caller.status_emoji : '');
        const payload = {
            room_id: roomId,
            username: displayUsername,
            color: caller.color,
            text: text,
            time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }),
            avatar: caller.avatar || ''
        };
        
        io.to(`user-${callerId}`).emit('chat message', payload);
        io.to(`user-${receiverId}`).emit('chat message', Object.assign({}, payload, { avatar: await avatarFor(receiverId, callerId, payload.avatar) }));
    } catch (err) {
        console.error('Ошибка логирования статуса звонка:', err);
    }
}

// ICE-серверы для звонков: STUN + TURN (Metered). Нужны переменные окружения METERED_APP (имя приложения) и METERED_API_KEY.
let iceCache = { at: 0, servers: null };
async function getIceServers() {
    const base = [{ urls: 'stun:stun.l.google.com:19302' }];
    // Вариант 1: готовая пара username/credential из раздела TURN Server (секреты METERED_TURN_USERNAME / METERED_TURN_CREDENTIAL)
    const tu = process.env.METERED_TURN_USERNAME;
    const tc = process.env.METERED_TURN_CREDENTIAL;
    if (tu && tc) {
        // Не больше 4 адресов (Firefox замедляется от 5): UDP, TCP и TLS на 443 — для сетей и VPN, где UDP заблокирован
        return [
            { urls: 'stun:stun.relay.metered.ca:80' },
            ...['turn:global.relay.metered.ca:80', 'turn:global.relay.metered.ca:443', 'turns:global.relay.metered.ca:443?transport=tcp']
                .map(u => ({ urls: u, username: tu, credential: tc }))
        ];
    }
    // Вариант 2: API-ключ учётных данных (METERED_APP + METERED_API_KEY)
    const app = process.env.METERED_APP;
    const key = process.env.METERED_API_KEY;
    if (!app || !key) return base;
    if (iceCache.servers && Date.now() - iceCache.at < 10 * 60 * 1000) return iceCache.servers;
    try {
        const host = app.includes('.') ? app : `${app}.metered.live`;
        const r = await fetch(`https://${host}/api/v1/turn/credentials?apiKey=${encodeURIComponent(key)}`);
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const list = await r.json();
        iceCache = { at: Date.now(), servers: [...base, ...list] };
        return iceCache.servers;
    } catch (e) {
        console.error('TURN credentials error:', e.message);
        return base;
    }
}

io.on('connection', (socket) => {
    console.log('Пользователь подключился');
    io.emit('online count', io.engine.clientsCount);

    function isAuthSpamming() {
        const ip = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address || socket.conn.remoteAddress || '127.0.0.1';
        const now = Date.now();
        if (authRateLimiter[ip] && (now - authRateLimiter[ip] < 5000)) {
            socket.emit('auth error', 'Слишком много запросов! Подождите 5 секунд.');
            return true;
        }
        authRateLimiter[ip] = now;
        return false;
    }

    // ===== Привязка почты к аккаунту =====
    socket.on('email link request', async (d) => {
        if (!socket.userId || !d) return;
        const em = normalizeEmail(d.email);
        if (!em) return socket.emit('settings error', 'Введите корректную почту!');
        if (DISPOSABLE_DOMAINS.has(em.domain)) return socket.emit('settings error', 'Временные почтовые сервисы не поддерживаются.');
        try {
            const me = await pool.query('SELECT password FROM users WHERE id = $1', [socket.userId]);
            if (!me.rows.length || !verifyPassword(String(d.password || ''), me.rows[0].password)) return socket.emit('settings error', 'Неверный пароль.');
            const taken = await pool.query('SELECT 1 FROM users WHERE email_norm = $1 AND id <> $2', [em.norm, socket.userId]);
            if (taken.rows.length) return socket.emit('settings error', 'Эта почта уже используется в другом аккаунте.');
            const b = await bumpEmailAction(socket.userId, 'link');
            if (!b.ok) return socket.emit('settings error', b.error);
            const code = makeCode();
            await saveEmailAction(socket.userId, 'link', em, code, b.sentCount, b.windowStart);
            try {
                await sendCodeMail(em.email, code, 'Код для привязки почты TwixxerChat: ' + code, 'Вы привязываете эту почту к аккаунту ' + socket.username + '.');
            } catch (mailErr) {
                console.error('Ошибка отправки письма:', mailErr.message);
                await pool.query('DELETE FROM email_actions WHERE user_id = $1 AND kind = $2', [socket.userId, 'link']).catch(() => {});
                return socket.emit('settings error', mailErr.message === 'mail not configured' ? 'Отправка почты не настроена на сервере.' : 'Не удалось отправить письмо. Проверьте адрес.');
            }
            socket.emit('email code sent', { email: em.email });
        } catch (err) { console.error(err); socket.emit('settings error', 'Ошибка сервера.'); }
    });

    socket.on('email link confirm', async (d) => {
        if (!socket.userId || !d) return;
        const code = String(d.code || '').trim();
        if (!/^\d{6}$/.test(code)) return socket.emit('settings error', 'Введите 6 цифр из письма.');
        try {
            const c = await checkEmailAction(socket.userId, 'link', code);
            if (c.status !== 'ok') return socket.emit('settings error', ACTION_ERRORS[c.status]);
            await pool.query('UPDATE users SET email = $1, email_norm = $2 WHERE id = $3', [c.row.email, c.row.email_norm, socket.userId]);
            await pool.query('DELETE FROM email_actions WHERE user_id = $1 AND kind = $2', [socket.userId, 'link']);
            socket.emit('email status', { email: c.row.email });
            socket.emit('settings success', 'Почта привязана: ' + c.row.email);
        } catch (err) {
            console.error(err);
            socket.emit('settings error', err && err.code === '23505' ? 'Эта почта уже используется в другом аккаунте.' : 'Ошибка сервера.');
        }
    });

    // ===== Сброс пароля по почте =====
    socket.on('reset request', async (d) => {
        if (isAuthSpamming()) return;
        if (!pool) return socket.emit('auth error', 'База данных недоступна.');
        const em = normalizeEmail(d && d.email);
        if (!em) return socket.emit('auth error', 'Введите корректную почту!');
        const ip = String(socket.handshake.headers['x-forwarded-for'] || socket.handshake.address || '').split(',')[0].trim();
        const nowMs = Date.now();
        const logKey = 'reset:' + ip;
        const recent = (regIpLog.get(logKey) || []).filter((t) => nowMs - t < 3600000);
        if (recent.length >= 8) return socket.emit('auth error', 'Слишком много попыток с вашего адреса. Попробуйте позже.');
        const last = resetCooldown.get(em.norm) || 0;
        if (nowMs - last < 60000) return socket.emit('auth error', 'Подождите ' + Math.ceil((60000 - (nowMs - last)) / 1000) + ' сек. перед повторной отправкой.');
        resetCooldown.set(em.norm, nowMs);
        recent.push(nowMs);
        regIpLog.set(logKey, recent);
        try {
            const u = await pool.query('SELECT id, username FROM users WHERE email_norm = $1', [em.norm]);
            if (u.rows.length) {
                const user = u.rows[0];
                const b = await bumpEmailAction(user.id, 'reset');
                if (b.ok) {
                    const code = makeCode();
                    await saveEmailAction(user.id, 'reset', em, code, b.sentCount, b.windowStart);
                    try {
                        await sendCodeMail(em.email, code, 'Код для сброса пароля TwixxerChat: ' + code, 'Вы запросили сброс пароля для аккаунта ' + user.username + '.');
                    } catch (mailErr) { console.error('Ошибка отправки письма:', mailErr.message); }
                }
            }
            // Ответ одинаковый независимо от того, есть ли такая почта в базе
            socket.emit('reset code sent', { email: em.email, cooldown: 60 });
        } catch (err) { console.error(err); socket.emit('auth error', 'Ошибка сервера.'); }
    });

    socket.on('reset confirm', async (d) => {
        if (!pool) return socket.emit('auth error', 'База данных недоступна.');
        d = d || {};
        const em = normalizeEmail(d.email);
        const code = String(d.code || '').trim();
        const newPassword = String(d.newPassword || '');
        if (!em || !/^\d{6}$/.test(code)) return socket.emit('auth error', 'Введите 6 цифр из письма.');
        if (newPassword.length < 4 || newPassword.length > 200) return socket.emit('auth error', 'Новый пароль должен содержать минимум 4 символа!');
        try {
            const u = await pool.query('SELECT * FROM users WHERE email_norm = $1', [em.norm]);
            if (!u.rows.length) return socket.emit('auth error', 'Неверный код.');
            const user = u.rows[0];
            const c = await checkEmailAction(user.id, 'reset', code);
            if (c.status !== 'ok') return socket.emit('auth error', c.status === 'none' ? 'Неверный код.' : ACTION_ERRORS[c.status]);
            // Ключ шифрования ЛС привязан к старому паролю, поэтому после сброса он пересоздаётся: старые ЛС станут нечитаемыми
            await pool.query("UPDATE users SET password = $1, key_backup = '', public_key = '' WHERE id = $2", [hashPassword(newPassword), user.id]);
            await pool.query('DELETE FROM login_tokens WHERE user_id = $1', [user.id]);
            await pool.query('DELETE FROM email_actions WHERE user_id = $1 AND kind = $2', [user.id, 'reset']);
            socket.emit('reset done');
        } catch (err) { console.error(err); socket.emit('auth error', 'Ошибка сервера.'); }
    });

    // ===== Двухфакторная аутентификация по почте =====
    socket.on('twofa enable', async (d) => {
        if (!socket.userId || !d) return;
        try {
            const me = await pool.query('SELECT password, email_norm FROM users WHERE id = $1', [socket.userId]);
            if (!me.rows.length || !verifyPassword(String(d.password || ''), me.rows[0].password)) return socket.emit('settings error', 'Неверный пароль.');
            if (!me.rows[0].email_norm) return socket.emit('settings error', 'Сначала привяжите почту: код для входа будет приходить на неё.');
            await pool.query('UPDATE users SET twofa_email = TRUE WHERE id = $1', [socket.userId]);
            socket.emit('twofa status', { enabled: true });
            socket.emit('settings success', 'Двухфакторная аутентификация включена.');
        } catch (err) { console.error(err); socket.emit('settings error', 'Ошибка сервера.'); }
    });

    socket.on('twofa disable request', async (d) => {
        if (!socket.userId || !d) return;
        try {
            const me = await pool.query('SELECT password, email, twofa_email FROM users WHERE id = $1', [socket.userId]);
            if (!me.rows.length || !verifyPassword(String(d.password || ''), me.rows[0].password)) return socket.emit('settings error', 'Неверный пароль.');
            const row = me.rows[0];
            if (!row.twofa_email) return socket.emit('twofa status', { enabled: false });
            const em = normalizeEmail(row.email);
            if (!em) return socket.emit('settings error', 'Почта не привязана.');
            const b = await bumpEmailAction(socket.userId, 'twofa_off');
            if (!b.ok) return socket.emit('settings error', b.error);
            const code = makeCode();
            await saveEmailAction(socket.userId, 'twofa_off', em, code, b.sentCount, b.windowStart);
            try {
                await sendCodeMail(row.email, code, 'Код для отключения 2FA TwixxerChat: ' + code, 'Вы отключаете двухфакторную аутентификацию аккаунта ' + socket.username + '.');
            } catch (mailErr) {
                console.error('Ошибка отправки письма:', mailErr.message);
                await pool.query('DELETE FROM email_actions WHERE user_id = $1 AND kind = $2', [socket.userId, 'twofa_off']).catch(() => {});
                return socket.emit('settings error', 'Не удалось отправить письмо.');
            }
            socket.emit('twofa disable code sent', { email: maskEmail(row.email) });
        } catch (err) { console.error(err); socket.emit('settings error', 'Ошибка сервера.'); }
    });

    socket.on('twofa disable confirm', async (d) => {
        if (!socket.userId || !d) return;
        const code = String(d.code || '').trim();
        if (!/^\d{6}$/.test(code)) return socket.emit('settings error', 'Введите 6 цифр из письма.');
        try {
            const c = await checkEmailAction(socket.userId, 'twofa_off', code);
            if (c.status !== 'ok') return socket.emit('settings error', ACTION_ERRORS[c.status]);
            await pool.query('UPDATE users SET twofa_email = FALSE WHERE id = $1', [socket.userId]);
            await pool.query('DELETE FROM login_tokens WHERE user_id = $1', [socket.userId]);
            await pool.query('DELETE FROM email_actions WHERE user_id = $1 AND kind = $2', [socket.userId, 'twofa_off']);
            socket.emit('twofa status', { enabled: false });
            socket.emit('settings success', 'Двухфакторная аутентификация отключена.');
        } catch (err) { console.error(err); socket.emit('settings error', 'Ошибка сервера.'); }
    });

    // ===== Регистрация по почте с кодом подтверждения =====
    socket.on('register request', async (data) => {
        if (isAuthSpamming()) return;
        if (!pool) return socket.emit('auth error', 'База данных недоступна. Проверьте DATABASE_URL.');
        data = data || {};
        const username = String(data.username || '').trim();
        const password = String(data.password || '');
        const color = /^#[0-9a-fA-F]{6}$/.test(data.color || '') ? data.color : '#0084ff';
        if (username.length < 3 || username.length > 15) return socket.emit('auth error', 'Имя должно быть от 3 до 15 символов!');
        if (password.length < 4 || password.length > 200) return socket.emit('auth error', 'Пароль должен быть не менее 4 символов!');
        const em = normalizeEmail(data.email);
        if (!em) return socket.emit('auth error', 'Введите корректную почту!');
        if (DISPOSABLE_DOMAINS.has(em.domain)) return socket.emit('auth error', 'Временные почтовые сервисы не поддерживаются. Используйте обычную почту.');

        // не больше 8 запросов кода в час с одного адреса
        const ip = String(socket.handshake.headers['x-forwarded-for'] || socket.handshake.address || '').split(',')[0].trim();
        const nowMs = Date.now();
        const recent = (regIpLog.get(ip) || []).filter((t) => nowMs - t < 3600000);
        if (recent.length >= 8) return socket.emit('auth error', 'Слишком много попыток с вашего адреса. Попробуйте позже.');

        try {
            const u = await pool.query('SELECT 1 FROM users WHERE LOWER(username) = LOWER($1)', [username]);
            if (u.rows.length) return socket.emit('auth error', 'Этот никнейм уже занят!');
            const e = await pool.query('SELECT 1 FROM users WHERE email_norm = $1', [em.norm]);
            if (e.rows.length) return socket.emit('auth error', 'Эта почта уже используется.');

            let sentCount = 1;
            let windowStart = new Date();
            const pend = await pool.query('SELECT last_sent, sent_count, window_start FROM email_codes WHERE email_norm = $1', [em.norm]);
            if (pend.rows.length) {
                const r = pend.rows[0];
                const since = nowMs - new Date(r.last_sent).getTime();
                if (since < 60000) return socket.emit('auth error', 'Подождите ' + Math.ceil((60000 - since) / 1000) + ' сек. перед повторной отправкой.');
                if (nowMs - new Date(r.window_start).getTime() < 3600000) {
                    if (r.sent_count >= 5) return socket.emit('auth error', 'Слишком много кодов на эту почту. Попробуйте через час.');
                    sentCount = r.sent_count + 1;
                    windowStart = r.window_start;
                }
            }

            const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
            await pool.query(
                `INSERT INTO email_codes (email_norm, email, username, password_hash, color, code_hash, attempts, expires_at, last_sent, sent_count, window_start)
                 VALUES ($1, $2, $3, $4, $5, $6, 0, NOW() + INTERVAL '10 minutes', NOW(), $7, $8)
                 ON CONFLICT (email_norm) DO UPDATE SET email = $2, username = $3, password_hash = $4, color = $5, code_hash = $6, attempts = 0,
                   expires_at = NOW() + INTERVAL '10 minutes', last_sent = NOW(), sent_count = $7, window_start = $8`,
                [em.norm, em.email, username, hashPassword(password), color, sha256(code), sentCount, windowStart]
            );

            const text = 'Код подтверждения TwixxerChat: ' + code + '\n\nОн действует 10 минут. Если вы не регистрировались, просто проигнорируйте это письмо.';
            const html = '<div style="font-family:Arial,sans-serif;max-width:420px;margin:0 auto;padding:24px;color:#222">'
                + '<h2 style="margin:0 0 12px">TwixxerChat</h2><p>Ваш код подтверждения:</p>'
                + '<p style="font-size:34px;font-weight:700;letter-spacing:8px;margin:12px 0">' + code + '</p>'
                + '<p style="color:#666;font-size:13px">Код действует 10 минут. Если вы не регистрировались, просто проигнорируйте это письмо.</p></div>';
            try {
                await sendMail(em.email, 'Код подтверждения TwixxerChat: ' + code, text, html);
            } catch (mailErr) {
                console.error('Ошибка отправки письма:', mailErr.message);
                await pool.query('DELETE FROM email_codes WHERE email_norm = $1', [em.norm]).catch(() => {});
                return socket.emit('auth error', mailErr.message === 'mail not configured'
                    ? 'Отправка почты не настроена на сервере.'
                    : 'Не удалось отправить письмо. Проверьте адрес или попробуйте позже.');
            }
            recent.push(nowMs);
            regIpLog.set(ip, recent);
            socket.emit('register code sent', { email: em.email, cooldown: 60 });
        } catch (err) {
            console.error(err);
            socket.emit('auth error', 'Ошибка сервера при регистрации!');
        }
    });

    socket.on('register confirm', async (data) => {
        if (!pool) return socket.emit('auth error', 'База данных недоступна.');
        data = data || {};
        const em = normalizeEmail(data.email);
        const code = String(data.code || '').trim();
        const password = String(data.password || '');
        if (!em || !/^\d{6}$/.test(code)) return socket.emit('auth error', 'Введите 6 цифр из письма.');
        try {
            const r = await pool.query('SELECT * FROM email_codes WHERE email_norm = $1', [em.norm]);
            if (!r.rows.length) return socket.emit('auth error', 'Код не найден. Запросите новый.');
            const row = r.rows[0];
            if (new Date(row.expires_at).getTime() < Date.now()) {
                await pool.query('DELETE FROM email_codes WHERE email_norm = $1', [em.norm]);
                return socket.emit('auth error', 'Код истёк. Запросите новый.');
            }
            if (row.attempts >= 5) {
                await pool.query('DELETE FROM email_codes WHERE email_norm = $1', [em.norm]);
                return socket.emit('auth error', 'Слишком много неверных попыток. Запросите новый код.');
            }
            if (sha256(code) !== row.code_hash) {
                await pool.query('UPDATE email_codes SET attempts = attempts + 1 WHERE email_norm = $1', [em.norm]);
                return socket.emit('auth error', 'Неверный код.');
            }
            if (!verifyPassword(password, row.password_hash)) return socket.emit('auth error', 'Данные не совпадают. Начните регистрацию заново.');

            const taken = await pool.query('SELECT 1 FROM users WHERE LOWER(username) = LOWER($1) OR email_norm = $2', [row.username, em.norm]);
            if (taken.rows.length) {
                await pool.query('DELETE FROM email_codes WHERE email_norm = $1', [em.norm]);
                return socket.emit('auth error', 'Этот никнейм или почта уже заняты.');
            }
            const isTwixxer = row.username.toLowerCase() === 'twixxer';
            const ins = await pool.query(
                'INSERT INTO users (username, password, color, avatar, bio, theme_base, theme_preset, theme_custom, email, email_norm) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *',
                [row.username, row.password_hash, row.color || '#0084ff', '', isTwixxer ? 'Создатель TwixxerChat' : '', 'dark', 'default', '', row.email, em.norm]
            );
            await pool.query('DELETE FROM email_codes WHERE email_norm = $1', [em.norm]);
            completeLogin(socket, ins.rows[0], { password });
        } catch (err) {
            console.error(err);
            socket.emit('auth error', err && err.code === '23505' ? 'Этот никнейм или почта уже заняты.' : 'Ошибка сервера при регистрации!');
        }
    });

    // Прямая регистрация (без почты) отключена; для разработки можно включить ALLOW_OPEN_REGISTRATION=1
    socket.on('register', async (data) => {
        if (isAuthSpamming()) return;
        if (process.env.ALLOW_OPEN_REGISTRATION !== '1') return socket.emit('auth error', 'Регистрация теперь только по почте. Обновите страницу.');
        if (!pool) {
            return socket.emit('auth error', 'База данных недоступна. Проверьте DATABASE_URL.');
        }

        const username = (data.username || '').trim();
        const password = data.password || '';
        const color = data.color || '#0084ff';

        if (username.length < 3 || username.length > 15) {
            return socket.emit('auth error', 'Имя должно быть от 3 до 15 символов!');
        }

        if (password.length < 4) {
            return socket.emit('auth error', 'Пароль должен быть не менее 4 символов!');
        }

        try {
            const checkUser = await pool.query(
                'SELECT * FROM users WHERE LOWER(username) = LOWER($1)',
                [username]
            );

            if (checkUser.rows.length > 0) {
                return socket.emit('auth error', 'Этот никнейм уже занят!');
            }

            const isTwixxer = username.toLowerCase() === 'twixxer';
            const registrationBio = isTwixxer ? 'Создатель TwixxerChat' : '';

            const newUser = await pool.query(
                'INSERT INTO users (username, password, color, avatar, bio, theme_base, theme_preset, theme_custom) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id',
                [username, hashPassword(password), color, '', registrationBio, 'dark', 'default', '']
            );

            socket.userId = newUser.rows[0].id;
            socket.username = username;
            socket.color = color;
            socket.status_emoji = '';
            socket.avatar = '';
            socket.bio = registrationBio;

            socket.join(`user-${socket.userId}`);
    announcePresence(socket.userId, true);

            deliverPendingCalls(socket.userId);

            socket.emit('auth success', { 
                id: socket.userId, 
                username, 
                password, 
                color, 
                status_emoji: '', 
                avatar: '', 
                bio: registrationBio,
                theme_base: 'dark',
                theme_preset: 'default',
                theme_custom: ''
            });
        } catch (err) {
            console.error(err);
            socket.emit('auth error', 'Ошибка сервера при регистрации!');
        }
    });

    // Вход
    socket.on('login', async (data) => {
        if (!(data && data.totp) && isAuthSpamming()) return;
        if (!pool) {
            return socket.emit('auth error', 'База данных недоступна. Проверьте DATABASE_URL.');
        }

        const username = (data.username || '').trim();
        const password = data.password || '';

        try {
            const checkUser = await pool.query(
                'SELECT * FROM users WHERE LOWER(username) = LOWER($1)',
                [username]
            );

            if (checkUser.rows.length === 0 || checkUser.rows[0].deleted_at || !verifyPassword(password, checkUser.rows[0].password)) {
                return socket.emit('auth error', 'Неверное имя пользователя или пароль!');
            }

            const user = checkUser.rows[0];
            if (user.banned_at) return socket.emit('auth error', 'Аккаунт заблокирован администрацией.');
            let loginToken;
            if (user.twofa_email) {
                if (!data.totp) {
                    // Пароль верный: отправляем код на почту аккаунта
                    const em = normalizeEmail(user.email);
                    if (!em) return socket.emit('auth error', 'У аккаунта включена 2FA, но почта не привязана. Обратитесь к администратору.');
                    const b = await bumpEmailAction(user.id, 'login2fa');
                    if (!b.ok) {
                        socket.emit('totp required', { email: maskEmail(user.email), cooldown: 60 });
                        return socket.emit('auth error', b.error);
                    }
                    const code = makeCode();
                    await saveEmailAction(user.id, 'login2fa', em, code, b.sentCount, b.windowStart);
                    try {
                        await sendCodeMail(user.email, code, 'Код для входа в TwixxerChat: ' + code, 'Кто-то ввёл пароль от вашего аккаунта ' + user.username + '. Если это вы, введите код для входа.');
                    } catch (mailErr) {
                        console.error('Ошибка отправки письма:', mailErr.message);
                        await pool.query('DELETE FROM email_actions WHERE user_id = $1 AND kind = $2', [user.id, 'login2fa']).catch(() => {});
                        return socket.emit('auth error', 'Не удалось отправить код на почту. Попробуйте позже.');
                    }
                    return socket.emit('totp required', { email: maskEmail(user.email), cooldown: 60 });
                }
                const c = await checkEmailAction(user.id, 'login2fa', String(data.totp).trim());
                if (c.status !== 'ok') return socket.emit('auth error', ACTION_ERRORS[c.status]);
                await pool.query('DELETE FROM email_actions WHERE user_id = $1 AND kind = $2', [user.id, 'login2fa']);
                // запоминаем устройство, чтобы не просить код при каждом переподключении
                loginToken = crypto.randomBytes(32).toString('hex');
                await pool.query('INSERT INTO login_tokens (token_hash, user_id) VALUES ($1, $2)', [sha256(loginToken), user.id]);
            }
            const storedPassword = user.password || '';
            if (!storedPassword.startsWith('scrypt:')) {
                await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashPassword(password), user.id]);
            }
            socket.userId = user.id;
            socket.username = user.username;
            socket.color = user.color;
            socket.status_emoji = user.status_emoji || '';
            socket.avatar = user.avatar || '';
            socket.banner = user.banner || '';
            socket.bio = user.username.toLowerCase() === 'twixxer' ? 'Создатель TwixxerChat' : (user.bio || '');

            socket.join(`user-${socket.userId}`);
    announcePresence(socket.userId, true);

            deliverPendingCalls(socket.userId);

            socket.emit('auth success', { 
                id: user.id, 
                username: user.username, 
                password, 
                color: user.color, 
                status_emoji: socket.status_emoji,
                avatar: socket.avatar,
                banner: socket.banner,
                bio: socket.bio,
                theme_base: user.theme_base || 'dark',
                theme_preset: user.theme_preset || 'default',
                theme_custom: user.theme_custom || '',
                googleEmail: user.google_email || '',
                email: user.email || '',
                twofa: !!user.twofa_email, privacy: privacyOf(user), isAdmin: isAdminName(user.username),
                loginToken
            });
        } catch (err) {
            console.error(err);
            socket.emit('auth error', 'Ошибка сервера при входе!');
        }
    });

    // Изменение пароля
    socket.on('change password', async (data) => {
        if (!socket.userId) return;
        const { oldPassword, newPassword, newKeyBackup } = data;

        try {
            const userQuery = await pool.query('SELECT password FROM users WHERE id = $1', [socket.userId]);
            if (userQuery.rows.length === 0 || !verifyPassword(oldPassword, userQuery.rows[0].password)) {
                return socket.emit('settings error', 'Неверный старый пароль!');
            }

            if (newPassword.length < 4) {
                return socket.emit('settings error', 'Новый пароль должен быть не менее 4 символов!');
            }

            if (typeof newKeyBackup === 'string' && newKeyBackup.length > 0 && newKeyBackup.length < 4000) {
                await pool.query('UPDATE users SET password = $1, key_backup = $2 WHERE id = $3', [hashPassword(newPassword), newKeyBackup, socket.userId]);
                await pool.query('DELETE FROM login_tokens WHERE user_id = $1', [socket.userId]).catch(() => {});
            } else {
                await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashPassword(newPassword), socket.userId]);
            }
            socket.emit('settings success', 'Пароль успешно изменен!');
        } catch (err) {
            console.error(err);
            socket.emit('settings error', 'Ошибка при изменении пароля!');
        }
    });

    // ========================================================
    // E2E: ключи. Приватный ключ хранится ТОЛЬКО как бэкап, зашифрованный паролем на клиенте.
    // ========================================================
    function validKeyPayload(d) {
        return !!(d && d.publicKey && d.publicKey.kty === 'EC' && d.publicKey.crv === 'P-256' &&
            typeof d.publicKey.x === 'string' && typeof d.publicKey.y === 'string' &&
            typeof d.keyBackup === 'string' && d.keyBackup.length > 0 && d.keyBackup.length < 4000);
    }

    socket.on('get my keys', async () => {
        if (!socket.userId) return;
        try {
            const r = await pool.query('SELECT public_key, key_backup FROM users WHERE id = $1', [socket.userId]);
            const row = r.rows[0] || {};
            let publicKey = null;
            try { publicKey = row.public_key ? JSON.parse(row.public_key) : null; } catch (e) {}
            socket.emit('my keys', { publicKey, keyBackup: row.key_backup || '' });
        } catch (err) {
            console.error(err);
            socket.emit('my keys', null);
        }
    });

    // Первичная установка ключей: срабатывает только если бэкапа ещё нет (защита от перезаписи)
    socket.on('init keys', async (d) => {
        if (!socket.userId || !validKeyPayload(d)) return socket.emit('keys init result', { ok: false });
        try {
            const r = await pool.query(
                "UPDATE users SET public_key = $1, key_backup = $2 WHERE id = $3 AND (key_backup IS NULL OR key_backup = '')",
                [JSON.stringify(d.publicKey), d.keyBackup, socket.userId]
            );
            socket.emit('keys init result', { ok: r.rowCount === 1 });
        } catch (err) {
            console.error(err);
            socket.emit('keys init result', { ok: false });
        }
    });

    // Осознанный сброс ключей (старые личные сообщения станут нечитаемыми)
    socket.on('reset keys', async (d) => {
        if (!socket.userId || !validKeyPayload(d)) return socket.emit('keys reset result', { ok: false });
        try {
            await pool.query('UPDATE users SET public_key = $1, key_backup = $2 WHERE id = $3',
                [JSON.stringify(d.publicKey), d.keyBackup, socket.userId]);
            socket.emit('keys reset result', { ok: true });
        } catch (err) {
            console.error(err);
            socket.emit('keys reset result', { ok: false });
        }
    });

    // Публичный ключ собеседника (ключи без бэкапа от старого E2E игнорируются)
    socket.on('get public key', async (targetUserId) => {
        if (!socket.userId) return;
        const id = parseInt(targetUserId);
        if (!id) return;
        try {
            const r = await pool.query('SELECT public_key, key_backup, deleted_at FROM users WHERE id = $1', [id]);
            let publicKey = null;
            if (r.rows.length > 0 && (r.rows[0].key_backup || r.rows[0].deleted_at) && r.rows[0].public_key) {
                try { publicKey = JSON.parse(r.rows[0].public_key); } catch (e) {}
            }
            socket.emit('public key data', { userId: id, publicKey });
        } catch (err) {
            console.error(err);
        }
    });

    // Сохранение настроек профиля (Позволяет Twixxer сохранять свое кастомное БИО, плашка Создатель вынесена на фронтенд как независимая роль)
    socket.on('save profile settings', async (data) => {
        if (!socket.userId) return;
        const { color, statusEmoji, avatar, bio, banner } = data;

        const cleanAvatar = (avatar || '').trim();
        if (cleanAvatar.length > 700000) return socket.emit('settings error', 'Аватарка слишком большая.');
        let cleanBio = (bio || '').trim().substring(0, 100);
        // Баннер: пустая строка = убрать, data:image/... до ~2.5 МБ = поставить, всё остальное = не менять
        let cleanBanner = null;
        if (typeof banner === 'string') {
            const b = banner.trim();
            if (b === '') cleanBanner = '';
            else if (/^data:image\/(png|jpeg|jpg|webp|gif);base64,/.test(b) && b.length <= 2500000) cleanBanner = b;
        }

        try {
            const upd = await pool.query(
                'UPDATE users SET color = $1, status_emoji = $2, avatar = $3, bio = $4, banner = COALESCE($6, banner), avatar_hash = $7 WHERE id = $5 RETURNING banner',
                [color, statusEmoji, cleanAvatar, cleanBio, socket.userId, cleanBanner, cleanAvatar.startsWith('data:image/') ? sha256(cleanAvatar) : null]
            );
            socket.color = color;
            socket.status_emoji = statusEmoji;
            socket.avatar = cleanAvatar;
            socket.bio = cleanBio;
            socket.banner = (upd.rows[0] && upd.rows[0].banner) || '';

            socket.emit('settings success', 'Профиль успешно сохранен!');
            socket.emit('auth success', { 
                id: socket.userId, 
                username: socket.username, 
                color, 
                status_emoji: statusEmoji, 
                avatar: cleanAvatar, 
                banner: socket.banner,
                bio: cleanBio 
            });
            io.emit('rooms list updated'); 
        } catch (err) {
            console.error(err);
            socket.emit('settings error', 'Ошибка при сохранении профиля!');
        }
    });

    // Сохранение настроек темы в аккаунт
    socket.on('save theme settings', async (data) => {
        if (!socket.userId) return;
        const { baseMode, themePreset, themeCustom } = data;
        try {
            await pool.query(
                'UPDATE users SET theme_base = $1, theme_preset = $2, theme_custom = $3 WHERE id = $4',
                [baseMode, themePreset, JSON.stringify(themeCustom), socket.userId]
            );
        } catch (err) {
            console.error('Ошибка сохранения настроек темы в БД:', err);
        }
    });

    // ===== Google: вход, привязка, отвязка, проверка пароля =====
    socket.on('google login', async (d) => {
        if (!GOOGLE_LOGIN_ENABLED) return socket.emit('auth error', 'Вход через Google временно отключён.');
        const info = await verifyGoogleToken(d && d.credential);
        if (!info) return socket.emit('auth error', 'Не удалось проверить вход через Google. Попробуйте ещё раз.');
        try {
            const r = await pool.query('SELECT * FROM users WHERE google_sub = $1', [info.sub]);
            if (!r.rows.length) return socket.emit('auth error', 'Этот Google-аккаунт не привязан. Войдите по паролю и привяжите его: Настройки → Безопасность.');
            const user = r.rows[0];
            const raw = crypto.randomBytes(32).toString('hex');
            await pool.query('INSERT INTO login_tokens (token_hash, user_id) VALUES ($1, $2)', [sha256(raw), user.id]);
            completeLogin(socket, user, { loginToken: raw });
        } catch (err) {
            console.error(err);
            socket.emit('auth error', 'Ошибка входа через Google.');
        }
    });

    socket.on('token login', async (d) => {
        try {
            if (!d || typeof d.username !== 'string' || typeof d.loginToken !== 'string') return;
            const r = await pool.query(
                "SELECT u.* FROM login_tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = $1 AND u.deleted_at IS NULL AND LOWER(u.username) = LOWER($2) AND t.created_at > NOW() - INTERVAL '90 days'",
                [sha256(d.loginToken), d.username.trim()]
            );
            if (!r.rows.length) return socket.emit('auth error', 'Сессия истекла, войдите снова.');
            completeLogin(socket, r.rows[0], { existingToken: d.loginToken });
        } catch (err) {
            console.error(err);
            socket.emit('auth error', 'Ошибка входа.');
        }
    });

    socket.on('link google', async (d) => {
        if (!socket.userId) return;
        if (!GOOGLE_LOGIN_ENABLED) return socket.emit('settings error', 'Вход через Google временно отключён.');
        const info = await verifyGoogleToken(d && d.credential);
        if (!info) return socket.emit('settings error', 'Не удалось проверить аккаунт Google.');
        try {
            const other = await pool.query('SELECT id FROM users WHERE google_sub = $1 AND id <> $2', [info.sub, socket.userId]);
            if (other.rows.length) return socket.emit('settings error', 'Этот Google-аккаунт уже привязан к другому профилю.');
            await pool.query('UPDATE users SET google_sub = $1, google_email = $2 WHERE id = $3', [info.sub, info.email, socket.userId]);
            socket.emit('google status', { email: info.email });
            socket.emit('settings success', 'Google привязан: ' + info.email);
        } catch (err) {
            console.error(err);
            socket.emit('settings error', 'Не удалось привязать Google.');
        }
    });

    socket.on('unlink google', async () => {
        if (!socket.userId) return;
        try {
            await pool.query("UPDATE users SET google_sub = NULL, google_email = '' WHERE id = $1", [socket.userId]);
            await pool.query('DELETE FROM login_tokens WHERE user_id = $1', [socket.userId]);
            socket.emit('google status', { email: '' });
            socket.emit('settings success', 'Google отвязан.');
        } catch (err) {
            console.error(err);
            socket.emit('settings error', 'Не удалось отвязать Google.');
        }
    });

    // Проверка пароля (нужна, чтобы открыть шифрованные ЛС после входа через Google)
    socket.on('verify my password', async (pw, cb) => {
        if (!socket.userId || typeof cb !== 'function') return;
        const now = Date.now();
        if (socket.lastPwCheck && now - socket.lastPwCheck < 1000) return cb(false);
        socket.lastPwCheck = now;
        try {
            const r = await pool.query('SELECT password FROM users WHERE id = $1', [socket.userId]);
            cb(r.rows.length > 0 && verifyPassword(String(pw || ''), r.rows[0].password));
        } catch (e) { cb(false); }
    });

    // ===== Редактирование, удаление, реакции, закреп =====
    socket.on('edit message', async (d) => {
        if (!socket.userId || !d) return;
        const id = parseInt(d.id);
        const text = typeof d.text === 'string' ? d.text : '';
        if (!id || !text.trim() || text.startsWith('data:')) return;
        const isE2E = text.startsWith('e2e2:');
        if (isE2E) return socket.emit('system message', 'Обновите страницу: ваша версия приложения устарела.');
        if ((isE2E && text.length > 4000) || (!isE2E && text.length > 250)) return socket.emit('system message', 'Сообщение слишком длинное!');
        try {
            const acc = await roomAccess(socket.userId, d.roomId);
            if (!acc.ok) return;
            const cur = await pool.query('SELECT text FROM messages WHERE id = $1 AND room_id = $2 AND sender_id = $3', [id, d.roomId, socket.userId]);
            if (!cur.rows.length || String(cur.rows[0].text).startsWith('data:')) return;
            await pool.query('UPDATE messages SET text = $1, edited = TRUE WHERE id = $2', [encText(d.roomId, text), id]);
            io.to(d.roomId).emit('message edited', { roomId: d.roomId, id, text });
        } catch (err) { console.error(err); }
    });

    socket.on('delete message', async (d) => {
        if (!socket.userId || !d) return;
        const id = parseInt(d.id);
        if (!id) return;
        try {
            const acc = await roomAccess(socket.userId, d.roomId);
            if (!acc.ok) return;
            const m = await pool.query('SELECT sender_id FROM messages WHERE id = $1 AND room_id = $2', [id, d.roomId]);
            if (!m.rows.length) return;
            const own = m.rows[0].sender_id === socket.userId;
            if (!own && !(acc.mod && acc.type !== 'dm')) return;
            await pool.query('DELETE FROM messages WHERE id = $1', [id]);
            await pool.query('UPDATE rooms SET pinned_message_id = NULL WHERE id = $1 AND pinned_message_id = $2', [d.roomId, id]);
            io.to(d.roomId).emit('message deleted', { roomId: d.roomId, id });
        } catch (err) { console.error(err); }
    });

    socket.on('toggle reaction', async (d) => {
        if (!socket.userId || !d) return;
        const id = parseInt(d.id);
        if (!id || !ALLOWED_REACTIONS.includes(d.emoji)) return;
        try {
            const acc = await roomAccess(socket.userId, d.roomId);
            if (!acc.ok) return;
            const m = await pool.query('SELECT 1 FROM messages WHERE id = $1 AND room_id = $2', [id, d.roomId]);
            if (!m.rows.length) return;
            const del = await pool.query('DELETE FROM message_reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3', [id, socket.userId, d.emoji]);
            if (del.rowCount === 0) {
                await pool.query('INSERT INTO message_reactions (message_id, user_id, emoji) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [id, socket.userId, d.emoji]);
            }
            const map = await reactionsFor([id]);
            io.to(d.roomId).emit('reactions updated', { roomId: d.roomId, id, reactions: map[id] || {} });
        } catch (err) { console.error(err); }
    });

    socket.on('pin message', async (d) => {
        if (!socket.userId || !d) return;
        const id = d.id ? parseInt(d.id) : null;
        try {
            const acc = await roomAccess(socket.userId, d.roomId);
            if (!acc.ok) return;
            if (acc.type !== 'dm' && !acc.mod) return socket.emit('system message', 'Закреплять сообщения могут только администраторы.');
            if (id) {
                const m = await pool.query('SELECT 1 FROM messages WHERE id = $1 AND room_id = $2', [id, d.roomId]);
                if (!m.rows.length) return;
            }
            const u = await pool.query('UPDATE rooms SET pinned_message_id = $1 WHERE id = $2 RETURNING id', [id, d.roomId]);
            if (!u.rows.length) return socket.emit('system message', 'В этом чате нельзя закреплять сообщения.');
            io.to(d.roomId).emit('pinned updated', { roomId: d.roomId, id });
        } catch (err) { console.error(err); }
    });

    // Запрос профиля по юзернейму
    socket.on('get user profile', async (username) => {
        try {
            const userQuery = await pool.query(
                'SELECT id, username, color, status_emoji, avatar, banner, bio, privacy_avatar, (deleted_at IS NOT NULL OR banned_at IS NOT NULL) AS deleted, (banned_at IS NOT NULL) AS banned FROM users WHERE LOWER(username) = LOWER($1)',
                [username.trim()]
            );
            if (userQuery.rows.length > 0) {
                const user = userQuery.rows[0];
                if (!canSee(socket.userId, user.id, user.privacy_avatar, await friendIdSet(socket.userId))) user.avatar = '';
                user.avatar = avatarUrl(user.avatar);
                delete user.privacy_avatar;
                let mutualFriends = [];
                let mutualGroups = [];

                if (socket.userId && socket.userId !== user.id) {
                    // Поиск общих друзей
                    const friendsQuery = await pool.query(`
                        SELECT u.username 
                        FROM friends f1
                        JOIN friends f2 ON f1.friend_id = f2.friend_id
                        JOIN users u ON f1.friend_id = u.id
                        WHERE f1.user_id = $1 AND f2.user_id = $2
                          AND f1.status = 'accepted' AND f2.status = 'accepted'
                    `, [socket.userId, user.id]);
                    mutualFriends = friendsQuery.rows.map(r => r.username);

                    // Поиск общих групп и каналов (исключая ЛС)
                    const groupsQuery = await pool.query(`
                        SELECT r.name 
                        FROM rooms r
                        JOIN room_members rm1 ON r.id = rm1.room_id AND rm1.user_id = $1
                        JOIN room_members rm2 ON r.id = rm2.room_id AND rm2.user_id = $2
                        WHERE r.type != 'dm'
                    `, [socket.userId, user.id]);
                    mutualGroups = groupsQuery.rows.map(r => r.name);
                }

                socket.emit('user profile data', {
                    ...user,
                    mutualFriends,
                    mutualGroups
                });
            }
        } catch (err) {
            console.error(err);
        }
    });

    // Запрос списка чатов (С поддержкой статуса архивации)
    socket.on('get rooms', async () => {
        if (!socket.userId) return;
        try {
            const isExcludedUser = ['durov', 'twixxer'].includes((socket.username || '').toLowerCase());

            // Для чатов без отметки прочитанного считаем всё существующее прочитанным (базовая точка)
            await pool.query(`
                INSERT INTO room_reads (room_id, user_id, last_read_id)
                SELECT rm.room_id, rm.user_id, COALESCE((SELECT MAX(id) FROM messages WHERE room_id = rm.room_id), 0)
                FROM room_members rm
                WHERE rm.user_id = $1 AND rm.room_id <> 'global'
                  AND NOT EXISTS (SELECT 1 FROM room_reads x WHERE x.room_id = rm.room_id AND x.user_id = rm.user_id)
                ON CONFLICT DO NOTHING
            `, [socket.userId]).catch(() => {});

            const rooms = await pool.query(`
                SELECT r.*, rm.is_archived, rm.role as member_role, u.username as creator_name,
                       CASE WHEN r.id = 'global' THEN 0 ELSE (
                           SELECT COUNT(*)::int FROM messages mm
                           WHERE mm.room_id = r.id AND mm.sender_id <> $1
                             AND mm.id > GREATEST(COALESCE(rr.last_read_id, 0), COALESCE(rm.cleared_before, 0))
                       ) END as unread_count,
                       lm.text as last_msg_text,
                       lm.sender_id as last_msg_sender_id,
                       lm.created_at as last_msg_time_raw,
                       CASE
                           WHEN r.type = 'dm' THEN (
                               SELECT username || '||' || color || '||' || COALESCE(status_emoji, '') || '||' || COALESCE(avatar, '') || '||' || id || '||' || (deleted_at IS NOT NULL OR banned_at IS NOT NULL)::text || '||' || (banned_at IS NOT NULL)::text
                               FROM users
                               WHERE id = CASE
                                   WHEN split_part(r.id, '-', 2)::integer = $1 THEN split_part(r.id, '-', 3)::integer
                                   ELSE split_part(r.id, '-', 2)::integer
                               END
                           )
                           ELSE NULL
                       END as dm_other_user_info
                FROM rooms r
                LEFT JOIN users u ON r.creator_id = u.id
                JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = $1
                LEFT JOIN room_reads rr ON rr.room_id = r.id AND rr.user_id = $1
                LEFT JOIN LATERAL (
                    SELECT left(m2.text, 4000) AS text, m2.sender_id, m2.created_at
                    FROM messages m2
                    WHERE m2.room_id = r.id AND m2.id > COALESCE(rm.cleared_before, 0)
                    ORDER BY m2.created_at DESC, m2.id DESC
                    LIMIT 1
                ) lm ON TRUE
                WHERE COALESCE(rm.hidden, FALSE) = FALSE
            `, [socket.userId]);
            
            const processedRooms = [];
            for (let room of rooms.rows) {
                if (room.id === 'global' && isExcludedUser) {
                    continue; 
                }

                if (room.last_msg_time_raw) {
                    room.last_msg_time = new Date(room.last_msg_time_raw).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
                } else {
                    room.last_msg_time = '';
                }

                room.last_msg_text = decText(room.id, room.last_msg_text);
                if (room.last_msg_text) {
                    if (room.last_msg_text.startsWith('e2e2:')) {
                        room.last_msg_enc = room.last_msg_text; // клиент расшифрует для предпросмотра
                        room.last_msg_text = '🔒 Сообщение';
                    } else if (room.last_msg_text.startsWith('data:image/')) {
                        room.last_msg_text = '🖼️ Фотография';
                    } else if (room.last_msg_text.startsWith('data:audio/')) {
                        room.last_msg_text = '🎤 Голосовое';
                    }
                } else {
                    room.last_msg_text = room.type === 'channel' ? 'Канал' : 'Группа';
                }

                if (room.type === 'dm' && room.dm_other_user_info) {
                    const [otherName, otherColor, otherEmoji, otherAvatar, otherIdStr, otherDeletedStr, otherBannedStr] = room.dm_other_user_info.split('||');
                    const otherId = parseInt(otherIdStr);
                    const emoji = otherEmoji ? ' ' + otherEmoji : '';
                    
                    room.name = `${otherName}${emoji}`; 
                    room.color = otherColor;
                    room.avatar = otherAvatar;
                    room.peer_deleted = otherDeletedStr === 'true';
                    room.peer_banned = otherBannedStr === 'true';
                    room.is_online = room.peer_deleted ? false : isUserOnline(otherId);
                    room.other_user_id = otherId;
                }
                processedRooms.push(room);
            }

            const dmIds = processedRooms.filter(r => r.type === 'dm' && r.other_user_id).map(r => r.other_user_id);
            if (dmIds.length) {
                const ls = await pool.query('SELECT id, last_seen, privacy_avatar, privacy_seen FROM users WHERE id = ANY($1)', [dmIds]);
                const fset = await friendIdSet(socket.userId);
                const info = {};
                ls.rows.forEach(x => { info[x.id] = x; });
                processedRooms.forEach(r => {
                    if (!r.other_user_id) return;
                    const x = info[r.other_user_id] || {};
                    r.avatar = canSee(socket.userId, r.other_user_id, x.privacy_avatar, fset) ? avatarUrl(r.avatar) : '';
                    if (canSee(socket.userId, r.other_user_id, x.privacy_seen, fset)) {
                        r.last_seen = x.last_seen || null;
                    } else {
                        r.last_seen = null; r.seen_hidden = true;
                    }
                    if (fset.blockedBy.has(r.other_user_id)) { r.is_online = false; r.last_seen = null; r.seen_hidden = true; }
                });
            }

            processedRooms.sort((a, b) => {
                const timeA = a.last_msg_time_raw ? new Date(a.last_msg_time_raw).getTime() : 0;
                const timeB = b.last_msg_time_raw ? new Date(b.last_msg_time_raw).getTime() : 0;
                return timeB - timeA;
            });

            socket.emit('rooms list', processedRooms);
        } catch (err) {
            console.error(err);
        }
    });

    // Архивирование/Разархивирование комнаты
    socket.on('archive room', async (data) => {
        if (!socket.userId) return;
        const { roomId, archive } = data;
        try {
            await pool.query(
                'UPDATE room_members SET is_archived = $1 WHERE room_id = $2 AND user_id = $3',
                [archive, roomId, socket.userId]
            );
            socket.emit('rooms list updated');
        } catch (err) {
            console.error(err);
        }
    });

    // Пересылка статуса набора текста
    socket.on('typing', (data) => {
        if (!socket.userId) return;
        const { roomId, isTyping } = data;
        if (typeof roomId !== 'string') return;
        if (roomId.startsWith('dm-') && !getTargetUserIdFromDmRoom(roomId, socket.userId)) return;
        const targetUserId = getTargetUserIdFromDmRoom(roomId, socket.userId);
        
        if (targetUserId) {
            io.to(`user-${targetUserId}`).emit('typing', {
                roomId,
                userId: socket.userId,
                username: socket.username,
                isTyping
            });
        } else {
            socket.to(roomId).emit('typing', {
                roomId,
                userId: socket.userId,
                username: socket.username,
                isTyping
            });
        }
    });

    // Создание закрытой группы или канала
    socket.on('create room', async (data) => {
        if (!socket.userId) return;
        const name = (data.name || '').trim();
        const type = data.type; 
        
        if (name.length < 3 || name.length > 20) {
            return socket.emit('system message', 'Название должно быть от 3 до 20 символов!');
        }

        const roomId = `room-${Date.now()}`;

        try {
            await pool.query(
                'INSERT INTO rooms (id, name, type, creator_id) VALUES ($1, $2, $3, $4)',
                [roomId, name, type, socket.userId]
            );
            await pool.query(
                'INSERT INTO room_members (room_id, user_id, role) VALUES ($1, $2, $3)',
                [roomId, socket.userId, 'owner']
            );
            io.emit('rooms list updated');
            socket.emit('room created', { roomId, name, type, creatorId: socket.userId });
        } catch (err) {
            console.error(err);
            socket.emit('system message', 'Ошибка при создании чата!');
        }
    });

    // Настройки группы/канала (описание, аватар, роли)
    socket.on('update room settings', async (data) => {
        if (!socket.userId) return;
        const { roomId, name, description, avatar } = data;

        try {
            const roomQuery = await pool.query('SELECT * FROM rooms WHERE id = $1', [roomId]);
            if (roomQuery.rows.length === 0) return;

            const room = roomQuery.rows[0];
            if (room.type === 'dm') return;

            const memberQuery = await pool.query(
                'SELECT role FROM room_members WHERE room_id = $1 AND user_id = $2',
                [roomId, socket.userId]
            );
            const role = memberQuery.rows[0]?.role;
            if (room.creator_id !== socket.userId && role !== 'admin' && role !== 'owner') {
                return socket.emit('system message', 'Недостаточно прав для изменения настроек!');
            }

            const cleanName = (name || room.name).trim().substring(0, 50);
            const cleanDesc = (description || '').trim().substring(0, 200);
            const cleanAvatar = (avatar || '').trim();

            await pool.query(
                'UPDATE rooms SET name = $1, description = $2, avatar = $3 WHERE id = $4',
                [cleanName, cleanDesc, cleanAvatar, roomId]
            );

            io.emit('rooms list updated');
            io.to(roomId).emit('room settings updated', { roomId, name: cleanName, description: cleanDesc, avatar: cleanAvatar });
        } catch (err) {
            console.error(err);
            socket.emit('system message', 'Ошибка сохранения настроек чата!');
        }
    });

    socket.on('update member role', async (data) => {
        if (!socket.userId) return;
        const { roomId, targetUserId, role } = data;
        const allowedRoles = ['member', 'admin', 'moderator'];

        if (!allowedRoles.includes(role)) return;

        try {
            const roomQuery = await pool.query('SELECT creator_id FROM rooms WHERE id = $1', [roomId]);
            if (roomQuery.rows.length === 0 || roomQuery.rows[0].creator_id !== socket.userId) {
                return socket.emit('system message', 'Только создатель может менять роли!');
            }

            await pool.query(
                'UPDATE room_members SET role = $1 WHERE room_id = $2 AND user_id = $3',
                [role, roomId, targetUserId]
            );

            io.to(roomId).emit('member role updated', { roomId, targetUserId, role });
        } catch (err) {
            console.error(err);
        }
    });

    socket.on('get room members', async (roomId) => {
        if (!socket.userId) return;
        try {
            const mine = await pool.query('SELECT 1 FROM room_members WHERE room_id = $1 AND user_id = $2', [roomId, socket.userId]);
            if (mine.rows.length === 0) return;
            const members = await pool.query(`
                SELECT u.id, u.username, u.color, u.avatar, u.privacy_avatar, u.privacy_seen, rm.role
                FROM room_members rm
                JOIN users u ON rm.user_id = u.id
                WHERE rm.room_id = $1
                ORDER BY (rm.role = 'owner') DESC, (rm.role = 'admin') DESC, u.username ASC
            `, [roomId]);
            const mfs = await friendIdSet(socket.userId);
            const list = members.rows.map(({ privacy_avatar, privacy_seen, ...m }) => ({
                ...m,
                avatar: canSee(socket.userId, m.id, privacy_avatar, mfs) ? avatarUrl(m.avatar) : '',
                is_online: isUserOnline(m.id)
            }));
            socket.emit('room members list', { roomId, members: list });
        } catch (err) {
            console.error(err);
        }
    });

    // Приглашение друга в группу/канал (только из списка своих друзей)
    socket.on('invite friend', async (data) => {
        if (!socket.userId || !data) return;
        const roomId = data.roomId;
        const friendId = parseInt(data.friendId);
        if (!roomId || !friendId || friendId === socket.userId) return;

        try {
            const roomQ = await pool.query('SELECT id, type, creator_id FROM rooms WHERE id = $1', [roomId]);
            if (roomQ.rows.length === 0) return;
            const room = roomQ.rows[0];
            if (room.type === 'dm' || room.id === 'global') return;

            const me = await pool.query('SELECT role FROM room_members WHERE room_id = $1 AND user_id = $2', [roomId, socket.userId]);
            if (me.rows.length === 0) return socket.emit('system message', 'Вы не состоите в этом чате!');
            const role = me.rows[0].role;
            const isStaff = room.creator_id === socket.userId || role === 'admin' || role === 'owner';
            if (room.type === 'channel' && !isStaff) {
                return socket.emit('system message', 'В канал приглашать могут только админы!');
            }

            const fr = await pool.query(
                "SELECT 1 FROM friends WHERE status = 'accepted' AND ((user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1))",
                [socket.userId, friendId]
            );
            if (fr.rows.length === 0) return socket.emit('system message', 'Приглашать можно только друзей!');
            {
                const bs = await blockState(socket.userId, friendId);
                if (bs.byMe || bs.byThem) return socket.emit('system message', 'Этого пользователя нельзя пригласить.');
            }
            const tp = await pool.query('SELECT allow_invites FROM users WHERE id = $1', [friendId]);
            if (tp.rows.length && tp.rows[0].allow_invites === false) {
                return socket.emit('system message', 'Этот пользователь запретил добавлять себя в группы. Отправьте ему ссылку-приглашение.');
            }

            await pool.query('INSERT INTO room_members (room_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [roomId, friendId]);
            io.to(`user-${friendId}`).emit('rooms list updated');
            io.to(roomId).emit('room members changed', { roomId });
        } catch (err) {
            console.error(err);
            socket.emit('system message', 'Ошибка при приглашении друга!');
        }
    });

    // Создание ЛС
    socket.on('create dm', async (targetUsername) => {
        if (!socket.userId) return;
        const targetName = (targetUsername || '').trim();
        
        try {
            const targetUserQuery = await pool.query(
                'SELECT * FROM users WHERE LOWER(username) = LOWER($1)',
                [targetName]
            );

            if (targetUserQuery.rows.length === 0) {
                return socket.emit('system message', `Пользователь ${targetName} не найден!`);
            }

            const targetUser = targetUserQuery.rows[0];
            if (targetUser.id === socket.userId) {
                return socket.emit('system message', 'Нельзя создать приватный чат с самим собой!');
            }

            const minId = Math.min(socket.userId, targetUser.id);
            const maxId = Math.max(socket.userId, targetUser.id);
            const dmRoomId = `dm-${minId}-${maxId}`;

            if (targetUser.deleted_at || targetUser.banned_at) {
                const ex = await pool.query('SELECT 1 FROM room_members WHERE room_id = $1 AND user_id = $2', [dmRoomId, socket.userId]);
                if (!ex.rows.length) return socket.emit('system message', 'Этот аккаунт удалён, написать ему нельзя.');
            }

            await pool.query(`
                INSERT INTO rooms (id, name, type)
                VALUES ($1, $2, 'dm')
                ON CONFLICT (id) DO NOTHING
            `, [dmRoomId, `Чат с ${targetUser.username}`]);

            await pool.query(`
                INSERT INTO room_members (room_id, user_id)
                VALUES ($1, $2)
                ON CONFLICT (room_id, user_id) DO UPDATE SET hidden = FALSE
            `, [dmRoomId, socket.userId]);

            await pool.query(`
                INSERT INTO room_members (room_id, user_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
            `, [dmRoomId, targetUser.id]);

            io.to(`user-${socket.userId}`).to(`user-${targetUser.id}`).emit('rooms list updated');
            socket.emit('dm created', { roomId: dmRoomId, targetName: targetUser.username });
        } catch (err) {
            console.error(err);
        }
    });

    // Вход по инвайт-ссылке
    socket.on('join by invite', async (roomId) => {
        if (!socket.userId) return;

        try {
            if (roomId === 'global' && ['durov', 'twixxer'].includes((socket.username || '').toLowerCase())) {
                return socket.emit('system message', 'Доступ к глобальному чату для вас заблокирован администратором.');
            }

            const roomQuery = await pool.query('SELECT * FROM rooms WHERE id = $1', [roomId]);
            if (roomQuery.rows.length === 0) {
                return socket.emit('system message', 'Неверная ссылка-приглашение или комната не найдена!');
            }

            const room = roomQuery.rows[0];

            await pool.query(`
                INSERT INTO room_members (room_id, user_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
            `, [roomId, socket.userId]);

            socket.emit('rooms list updated');
            socket.emit('invite join success', { roomId, name: room.name, creatorId: room.creator_id, type: room.type });
        } catch (err) {
            console.error(err);
        }
    });

    // Удаление комнаты
    socket.on('delete room', async (roomId) => {
        if (!socket.userId) return;

        try {
            const roomQuery = await pool.query('SELECT * FROM rooms WHERE id = $1', [roomId]);
            if (roomQuery.rows.length > 0) {
                const room = roomQuery.rows[0];
                if (room.creator_id !== socket.userId) {
                    return socket.emit('system message', 'Только создатель может удалить этот чат!');
                }

                await pool.query('DELETE FROM messages WHERE room_id = $1', [roomId]);
                await pool.query('DELETE FROM rooms WHERE id = $1', [roomId]);

                io.emit('rooms list updated');
                io.to(roomId).emit('room deleted', roomId);
            }
        } catch (err) {
            console.error(err);
        }
    });

    // ===== Удаление чата: у себя (скрыть и очистить историю) или у обоих =====
    socket.on('delete chat', async (data) => {
        if (!socket.userId || !data) return;
        const roomId = String(data.roomId || '');
        if (!roomId.startsWith('dm-')) return;
        try {
            const acc = await roomAccess(socket.userId, roomId);
            if (!acc.ok || acc.type !== 'dm') return;
            const otherId = getTargetUserIdFromDmRoom(roomId, socket.userId);
            const ou = otherId ? await pool.query('SELECT deleted_at, banned_at FROM users WHERE id = $1', [otherId]) : { rows: [] };
            const otherGone = !ou.rows.length || !!(ou.rows[0].deleted_at || ou.rows[0].banned_at);
            const forAll = !!data.forAll || otherGone; // чат с удалённым аккаунтом удаляется целиком

            const call = activeCalls[roomId];
            if (call) {
                clearTimeout(call.timeoutId);
                delete activeCalls[roomId];
                io.to(`user-${call.callerId}`).emit('call-hangup', { roomId });
                io.to(`user-${call.receiverId}`).emit('call-hangup', { roomId });
            }

            if (forAll) {
                await pool.query('DELETE FROM messages WHERE room_id = $1', [roomId]);
                await pool.query('DELETE FROM rooms WHERE id = $1', [roomId]);
                evictFromRoom(roomId, [socket.userId, otherId]);
                io.to(`user-${socket.userId}`).emit('chat deleted', { roomId, forAll: true });
                if (otherId && !otherGone) io.to(`user-${otherId}`).emit('chat deleted', { roomId, forAll: true, byOther: true });
            } else {
                const last = await pool.query('SELECT COALESCE(MAX(id), 0) AS m FROM messages WHERE room_id = $1', [roomId]);
                const lastId = parseInt(last.rows[0].m) || 0;
                await pool.query('UPDATE room_members SET hidden = TRUE, cleared_before = $3 WHERE room_id = $1 AND user_id = $2', [roomId, socket.userId, lastId]);
                evictFromRoom(roomId, [socket.userId]);
                io.to(`user-${socket.userId}`).emit('chat deleted', { roomId, forAll: false });
            }
        } catch (err) {
            console.error(err);
            socket.emit('system message', 'Не удалось удалить чат.');
        }
    });

    // ===== Удаление аккаунта: пароль, а если привязана почта, то ещё и код из письма =====
    function delAcctThrottled() {
        const now = Date.now();
        if (socket.lastDelAcct && now - socket.lastDelAcct < 1500) return true;
        socket.lastDelAcct = now;
        return false;
    }
    async function finishAccountDeletion() {
        const uid = socket.userId;
        const peers = await deleteAccountData(uid);
        announcePresence(uid, false, new Date().toISOString());
        io.to(`user-${uid}`).emit('account deleted');
        peers.forEach((pid) => io.to(`user-${pid}`).emit('rooms list updated'));
        io.emit('friends list updated');
        // Даём клиенту время очистить сохранённый вход, иначе он попытается переподключиться со старыми данными
        setTimeout(() => {
            for (const [, s] of io.of('/').sockets) { if (s.userId === uid) s.disconnect(true); }
        }, 500);
    }

    socket.on('delete account request', async (d) => {
        if (!socket.userId || !d || delAcctThrottled()) return;
        try {
            const me = await pool.query('SELECT password, email FROM users WHERE id = $1 AND deleted_at IS NULL', [socket.userId]);
            if (!me.rows.length || !verifyPassword(String(d.password || ''), me.rows[0].password)) return socket.emit('settings error', 'Неверный пароль.');
            const em = normalizeEmail(me.rows[0].email);
            if (!em) return await finishAccountDeletion(); // почта не привязана: достаточно пароля
            const b = await bumpEmailAction(socket.userId, 'delacc');
            if (!b.ok) return socket.emit('settings error', b.error);
            const code = makeCode();
            await saveEmailAction(socket.userId, 'delacc', em, code, b.sentCount, b.windowStart);
            try {
                await sendCodeMail(me.rows[0].email, code, 'Код для удаления аккаунта TwixxerChat: ' + code, 'Вы удаляете аккаунт ' + socket.username + '. Это действие необратимо.');
            } catch (mailErr) {
                console.error('Ошибка отправки письма:', mailErr.message);
                await pool.query('DELETE FROM email_actions WHERE user_id = $1 AND kind = $2', [socket.userId, 'delacc']).catch(() => {});
                return socket.emit('settings error', 'Не удалось отправить письмо. Попробуйте позже.');
            }
            socket.emit('delete account code sent', { email: maskEmail(me.rows[0].email) });
        } catch (err) { console.error(err); socket.emit('settings error', 'Ошибка сервера.'); }
    });

    socket.on('delete account confirm', async (d) => {
        if (!socket.userId || !d || delAcctThrottled()) return;
        const code = String(d.code || '').trim();
        if (!/^\d{6}$/.test(code)) return socket.emit('settings error', 'Введите 6 цифр из письма.');
        try {
            const me = await pool.query('SELECT password FROM users WHERE id = $1 AND deleted_at IS NULL', [socket.userId]);
            if (!me.rows.length || !verifyPassword(String(d.password || ''), me.rows[0].password)) return socket.emit('settings error', 'Неверный пароль.');
            const c = await checkEmailAction(socket.userId, 'delacc', code);
            if (c.status !== 'ok') return socket.emit('settings error', ACTION_ERRORS[c.status]);
            await finishAccountDeletion();
        } catch (err) { console.error(err); socket.emit('settings error', 'Ошибка сервера.'); }
    });

    // ===== Сессии и устройства =====
    socket.on('get sessions', async () => {
        if (!socket.userId) return;
        try { await sendSessions(socket); } catch (e) { console.error(e); }
    });
    socket.on('revoke session', async (d) => {
        if (!socket.userId || !d) return;
        const key = String(d.key || '');
        if (!/^[0-9a-f]{64}$/.test(key) || key === socket.tokenHash) return;
        try {
            await pool.query('DELETE FROM login_tokens WHERE token_hash = $1 AND user_id = $2', [key, socket.userId]);
            kickSessions(socket.userId, (h) => h === key);
            await sendSessions(socket);
        } catch (e) { console.error(e); }
    });
    socket.on('revoke other sessions', async () => {
        if (!socket.userId || !socket.tokenHash) return;
        try {
            await pool.query('DELETE FROM login_tokens WHERE user_id = $1 AND token_hash <> $2', [socket.userId, socket.tokenHash]);
            kickSessions(socket.userId, (h) => h !== socket.tokenHash);
            await sendSessions(socket);
        } catch (e) { console.error(e); }
    });
    socket.on('logout session', async () => {
        if (!socket.userId || !socket.tokenHash) return;
        try {
            await pool.query('DELETE FROM login_tokens WHERE token_hash = $1 AND user_id = $2', [socket.tokenHash, socket.userId]);
            socket.tokenHash = null;
        } catch (e) { console.error(e); }
    });

    // ===== Чёрный список =====
    async function sendBlocks(sock) {
        const r = await pool.query('SELECT u.id, u.username, u.color, u.avatar FROM blocks b JOIN users u ON u.id = b.blocked_id WHERE b.user_id = $1 ORDER BY b.created_at DESC', [sock.userId]);
        sock.emit('blocks list', r.rows.map((x) => ({ id: x.id, username: x.username, color: x.color, avatar: avatarUrl(x.avatar) })));
    }
    socket.on('get blocks', async () => {
        if (!socket.userId) return;
        try { await sendBlocks(socket); } catch (e) { console.error(e); }
    });
    socket.on('block user', async (d) => {
        if (!socket.userId || !d) return;
        const id = parseInt(d.userId);
        if (!id || id === socket.userId) return;
        try {
            const u = await pool.query('SELECT id FROM users WHERE id = $1', [id]);
            if (!u.rows.length) return;
            await pool.query('INSERT INTO blocks (user_id, blocked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [socket.userId, id]);
            await pool.query('DELETE FROM friends WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)', [socket.userId, id]);
            const roomId = `dm-${Math.min(socket.userId, id)}-${Math.max(socket.userId, id)}`;
            const call = activeCalls[roomId];
            if (call) {
                clearTimeout(call.timeoutId);
                delete activeCalls[roomId];
                io.to(`user-${call.callerId}`).emit('call-hangup', { roomId });
                io.to(`user-${call.receiverId}`).emit('call-hangup', { roomId });
            }
            await sendBlocks(socket);
            io.to(`user-${socket.userId}`).to(`user-${id}`).emit('friends list updated');
            io.to(`user-${socket.userId}`).to(`user-${id}`).emit('rooms list updated');
        } catch (e) { console.error(e); socket.emit('system message', 'Не удалось заблокировать.'); }
    });
    socket.on('unblock user', async (d) => {
        if (!socket.userId || !d) return;
        const id = parseInt(d.userId);
        if (!id) return;
        try {
            await pool.query('DELETE FROM blocks WHERE user_id = $1 AND blocked_id = $2', [socket.userId, id]);
            await sendBlocks(socket);
            io.to(`user-${socket.userId}`).to(`user-${id}`).emit('rooms list updated');
        } catch (e) { console.error(e); }
    });

    // ===== Жалобы =====
    socket.on('report user', async (d) => {
        if (!socket.userId || !d) return;
        const reportedId = parseInt(d.userId);
        const reason = REPORT_REASONS[d.reason] ? d.reason : null;
        if (!reportedId || reportedId === socket.userId || !reason) return socket.emit('system message', 'Некорректная жалоба.');
        const comment = String(d.comment || '').trim().slice(0, 500);
        try {
            const ru = await pool.query('SELECT id, username FROM users WHERE id = $1', [reportedId]);
            if (!ru.rows.length) return socket.emit('system message', 'Пользователь не найден.');
            const hourly = await pool.query("SELECT COUNT(*)::int AS n FROM reports WHERE reporter_id = $1 AND created_at > NOW() - INTERVAL '1 hour'", [socket.userId]);
            if (hourly.rows[0].n >= 5) return socket.emit('system message', 'Слишком много жалоб за час. Попробуйте позже.');
            const dup = await pool.query("SELECT 1 FROM reports WHERE reporter_id = $1 AND reported_id = $2 AND status = 'open'", [socket.userId, reportedId]);
            if (dup.rows.length) return socket.emit('system message', 'Вы уже отправили жалобу на этого пользователя, мы её рассмотрим.');

            // Переписка прикладывается только по желанию жалующегося и только из чата, где он состоит
            let evidence = [];
            const roomId = typeof d.roomId === 'string' ? d.roomId : '';
            if (d.attach && roomId) {
                const acc = await roomAccess(socket.userId, roomId);
                let related = false;
                if (acc.ok) {
                    if (roomId.startsWith('dm-')) related = getTargetUserIdFromDmRoom(roomId, socket.userId) === reportedId;
                    else related = (await pool.query('SELECT 1 FROM room_members WHERE room_id = $1 AND user_id = $2', [roomId, reportedId])).rows.length > 0;
                }
                if (related) {
                    const m = await pool.query('SELECT sender_name, text, created_at FROM messages WHERE room_id = $1 ORDER BY id DESC LIMIT 10', [roomId]);
                    evidence = m.rows.reverse().map((x) => {
                        let t = decText(roomId, x.text);
                        if (t.startsWith('data:image/')) t = '[фото]';
                        else if (t.startsWith('data:audio/')) t = '[голосовое сообщение]';
                        else if (t.startsWith('e2e2:')) t = '[старое зашифрованное сообщение]';
                        return { n: x.sender_name, t: t.slice(0, 300), time: x.created_at };
                    });
                }
            }
            const ins = await pool.query('INSERT INTO reports (reporter_id, reported_id, room_id, reason, comment, evidence) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
                [socket.userId, reportedId, roomId || null, reason, comment, JSON.stringify(evidence)]);
            socket.emit('report sent');
            pushReportsToAdmins();
            mailAdminsAboutReport({ id: ins.rows[0].id, reporter: socket.username, reported: ru.rows[0].username, reason, comment, evidence });
        } catch (e) { console.error(e); socket.emit('system message', 'Не удалось отправить жалобу.'); }
    });
    socket.on('get reports', async () => {
        if (!socket.userId || !isAdminName(socket.username)) return;
        try { socket.emit('reports list', await getOpenReports()); } catch (e) { console.error(e); }
    });
    socket.on('handle report', async (d) => {
        if (!socket.userId || !isAdminName(socket.username) || !d) return;
        const id = parseInt(d.id);
        const action = d.action;
        if (!id || !['dismiss', 'resolve', 'ban'].includes(action)) return;
        try {
            const rep = await pool.query("SELECT reported_id FROM reports WHERE id = $1 AND status = 'open'", [id]);
            if (!rep.rows.length) return socket.emit('reports list', await getOpenReports());
            const reportedId = rep.rows[0].reported_id;
            if (action === 'ban') {
                const tu = await pool.query('SELECT username FROM users WHERE id = $1', [reportedId]);
                if (!tu.rows.length || isAdminName(tu.rows[0].username) || reportedId === socket.userId) return socket.emit('system message', 'Этот аккаунт нельзя заблокировать.');
                await pool.query('UPDATE users SET banned_at = NOW() WHERE id = $1', [reportedId]);
                await pool.query('DELETE FROM login_tokens WHERE user_id = $1', [reportedId]);
                await pool.query("UPDATE reports SET status = 'resolved', handled_by = $2, handled_at = NOW() WHERE reported_id = $1 AND status = 'open'", [reportedId, socket.userId]);
                for (const [, s] of io.of('/').sockets) { if (s.userId === reportedId) s.emit('auth error', 'Аккаунт заблокирован администрацией.'); }
                setTimeout(() => { for (const [, s] of io.of('/').sockets) { if (s.userId === reportedId) s.disconnect(true); } }, 400);
            } else {
                await pool.query('UPDATE reports SET status = $2, handled_by = $3, handled_at = NOW() WHERE id = $1', [id, action === 'dismiss' ? 'dismissed' : 'resolved', socket.userId]);
            }
            pushReportsToAdmins();
        } catch (e) { console.error(e); socket.emit('system message', 'Не удалось обработать жалобу.'); }
    });

    // ===== Приватность =====
    socket.on('save privacy', async (d) => {
        if (!socket.userId || !d) return;
        const ok = ['all', 'friends', 'none'];
        if (!ok.includes(d.avatar) || !ok.includes(d.seen) || typeof d.invites !== 'boolean') {
            return socket.emit('settings error', 'Некорректные настройки приватности.');
        }
        try {
            await pool.query('UPDATE users SET privacy_avatar = $1, privacy_seen = $2, allow_invites = $3 WHERE id = $4',
                [d.avatar, d.seen, d.invites, socket.userId]);
            for (const [, s] of io.of('/').sockets) { if (s.userId === socket.userId) s.privacy = null; }
            socket.emit('privacy status', { avatar: d.avatar, seen: d.seen, invites: d.invites });
            socket.emit('settings success', 'Настройки приватности сохранены.');
            io.emit('rooms list updated');
            announcePresence(socket.userId, true);
        } catch (err) { console.error(err); socket.emit('settings error', 'Не удалось сохранить настройки.'); }
    });

    // Добавление в друзья
    socket.on('add friend', async (targetUsername) => {
        if (!socket.userId) return;
        const name = (targetUsername || '').trim();

        try {
            const target = await pool.query('SELECT id, username, deleted_at, banned_at FROM users WHERE LOWER(username) = LOWER($1)', [name]);
            if (target.rows.length === 0) {
                return socket.emit('system message', `Пользователь ${name} не найден!`);
            }

            if (target.rows[0].deleted_at || target.rows[0].banned_at) return socket.emit('system message', 'Этот аккаунт недоступен.');
            const targetId = target.rows[0].id;
            {
                const bs = await blockState(socket.userId, targetId);
                if (bs.byMe || bs.byThem) return socket.emit('system message', bs.byMe ? 'Вы заблокировали этого пользователя.' : 'Этот пользователь недоступен для добавления.');
            }
            if (targetId === socket.userId) {
                return socket.emit('system message', 'Нельзя добавить в друзья самого себя!');
            }

            const check = await pool.query(
                'SELECT * FROM friends WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)',
                [socket.userId, targetId]
            );

            if (check.rows.length > 0) {
                const rel = check.rows[0];
                if (rel.status === 'accepted') {
                    return socket.emit('system message', `Вы уже дружите с ${target.rows[0].username}!`);
                }
                if (rel.user_id === socket.userId) {
                    return socket.emit('system message', `Запрос дружбы к ${target.rows[0].username} уже отправлен.`);
                }

                await pool.query(
                    "UPDATE friends SET status = 'accepted' WHERE user_id = $1 AND friend_id = $2",
                    [targetId, socket.userId]
                );
                await pool.query(
                    "INSERT INTO friends (user_id, friend_id, status) VALUES ($1, $2, 'accepted') ON CONFLICT DO NOTHING",
                    [socket.userId, targetId]
                );

                socket.emit('system message', `Вы приняли запрос дружбы от ${target.rows[0].username}!`);
                io.emit('friends list updated');
                return;
            }

            await pool.query(
                "INSERT INTO friends (user_id, friend_id, status) VALUES ($1, $2, 'pending')",
                [socket.userId, targetId]
            );
            socket.emit('system message', `Запрос дружбы отправлен пользователю ${target.rows[0].username}.`);
            io.emit('friends list updated');
        } catch (err) {
            console.error(err);
        }
    });

    // Список друзей
    socket.on('get friends', async () => {
        if (!socket.userId) return;
        try {
            const friends = await pool.query(`
                SELECT u.id, u.username, u.color, u.status_emoji, u.avatar, u.privacy_avatar 
                FROM friends f
                JOIN users u ON f.friend_id = u.id
                WHERE f.user_id = $1 AND f.status = 'accepted'
            `, [socket.userId]);

            const pending = await pool.query(`
                SELECT u.id, u.username, u.color, u.status_emoji, u.avatar, u.privacy_avatar 
                FROM friends f
                JOIN users u ON f.user_id = u.id
                WHERE f.friend_id = $1 AND f.status = 'pending'
            `, [socket.userId]);

            const hideAv = (strict) => ({ privacy_avatar, ...u }) => ((strict ? privacy_avatar !== 'all' : privacy_avatar === 'none') ? { ...u, avatar: '' } : { ...u, avatar: avatarUrl(u.avatar) });
            socket.emit('friends list', { friends: friends.rows.map(hideAv(false)), pending: pending.rows.map(hideAv(true)) });
        } catch (err) {
            console.error(err);
        }
    });

    // Вход в комнату
    socket.on('join room', async (roomId) => {
        if (!socket.userId) return;

        if (roomId === 'global' && ['durov', 'twixxer'].includes((socket.username || '').toLowerCase())) {
            return socket.emit('system message', 'Доступ к глобальному чату для вас заблокирован администратором.');
        }
        
        try {
            const acc = await roomAccess(socket.userId, roomId);
            if (!acc.ok) return socket.emit('system message', 'У вас нет доступа к этому чату.');
        } catch (err) { console.error(err); return; }

        const currentRooms = Array.from(socket.rooms);
        currentRooms.forEach(r => {
            if (r !== socket.id && !r.startsWith('user-')) socket.leave(r);
        });

        socket.join(roomId);

        try {
            const [history, rd, pin] = await Promise.all([
                pool.query(`
                    SELECT m.*, u.avatar as sender_avatar, u.privacy_avatar as sender_priv, u.status_emoji as sender_status_emoji
                    FROM messages m
                    LEFT JOIN users u ON m.sender_id = u.id
                    WHERE m.room_id = $1
                      AND m.id > COALESCE((SELECT rm.cleared_before FROM room_members rm WHERE rm.room_id = $1 AND rm.user_id = $2), 0)
                    ORDER BY m.created_at DESC, m.id DESC
                    LIMIT 100
                `, [roomId, socket.userId]),
                pool.query(
                    'SELECT COALESCE(MAX(last_read_id), 0) AS other_read FROM room_reads WHERE room_id = $1 AND user_id <> $2',
                    [roomId, socket.userId]
                ).catch(() => ({ rows: [{ other_read: 0 }] })),
                pool.query('SELECT pinned_message_id FROM rooms WHERE id = $1', [roomId]).catch(() => ({ rows: [] }))
            ]);
            history.rows.reverse();
            let hfs = null;
            for (const m of history.rows) {
                if (m.sender_avatar && m.sender_priv && m.sender_priv !== 'all' && m.sender_id !== socket.userId) {
                    if (!hfs) hfs = await friendIdSet(socket.userId);
                    if (!canSee(socket.userId, m.sender_id, m.sender_priv, hfs)) m.sender_avatar = '';
                }
                m.sender_avatar = avatarUrl(m.sender_avatar);
                delete m.sender_priv;
            }

            const formattedMessages = history.rows.map(msg => {
                const baseName = msg.sender_name;
                const emoji = msg.sender_status_emoji ? ' ' + msg.sender_status_emoji : '';
                return {
                    ...msg,
                    text: decText(roomId, msg.text),
                    sender_name: baseName + emoji
                };
            });

            const reactions = await reactionsFor(history.rows.map(r => r.id)).catch(() => ({}));
            socket.emit('chat history', { roomId, messages: formattedMessages, otherRead: parseInt(rd.rows[0].other_read) || 0, reactions, pinnedId: (pin.rows[0] && pin.rows[0].pinned_message_id) || null });
        } catch (err) {
            console.error(err);
        }
    });

    // Отметка «прочитано»: запоминаем последнее прочитанное сообщение пользователя в комнате
    socket.on('mark read', async (data) => {
        if (!socket.userId || !data || !data.roomId) return;
        try {
            const mem = await pool.query('SELECT 1 FROM room_members WHERE room_id = $1 AND user_id = $2', [data.roomId, socket.userId]);
            if (mem.rows.length === 0) return;
            const last = await pool.query('SELECT COALESCE(MAX(id), 0) AS m FROM messages WHERE room_id = $1', [data.roomId]);
            const lastId = parseInt(last.rows[0].m) || 0;
            await pool.query(
                `INSERT INTO room_reads (room_id, user_id, last_read_id) VALUES ($1, $2, $3)
                 ON CONFLICT (room_id, user_id) DO UPDATE SET last_read_id = GREATEST(room_reads.last_read_id, EXCLUDED.last_read_id)`,
                [data.roomId, socket.userId, lastId]
            );
            io.to(data.roomId).emit('read update', { roomId: data.roomId, userId: socket.userId, lastReadId: lastId });
        } catch (err) {
            console.error(err);
        }
    });

    // Отправка сообщений
    socket.on('chat message', async (data) => {
        if (!socket.userId || !socket.username) return; 

        const roomId = data.roomId;
        const msgText = data.text;
        
        if (!msgText || msgText.trim() === '') return;

        const lowerName = socket.username.toLowerCase();
        const now = Date.now();

        if (mutedUsers[lowerName] && now < mutedUsers[lowerName]) {
            const timeLeftMs = mutedUsers[lowerName] - now;
            const timeLeftMin = Math.ceil(timeLeftMs / 1000 / 60); 
            return socket.emit('system message', `Вы заблокированы за спам! Оставшееся время: ${timeLeftMin} мин.`);
        }

        const isMedia = msgText.startsWith('data:image/') || msgText.startsWith('data:audio/') || msgText.startsWith('data:application/') || msgText.startsWith('data:text/');
        const isE2E = msgText.startsWith('e2e2:');
        if (isE2E) return socket.emit('system message', 'Обновите страницу: ваша версия приложения устарела.');
        if (isE2E && msgText.length > 4000) {
            return socket.emit('system message', 'Сообщение слишком длинное!');
        }
        if (!isMedia && !isE2E && msgText.length > 250) {
            return socket.emit('system message', 'Сообщение слишком длинное (максимум 250 символов)!');
        }

        const cooldown = isMedia ? 3000 : 1000; 
        if (socket.lastMessageTime && (now - socket.lastMessageTime < cooldown)) {
            return socket.emit('system message', `Пожалуйста, подождите немного перед отправкой следующего сообщения.`);
        }

        socket.lastMessageTime = now;
        const currentTime = new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });

        try {
            const acc = await roomAccess(socket.userId, roomId);
            if (!acc.ok) return socket.emit('system message', 'У вас нет доступа к этому чату.');
            if (acc.type === 'dm' && await dmPeerDeleted(roomId, socket.userId)) {
                return socket.emit('system message', 'Этот аккаунт удалён, писать ему нельзя.');
            }
            if (acc.type === 'dm') {
                const peerId = getTargetUserIdFromDmRoom(roomId, socket.userId);
                const bs = peerId ? await blockState(socket.userId, peerId) : { byMe: false, byThem: false };
                if (bs.byMe) return socket.emit('system message', 'Вы заблокировали этого пользователя. Разблокируйте его, чтобы написать.');
                if (bs.byThem) return socket.emit('system message', 'Вы не можете писать этому пользователю.');
            }
            const senderAvatar = avatarUrl(socket.avatar || '');

            let replyTo = null;
            const rid = parseInt(data.replyTo);
            if (rid) {
                const rq = await pool.query('SELECT 1 FROM messages WHERE id = $1 AND room_id = $2', [rid, roomId]);
                if (rq.rows.length) replyTo = rid;
            }

            const ins = await pool.query(
                'INSERT INTO messages (room_id, sender_id, sender_name, sender_color, text, reply_to) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
                [roomId, socket.userId, socket.username, socket.color, encText(roomId, msgText), replyTo]
            );

            const displayUsername = socket.username + (socket.status_emoji ? ' ' + socket.status_emoji : '');

            const payload = {
                id: ins.rows[0].id,
                room_id: roomId,
                username: displayUsername,
                color: socket.color,
                text: msgText,
                time: currentTime,
                avatar: senderAvatar,
                reply_to: replyTo
            };
            const spriv = await ensurePrivacy(socket);
            const maskAv = !!senderAvatar && spriv.avatar !== 'all';
            const sfs = maskAv ? await friendIdSet(socket.userId) : null;
            const payloadFor = (viewerId) => (!maskAv || canSee(viewerId, socket.userId, spriv.avatar, sfs)) ? payload : Object.assign({}, payload, { avatar: '' });
            if (!maskAv) {
                io.to(roomId).emit('chat message', payload);
            } else {
                for (const sid of (io.sockets.adapter.rooms.get(roomId) || [])) {
                    const s = io.of('/').sockets.get(sid);
                    if (s) s.emit('chat message', payloadFor(s.userId));
                }
            }

            // Участники, которые сейчас не открыли этот чат, тоже получают событие (счётчик непрочитанных, звук, уведомление).
            // Раньше событие шло только тем, кто смотрит чат, поэтому непрочитанное не появлялось.
            if (roomId !== 'global') {
                // Если собеседник удалял чат «у себя», новое сообщение возвращает чат в его список (старая переписка остаётся скрытой)
                const un = await pool.query('UPDATE room_members SET hidden = FALSE WHERE room_id = $1 AND hidden = TRUE RETURNING user_id', [roomId]).catch(() => ({ rows: [] }));
                for (const row of un.rows) io.to(`user-${row.user_id}`).emit('rooms list updated');
                const inRoom = io.sockets.adapter.rooms.get(roomId) || new Set();
                const mem = await pool.query('SELECT user_id FROM room_members WHERE room_id = $1 AND user_id <> $2', [roomId, socket.userId]);
                for (const m of mem.rows) {
                    const sids = io.sockets.adapter.rooms.get(`user-${m.user_id}`);
                    if (!sids) continue;
                    for (const sid of sids) {
                        if (!inRoom.has(sid)) io.to(sid).emit('chat message', payloadFor(m.user_id));
                    }
                }
            }
        } catch (err) {
            console.error(err);
        }
    });

    // ========================================================
    // МНОГОПОТОЧНЫЕ ЗВОНКИ & СИГНАЛИНГ С ЛОГИРОВАНИЕМ В ЛС
    // ========================================================

    // Запрос звонка (Исходящий)
    socket.on('get ice servers', async (opts) => {
        if (!socket.userId) return;
        // FORCE_RELAY=1 (секрет Space): все звонки идут только через TURN — помогает при VPN и строгих сетях
        const turnConfigured = !!((process.env.METERED_TURN_USERNAME && process.env.METERED_TURN_CREDENTIAL) || (process.env.METERED_APP && process.env.METERED_API_KEY));
        // По умолчанию при настроенном TURN звонки идут только через него (надёжно при VPN и строгих NAT). FORCE_RELAY=0 — отключить.
        // opts.tlsOnly: клиент просит только TURN по TLS (turns:) — для браузера за прокси/VPN-расширением, где UDP не работает
        let iceList = await getIceServers();
        if (opts && opts.tlsOnly) iceList = iceList.filter(sv => [].concat(sv.urls).every(u => u.startsWith('turns:')));
        socket.emit('ice servers', iceList, { relay: turnConfigured && process.env.FORCE_RELAY !== '0' });
    });

    socket.on('call-request', async (data) => {
        if (!socket.userId) return;
        const roomId = data.roomId;
        const targetUserId = getTargetUserIdFromDmRoom(roomId, socket.userId);
        if (!targetUserId) return;

        if (await dmPeerDeleted(roomId, socket.userId)) return socket.emit('system message', 'Этот аккаунт удалён.');
        {
            const bs = await blockState(socket.userId, targetUserId);
            if (bs.byMe || bs.byThem) return socket.emit('system message', bs.byMe ? 'Вы заблокировали этого пользователя.' : 'Вы не можете позвонить этому пользователю.');
        }
        if (activeCalls[roomId]) {
            return socket.emit('system message', 'Звонок в этом чате уже идет!');
        }

        activeCalls[roomId] = {
            callerId: socket.userId,
            receiverId: targetUserId,
            status: 'pending',
            startTime: Date.now(),
            timeoutId: setTimeout(async () => {
                if (activeCalls[roomId] && activeCalls[roomId].status === 'pending') {
                    await logCallStatus(roomId, socket.userId, targetUserId, '📞 Пропущенный звонок');
                    io.to(`user-${socket.userId}`).emit('call-hangup', { roomId });
                    io.to(`user-${targetUserId}`).emit('call-hangup', { roomId });
                    delete activeCalls[roomId];
                }
            }, 30000)
        };

        await logCallStatus(roomId, socket.userId, targetUserId, '📞 Исходящий звонок');

        io.to(`user-${targetUserId}`).emit('call-request', {
            roomId: roomId,
            callerId: socket.userId,
            callerName: socket.username,
            callerColor: socket.color,
            callerAvatar: await avatarFor(targetUserId, socket.userId, socket.avatar)
        });
    });

    // Ответ на входящий звонок
    socket.on('call-response', async (data) => {
        if (!socket.userId) return;
        const { roomId, accepted } = data;
        const targetUserId = getTargetUserIdFromDmRoom(roomId, socket.userId);
        if (!targetUserId) return;

        const call = activeCalls[roomId];
        if (call) {
            if (accepted) {
                clearTimeout(call.timeoutId);
                call.status = 'active';
                call.startTime = Date.now(); 

                await logCallStatus(roomId, socket.userId, targetUserId, '📞 Звонок принят');
            } else {
                clearTimeout(call.timeoutId);
                await logCallStatus(roomId, call.callerId, call.receiverId, '📞 Звонок отклонен');
                delete activeCalls[roomId];
            }
        }

        io.to(`user-${targetUserId}`).emit('call-response', data);
    });

    socket.on('webrtc-offer', (data) => {
        if (!socket.userId) return;
        const targetUserId = getTargetUserIdFromDmRoom(data.roomId, socket.userId);
        if (targetUserId) {
            io.to(`user-${targetUserId}`).emit('webrtc-offer', data);
        }
    });

    socket.on('webrtc-answer', (data) => {
        if (!socket.userId) return;
        const targetUserId = getTargetUserIdFromDmRoom(data.roomId, socket.userId);
        if (targetUserId) {
            io.to(`user-${targetUserId}`).emit('webrtc-answer', data);
        }
    });

    socket.on('webrtc-ice', (data) => {
        if (!socket.userId) return;
        const targetUserId = getTargetUserIdFromDmRoom(data.roomId, socket.userId);
        if (targetUserId) {
            io.to(`user-${targetUserId}`).emit('webrtc-ice', data);
        }
    });

    socket.on('call-hangup', async (data) => {
        if (!socket.userId) return;
        const roomId = data.roomId;
        const targetUserId = getTargetUserIdFromDmRoom(roomId, socket.userId);
        if (!targetUserId) return;

        const call = activeCalls[roomId];
        if (call) {
            clearTimeout(call.timeoutId);
            if (call.status === 'active') {
                const durationMs = Date.now() - call.startTime;
                const mins = Math.floor(durationMs / 60000);
                const secs = Math.floor((durationMs % 60000) / 1000);
                const durationText = `📞 Звонок завершен. Длительность: ${mins} мин ${secs} сек`;
                
                await logCallStatus(roomId, socket.userId, targetUserId, durationText);
            } else {
                if (call.callerId === socket.userId) {
                    await logCallStatus(roomId, call.callerId, call.receiverId, '📞 Пропущенный звонок');
                }
            }
            delete activeCalls[roomId];
        }

        io.to(`user-${targetUserId}`).emit('call-hangup', data);
    });

    socket.on('disconnect', () => {
        io.emit('online count', io.engine.clientsCount);

        if (socket.userId && !isUserOnline(socket.userId)) {
            const seenAt = new Date();
            pool.query('UPDATE users SET last_seen = $1 WHERE id = $2', [seenAt, socket.userId]).catch(console.error);
            announcePresence(socket.userId, false, seenAt.toISOString());
        }

        if (socket.userId) {
            for (const roomId in activeCalls) {
                const call = activeCalls[roomId];
                if (call.callerId === socket.userId || call.receiverId === socket.userId) {
                    clearTimeout(call.timeoutId);
                    const targetUserId = (socket.userId === call.callerId) ? call.receiverId : call.callerId;

                    if (call.status === 'active') {
                        const durationMs = Date.now() - call.startTime;
                        const mins = Math.floor(durationMs / 60000);
                        const secs = Math.floor((durationMs % 60000) / 1000);
                        const durationText = `📞 Звонок оборвался. Длительность: ${mins} мин ${secs} сек`;
                        
                        logCallStatus(roomId, socket.userId, targetUserId, durationText).catch(console.error);
                    } else {
                        logCallStatus(roomId, call.callerId, call.receiverId, '📞 Пропущенный звонок').catch(console.error);
                    }

                    io.to(`user-${targetUserId}`).emit('call-hangup', { roomId });
                    delete activeCalls[roomId];
                }
            }
        }
    });
});

// Чистим устаревшие коды подтверждения
setInterval(() => {
    if (pool) pool.query("DELETE FROM email_codes WHERE expires_at < NOW() - INTERVAL '1 day'").catch(() => {});
    if (pool) pool.query("DELETE FROM email_actions WHERE expires_at < NOW() - INTERVAL '1 day'").catch(() => {});
}, 3600000);

const PORT = process.env.PORT || 7860;
server.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});