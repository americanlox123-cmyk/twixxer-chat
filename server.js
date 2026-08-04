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
const io = new Server(server, {
  cors: {
    origin: "*",
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
        await pool.query("ALTER TABLE users ALTER COLUMN password TYPE VARCHAR(255);").catch(() => {});
        await pool.query("ALTER TABLE users ALTER COLUMN status_emoji TYPE VARCHAR(30);").catch(() => {});

        await pool.query("CREATE INDEX IF NOT EXISTS idx_messages_room_id ON messages(room_id);").catch(() => {});
        await pool.query("CREATE INDEX IF NOT EXISTS idx_room_members_user_id ON room_members(user_id);").catch(() => {});
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
function deliverPendingCalls(userId) {
    for (const roomId in activeCalls) {
        const call = activeCalls[roomId];
        if (call.status === 'pending' && call.receiverId === userId) {
            pool.query('SELECT username, color, avatar FROM users WHERE id = $1', [call.callerId])
                .then(result => {
                    if (result.rows.length === 0) return;
                    const caller = result.rows[0];
                    io.to(`user-${userId}`).emit('call-request', {
                        roomId,
                        callerId: call.callerId,
                        callerName: caller.username,
                        callerColor: caller.color,
                        callerAvatar: caller.avatar || ''
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
    return (currentUserId === id1) ? id2 : id1;
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
        io.to(`user-${receiverId}`).emit('chat message', payload);
    } catch (err) {
        console.error('Ошибка логирования статуса звонка:', err);
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

    // Регистрация
    socket.on('register', async (data) => {
        if (isAuthSpamming()) return;
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
        if (isAuthSpamming()) return;
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

            if (checkUser.rows.length === 0 || !verifyPassword(password, checkUser.rows[0].password)) {
                return socket.emit('auth error', 'Неверное имя пользователя или пароль!');
            }

            const user = checkUser.rows[0];
            const storedPassword = user.password || '';
            if (!storedPassword.startsWith('scrypt:')) {
                await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashPassword(password), user.id]);
            }
            socket.userId = user.id;
            socket.username = user.username;
            socket.color = user.color;
            socket.status_emoji = user.status_emoji || '';
            socket.avatar = user.avatar || '';
            socket.bio = user.username.toLowerCase() === 'twixxer' ? 'Создатель TwixxerChat' : (user.bio || '');

            socket.join(`user-${socket.userId}`);

            deliverPendingCalls(socket.userId);

            socket.emit('auth success', { 
                id: user.id, 
                username: user.username, 
                password, 
                color: user.color, 
                status_emoji: socket.status_emoji,
                avatar: socket.avatar,
                bio: socket.bio,
                theme_base: user.theme_base || 'dark',
                theme_preset: user.theme_preset || 'default',
                theme_custom: user.theme_custom || ''
            });
        } catch (err) {
            console.error(err);
            socket.emit('auth error', 'Ошибка сервера при входе!');
        }
    });

    // Изменение пароля
    socket.on('change password', async (data) => {
        if (!socket.userId) return;
        const { oldPassword, newPassword } = data;

        try {
            const userQuery = await pool.query('SELECT password FROM users WHERE id = $1', [socket.userId]);
            if (userQuery.rows.length === 0 || !verifyPassword(oldPassword, userQuery.rows[0].password)) {
                return socket.emit('settings error', 'Неверный старый пароль!');
            }

            if (newPassword.length < 4) {
                return socket.emit('settings error', 'Новый пароль должен быть не менее 4 символов!');
            }

            await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashPassword(newPassword), socket.userId]);
            socket.emit('settings success', 'Пароль успешно изменен!');
        } catch (err) {
            console.error(err);
            socket.emit('settings error', 'Ошибка при изменении пароля!');
        }
    });

    // Сохранение публичного ключа E2E шифрования
    socket.on('save public key', async (publicKeyJwk) => {
        if (!socket.userId || !publicKeyJwk) return;
        try {
            await pool.query('UPDATE users SET public_key = $1 WHERE id = $2', [JSON.stringify(publicKeyJwk), socket.userId]);
        } catch (err) {
            console.error('Ошибка сохранения публичного ключа:', err);
        }
    });

    // Получение публичного ключа пользователя
    socket.on('get public key', async (targetUserId) => {
        if (!socket.userId) return;
        try {
            const result = await pool.query('SELECT id, username, public_key FROM users WHERE id = $1', [targetUserId]);
            if (result.rows.length > 0) {
                socket.emit('public key data', {
                    userId: result.rows[0].id,
                    username: result.rows[0].username,
                    publicKey: result.rows[0].public_key ? JSON.parse(result.rows[0].public_key) : null
                });
            }
        } catch (err) {
            console.error(err);
        }
    });

    // Сохранение настроек профиля (Позволяет Twixxer сохранять свое кастомное БИО, плашка Создатель вынесена на фронтенд как независимая роль)
    socket.on('save profile settings', async (data) => {
        if (!socket.userId) return;
        const { color, statusEmoji, avatar, bio } = data;

        const cleanAvatar = (avatar || '').trim();
        let cleanBio = (bio || '').trim().substring(0, 100);

        try {
            await pool.query(
                'UPDATE users SET color = $1, status_emoji = $2, avatar = $3, bio = $4 WHERE id = $5', 
                [color, statusEmoji, cleanAvatar, cleanBio, socket.userId]
            );
            socket.color = color;
            socket.status_emoji = statusEmoji;
            socket.avatar = cleanAvatar;
            socket.bio = cleanBio;
            
            socket.emit('settings success', 'Профиль успешно сохранен!');
            socket.emit('auth success', { 
                id: socket.userId, 
                username: socket.username, 
                color, 
                status_emoji: statusEmoji, 
                avatar: cleanAvatar, 
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

    // Запрос профиля по юзернейму
    socket.on('get user profile', async (username) => {
        try {
            const userQuery = await pool.query(
                'SELECT id, username, color, status_emoji, avatar, bio FROM users WHERE LOWER(username) = LOWER($1)',
                [username.trim()]
            );
            if (userQuery.rows.length > 0) {
                const user = userQuery.rows[0];
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

            const rooms = await pool.query(`
                SELECT r.*, rm.is_archived, rm.role as member_role, u.username as creator_name,
                       (SELECT text FROM messages WHERE room_id = r.id ORDER BY created_at DESC LIMIT 1) as last_msg_text,
                       (SELECT created_at FROM messages WHERE room_id = r.id ORDER BY created_at DESC LIMIT 1) as last_msg_time_raw,
                       CASE 
                           WHEN r.type = 'dm' THEN (
                               SELECT username || '||' || color || '||' || COALESCE(status_emoji, '') || '||' || COALESCE(avatar, '') || '||' || id
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
                JOIN room_members rm ON r.id = rm.room_id
                WHERE rm.user_id = $1
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

                if (room.last_msg_text) {
                    if (room.last_msg_text.startsWith('data:image/')) {
                        room.last_msg_text = '🖼️ Фотография';
                    } else if (room.last_msg_text.startsWith('data:audio/')) {
                        room.last_msg_text = '🎤 Голосовое';
                    }
                } else {
                    room.last_msg_text = room.type === 'channel' ? 'Канал' : 'Группа';
                }

                if (room.type === 'dm' && room.dm_other_user_info) {
                    const [otherName, otherColor, otherEmoji, otherAvatar, otherIdStr] = room.dm_other_user_info.split('||');
                    const otherId = parseInt(otherIdStr);
                    const emoji = otherEmoji ? ' ' + otherEmoji : '';
                    
                    room.name = `${otherName}${emoji}`; 
                    room.color = otherColor;
                    room.avatar = otherAvatar;
                    room.is_online = isUserOnline(otherId);
                }
                processedRooms.push(room);
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
            socket.emit('room settings updated', { roomId, name: cleanName, description: cleanDesc, avatar: cleanAvatar });
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
            const members = await pool.query(`
                SELECT u.id, u.username, u.color, u.avatar, rm.role
                FROM room_members rm
                JOIN users u ON rm.user_id = u.id
                WHERE rm.room_id = $1
            `, [roomId]);
            socket.emit('room members list', { roomId, members: members.rows });
        } catch (err) {
            console.error(err);
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

            await pool.query(`
                INSERT INTO rooms (id, name, type)
                VALUES ($1, $2, 'dm')
                ON CONFLICT (id) DO NOTHING
            `, [dmRoomId, `Чат с ${targetUser.username}`]);

            await pool.query(`
                INSERT INTO room_members (room_id, user_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
            `, [dmRoomId, socket.userId]);

            await pool.query(`
                INSERT INTO room_members (room_id, user_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
            `, [dmRoomId, targetUser.id]);

            io.emit('rooms list updated');
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

    // Добавление в друзья
    socket.on('add friend', async (targetUsername) => {
        if (!socket.userId) return;
        const name = (targetUsername || '').trim();

        try {
            const target = await pool.query('SELECT id, username FROM users WHERE LOWER(username) = LOWER($1)', [name]);
            if (target.rows.length === 0) {
                return socket.emit('system message', `Пользователь ${name} не найден!`);
            }

            const targetId = target.rows[0].id;
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
                SELECT u.id, u.username, u.color, u.status_emoji, u.avatar 
                FROM friends f
                JOIN users u ON f.friend_id = u.id
                WHERE f.user_id = $1 AND f.status = 'accepted'
            `, [socket.userId]);

            const pending = await pool.query(`
                SELECT u.id, u.username, u.color, u.status_emoji, u.avatar 
                FROM friends f
                JOIN users u ON f.user_id = u.id
                WHERE f.friend_id = $1 AND f.status = 'pending'
            `, [socket.userId]);

            socket.emit('friends list', { friends: friends.rows, pending: pending.rows });
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
        
        const currentRooms = Array.from(socket.rooms);
        currentRooms.forEach(r => {
            if (r !== socket.id && !r.startsWith('user-')) socket.leave(r);
        });

        socket.join(roomId);

        try {
            const history = await pool.query(`
                SELECT m.*, u.avatar as sender_avatar, u.status_emoji as sender_status_emoji 
                FROM messages m
                LEFT JOIN users u ON m.sender_id = u.id
                WHERE m.room_id = $1 
                ORDER BY m.created_at ASC 
                LIMIT 50
            `, [roomId]);

            const formattedMessages = history.rows.map(msg => {
                const baseName = msg.sender_name;
                const emoji = msg.sender_status_emoji ? ' ' + msg.sender_status_emoji : '';
                return {
                    ...msg,
                    sender_name: baseName + emoji
                };
            });

            socket.emit('chat history', { roomId, messages: formattedMessages });
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
        if (!isMedia && msgText.length > 250) {
            return socket.emit('system message', 'Сообщение слишком длинное (максимум 250 символов)!');
        }

        const cooldown = isMedia ? 3000 : 1000; 
        if (socket.lastMessageTime && (now - socket.lastMessageTime < cooldown)) {
            return socket.emit('system message', `Пожалуйста, подождите немного перед отправкой следующего сообщения.`);
        }

        socket.lastMessageTime = now;
        const currentTime = new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });

        try {
            const senderAvatar = socket.avatar || '';

            await pool.query(
                'INSERT INTO messages (room_id, sender_id, sender_name, sender_color, text) VALUES ($1, $2, $3, $4, $5)',
                [roomId, socket.userId, socket.username, socket.color, msgText]
            );

            const displayUsername = socket.username + (socket.status_emoji ? ' ' + socket.status_emoji : '');

            io.to(roomId).emit('chat message', {
                room_id: roomId,
                username: displayUsername,
                color: socket.color,
                text: msgText,
                time: currentTime,
                avatar: senderAvatar 
            });
        } catch (err) {
            console.error(err);
        }
    });

    // ========================================================
    // МНОГОПОТОЧНЫЕ ЗВОНКИ & СИГНАЛИНГ С ЛОГИРОВАНИЕМ В ЛС
    // ========================================================

    // Запрос звонка (Исходящий)
    socket.on('call-request', async (data) => {
        if (!socket.userId) return;
        const roomId = data.roomId;
        const targetUserId = getTargetUserIdFromDmRoom(roomId, socket.userId);
        if (!targetUserId) return;

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
            callerAvatar: socket.avatar
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

const PORT = process.env.PORT || 7860;
server.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});