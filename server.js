const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*", // Разрешаем подключение с любых доменов в интернете
    methods: ["GET", "POST"]
  }
});

// Указываем серверу раздавать файлы из папки public
app.use(express.static('public'));

// Обработка подключений
io.on('connection', (socket) => {
    console.log('Пользователь подключился!');

    socket.on('chat message', (msg) => {
        // Рассылаем сообщение всем пользователям
        io.emit('chat message', msg);
    });

    socket.on('disconnect', () => {
        console.log('Пользователь отключился');
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
});