const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http, {maxHttpBufferSize: 50 * 1024 * 1024});   // 50MB limit (adjust as needed)
const crypto = require('crypto');

// CHANGE THIS TO YOUR OWN STRONG PASSWORD
// Use a long, random string (e.g., 20+ characters with letters, numbers, symbols)
const SHARED_PASSWORD = 'SuperStrongPassword!@#123';
const PASSWORD_HASH = crypto.createHash('sha256').update(SHARED_PASSWORD).digest('hex');

app.use(express.static('public'));

let users = {}; // {username: {socket, publicKey}}

io.on('connection', (socket) => {
  // No IP logging anywhere — completely ignored

socket.on('file', (fileData) => {
  if (!socket.username) return;
  io.emit('file', { from: socket.username, ...fileData });
});

socket.on('login', (data) => {
  const { name, password } = data;

  const hash = crypto.createHash('sha256').update(password).digest('hex');
  if (hash !== PASSWORD_HASH) {
    socket.emit('error', 'Invalid password');
    return;
  }

  if (users[name]) {
    socket.emit('error', 'Name already taken');
    return;
  }

  users[name] = { socket, publicKey: null };
  socket.username = name;
  socket.emit('loggedin');

  // Notify ALL connected users (including others) that someone joined
  // The new user won't see their own join because we'll handle it client-side if needed
  io.emit('systemMessage', `${name} has joined the chat`);
});

socket.on('publicKey', (publicKey) => {
    if (!socket.username) return;

    users[socket.username].publicKey = publicKey;

    // Send list of existing users with public keys to the new user
    const userList = Object.keys(users).reduce((acc, u) => {
      if (users[u].publicKey) {
        acc.push({ name: u, publicKey: users[u].publicKey });
      }
      return acc;
    }, []);

    socket.emit('userList', userList);

    // Notify others about the new user
    io.emit('newUser', { name: socket.username, publicKey });
  });

  socket.on('message', (msgData) => {
    if (!socket.username) return;
    io.emit('message', { from: socket.username, ...msgData });
  });

  socket.on('disconnect', () => {
    if (socket.username && users[socket.username]) {
        const leavingName = socket.username;
        delete users[socket.username];
        // Notify EVERYONE ELSE (not the disconnected user) that someone left
        io.emit('systemMessage', `${leavingName} has left the chat`);}
    });
});

// Startup message so you know it's running
http.listen(3000, () => {
  console.log('Secure chat server running on http://localhost:3000');
  console.log('Pass: SuperStrongPassword!@#123    attach is not workin!');
});

// cd /Users/ritikjai/Desktop/Projects/messagingApp/
// node server.js
