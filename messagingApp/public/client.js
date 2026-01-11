const socket = io();
let myName;
let privateKey;
let usersPublic = {}; // {username: publicKeyB64}

// ===== SAFE BASE64 HELPERS (MUST BE AT TOP) =====
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ===== SOCKET EVENTS =====
socket.on('error', (msg) => {
  document.getElementById('error').innerText = msg;
});

socket.on('loggedin', async () => {
  myName = document.getElementById('name').value;
  const publicKeyB64 = await generateKeys();
  socket.emit('publicKey', publicKeyB64);
  document.getElementById('login').style.display = 'none';
  document.getElementById('chat').style.display = 'block';
});

socket.on('userList', (list) => {
  list.forEach(u => {
    usersPublic[u.name] = u.publicKey;
  });
});

socket.on('newUser', (user) => {
  usersPublic[user.name] = user.publicKey;
});

socket.on('userLeft', (name) => {
  delete usersPublic[name];
});

// Text message receive
socket.on('message', async (data) => {
  const { from, encryptedMsg, iv, encryptedKeys } = data;
  if (from === myName) return;

  const encKeyB64 = encryptedKeys[myName];
  if (!encKeyB64) return;

  try {
    const encKey = new Uint8Array(base64ToArrayBuffer(encKeyB64));
    const decryptedAes = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      encKey
    );

    const aesKey = await crypto.subtle.importKey(
      'raw',
      decryptedAes,
      'AES-GCM',
      true,
      ['decrypt']
    );

    const ivArr = new Uint8Array(base64ToArrayBuffer(iv));
    const encMsgArr = new Uint8Array(base64ToArrayBuffer(encryptedMsg));

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivArr },
      aesKey,
      encMsgArr
    );

    const msg = new TextDecoder().decode(decrypted);
    appendMessage(from, msg);
  } catch (e) {
    console.error('Text decryption failed', e);
  }
});

// System messages (join/leave - others only)
socket.on('systemMessage', (text) => {
  const messages = document.getElementById('messages');
  const div = document.createElement('div');
  div.innerText = text;
  div.className = 'system';
  messages.appendChild(div);
  messages.scrollTop = messages.scrollHeight;
});

// File receive
socket.on('file', async (data) => {
  const { from, filename, mime, encryptedData, iv, encryptedKeys } = data;
  const encKeyB64 = encryptedKeys[myName];
  if (!encKeyB64) return;

  try {
    const encKey = new Uint8Array(base64ToArrayBuffer(encKeyB64));
    const decryptedAes = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      encKey
    );

    const aesKey = await crypto.subtle.importKey(
      'raw',
      decryptedAes,
      'AES-GCM',
      true,
      ['decrypt']
    );

    const ivArr = new Uint8Array(base64ToArrayBuffer(iv));
    const encDataArr = new Uint8Array(base64ToArrayBuffer(encryptedData));

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivArr },
      aesKey,
      encDataArr
    );

    const blob = new Blob([decrypted], { type: mime });

    const div = document.createElement('div');
    div.innerHTML = `${from}>> [File: ${filename}]`;

    if (mime.startsWith('image/')) {
      const url = URL.createObjectURL(blob);
      const img = document.createElement('img');
      img.src = url;
      img.style.maxWidth = '300px';
      img.style.marginTop = '5px';
      img.style.borderRadius = '8px';
      div.appendChild(document.createElement('br'));
      div.appendChild(img);
    } else {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.innerText = `Download ${filename}`;
      a.style.color = '#88ccff';
      div.appendChild(document.createElement('br'));
      div.appendChild(a);
    }

    document.getElementById('messages').appendChild(div);
    document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
  } catch (e) {
    console.error('File decryption failed', e);
  }
});

// ===== FUNCTIONS =====
function login() {
  const name = document.getElementById('name').value.trim();
  const password = document.getElementById('password').value;
  if (!name || !password) return;
  socket.emit('login', { name, password });
}

async function generateKeys() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  );

  privateKey = keyPair.privateKey;
  const exported = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  return arrayBufferToBase64(exported); // Use safe function
}

async function sendMessage() {
  const msg = document.getElementById('message').value.trim();
  if (!msg) return;

  document.getElementById('message').value = '';
  appendMessage(myName, msg);

  const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    new TextEncoder().encode(msg)
  );

  const encryptedMsgB64 = arrayBufferToBase64(encrypted);
  const ivB64 = arrayBufferToBase64(iv.buffer);

  const exportedAes = await crypto.subtle.exportKey('raw', aesKey);
  const encryptedKeys = {};

  for (const u in usersPublic) {
    const pubKey = await crypto.subtle.importKey(
      'spki',
      base64ToArrayBuffer(usersPublic[u]),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    );
    const encKey = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      pubKey,
      exportedAes
    );
    encryptedKeys[u] = arrayBufferToBase64(encKey);
  }

  socket.emit('message', {
    encryptedMsg: encryptedMsgB64,
    iv: ivB64,
    encryptedKeys
  });
}

function appendMessage(username, text) {
  const messages = document.getElementById('messages');
  const div = document.createElement('div');
  div.innerText = `${username}>> ${text}`;
  messages.appendChild(div);
  messages.scrollTop = messages.scrollHeight;
}

// File upload
document.getElementById('file-input').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;

  if (file.size > 10 * 1024 * 1024) {
    alert('File too large! Max 10MB.');
    e.target.value = ''; // Clear input
    return;
  }

  const reader = new FileReader();
  reader.onload = async () => {
    const fileData = new Uint8Array(reader.result);

    const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encryptedData = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      fileData
    );

    const encryptedDataB64 = arrayBufferToBase64(encryptedData);
    const ivB64 = arrayBufferToBase64(iv.buffer);

    const exportedAes = await crypto.subtle.exportKey('raw', aesKey);
    const encryptedKeys = {};

    for (const u in usersPublic) {
      const pubKey = await crypto.subtle.importKey(
        'spki',
        base64ToArrayBuffer(usersPublic[u]),
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt']
      );
      const encKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, exportedAes);
      encryptedKeys[u] = arrayBufferToBase64(encKey);
    }

    socket.emit('file', {
      filename: file.name,
      mime: file.type || 'application/octet-stream',
      encryptedData: encryptedDataB64,
      iv: ivB64,
      encryptedKeys
    });

    displayLocalFile(file.name, file.type, fileData);
  };

  reader.readAsArrayBuffer(file);
});

function displayLocalFile(filename, mime, data) {
  const div = document.createElement('div');
  div.innerHTML = `${myName}>> [File: ${filename}]`;

  if (mime.startsWith('image/')) {
    const blob = new Blob([data], { type: mime });
    const url = URL.createObjectURL(blob);
    const img = document.createElement('img');
    img.src = url;
    img.style.maxWidth = '300px';
    img.style.marginTop = '5px';
    img.style.borderRadius = '8px';
    div.appendChild(document.createElement('br'));
    div.appendChild(img);
  } else {
    div.innerHTML += `<br><span style="color:#88ccff;">(Non-image file attached)</span>`;
  }

  document.getElementById('messages').appendChild(div);
  document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
}