const crypto = require('crypto-browserify');

/**
 * Aláírás létrehozása
 */
function createSign(privateKey, data) {
  const signer = crypto.createSign('RSA-SHA256'); // aláíró létrehozása (SHA-256 hash)

  // aláíró feltöltése az aláírandó adattal
  signer.update(data);
  signer.end();

  // base64 kódolt aláírás létrehozása a privát kulcs segítségével
  return signer.sign(privateKey).toString('base64'); 
}

/**
 * Aláírás ellenőrzése
 */
function verifySign(publicKey, data, signature) {
  const verifier = crypto.createVerify('RSA-SHA256'); // aláíró letrehozása (SHA-256 hash)

  // aláíró feltöltése az aláírandó adattal
  verifier.update(data);
  verifier.end();

  // aláírás ellenőrzése a publikus kulcs és a base64 kódolt aláírás segítségével
  return verifier.verify(publicKey, Buffer.from(signature, 'base64')); 
}

/**
 * Véletlen szöveges kulcs létrehozása
 */
function createRandomKey() {
  return crypto.randomBytes(16).toString('base64').substring(0,16);
}

/**
 * Új szimmetrikus kulcs és iv (counter) létrehozása
 */
function createSymmetricKey() {
  const key = createRandomKey(); // véletlen szöveges kulcs - 16byte
  const nonce = crypto.randomBytes(12); // 96 bit
  const counter0 = Buffer.alloc(4, 0);// 32 bit
  // iv = Counter állapot 96 bites nonce prefix, és 32 bites számláló 0 kezdőértékkel
  const iv = Buffer.concat([nonce, counter0]).toString('base64'); // base64 kódolva
  return {key, iv};
}

/**
 * Üzenet rejtjelezése szimmetrikus kulcs segítségével
 * @param {*} param0 kulcs
 * @param {*} data rejtjelezendő szöveges üzenet
 * @returns rejtjelezett üzenet base64 kódolva
 */
function encryptMessage({key, iv}, data) {
  const cipher = crypto.createCipheriv("aes-128-ctr", key, Buffer.from(iv, 'base64'));
  return cipher.update(data, 'utf-8', 'base64') + cipher.final('base64');
}

/**
 * Üzenet dekódolása szimmetrikus kulcs segítségével
 * @param {*} param0  kulcs
 * @param {*} encryptedData base64 kódolt rejtjelezett üzenet
 * @returns nyílt üzenet
 */
function decryptMessage({key, iv}, encryptedData) {
  const cipher = crypto.createDecipheriv("aes-128-ctr", key, Buffer.from(iv, 'base64'))
  return cipher.update(encryptedData, 'base64', 'utf-8') + cipher.final('utf-8');
}

/**
 * Kulcs (és counter) kódolása publikus kulcs segítségével
 * @returns rejtjelezett kulcs base64 formátumban
 */
function publicEncryptKey(publicKey, {key, iv}) {
  const keyStr = key + '|' + iv; // kulcs és iv (counter állapot) összefűzése
  return crypto.publicEncrypt(publicKey, Buffer.from(keyStr)).toString('base64');
}

/**
 * Base64 formátumú rejtjelezett kulcs (és counter) dekódolása privát kulcs segítségével
 */
function privateDecryptKey(privateKey, encrypedKeyStr /* base64 */) {
  const decrypedKeyStr = crypto.privateDecrypt(privateKey, Buffer.from(encrypedKeyStr, 'base64')).toString();
  const [key, iv] = decrypedKeyStr.split('|'); // kulcs és iv (counter állapot) szétválasztása
  return { key, iv };
}

module.exports = {
  createSign,
  verifySign,
  createSymmetricKey,
  encryptMessage,
  decryptMessage,
  publicEncryptKey,
  privateDecryptKey,
  createKeyPair: generateKeyPair,
}

/* GENERATE RSA KEYPAIR - PEM */

/*
Compatible with

crypto.generateKeyPairSync('rsa', {
  modulusLength: 4096,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
});
*/

function arrayBufferToBase64(arrayBuffer) {
    var byteArray = new Uint8Array(arrayBuffer);
    var byteString = '';
    for(var i=0; i < byteArray.byteLength; i++) {
        byteString += String.fromCharCode(byteArray[i]);
    }
    var b64 = window.btoa(byteString);

    return b64;
}

function addNewLines(str) {
    var finalString = '';
    while(str.length > 0) {
        finalString += str.substring(0, 64) + '\n';
        str = str.substring(64);
    }

    return finalString;
}

function toPem(privateKey, ispub = false) {
    var b64 = addNewLines(arrayBufferToBase64(privateKey));
    var pem = "-----BEGIN " + (ispub ? 'PUBLIC' : 'PRIVATE') + " KEY-----\n" 
    + b64 + "-----END " + (ispub ? 'PUBLIC' : 'PRIVATE') + " KEY-----";
    
    return pem;
}

async function generateKeyPair() {
  // Let's generate the key pair first
  var keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096, // can be 1024, 2048 or 4096
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {name: "SHA-256"} // or SHA-512
    },
    true,
    ["encrypt", "decrypt"]
  );


  // PublicKey - SPKI export
  var exportedPublicKeyPEM = await window.crypto.subtle.exportKey(
    "spki",
    keyPair.publicKey
  ).then(function(exportedPublicKey) {
    // converting exported public key to PEM format
    return toPem(exportedPublicKey, true);
  });

  // PrivateKey - PKCS8 export
  var exportedPrivateKeyPEM = await window.crypto.subtle.exportKey(
    "pkcs8",
    keyPair.privateKey
  ).then(function(exportedPrivateKey) {
    // converting exported private key to PEM format
    return toPem(exportedPrivateKey);
  });

  return {
    privateKey: exportedPrivateKeyPEM, 
    publicKey: exportedPublicKeyPEM,
  }
}