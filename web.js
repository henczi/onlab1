const {
  createSign,
  verifySign,
  createSymmetricKey,
  encryptMessage,
  decryptMessage,
  publicEncryptKey,
  privateDecryptKey,
  createKeyPair,
} = require('./message-crypto.js');

createKeyPair().then(keyPair =>{

let sign = createSign(keyPair.privateKey, 'alma-áéáű');
console.log('sign', sign);
let verify = verifySign(keyPair.publicKey, 'alma-áéáű', sign);
console.log('verify', verify);
let symmetricKey = createSymmetricKey();
console.log('symmetric key', symmetricKey);
let encryped = encryptMessage(symmetricKey, 'HELLoooo');
console.log('encryped msg', encryped);
let publicEncryptedSymmetricKey = publicEncryptKey(keyPair.publicKey, symmetricKey);
console.log('pub encr key', publicEncryptedSymmetricKey);
let privateDecryptedSymmetricKey = privateDecryptKey(keyPair.privateKey, publicEncryptedSymmetricKey);
console.log('priv decr key', privateDecryptedSymmetricKey);
let decrypted = decryptMessage(privateDecryptedSymmetricKey, encryped);
console.log('decrypted msg', decrypted);

});
