const crypto =require('crypto');
const fs = require('fs');


function getAESKey() {
    const key = crypto.randomBytes(32); // Generate a 256-bit key (32 bytes)
    const encodedKey = key.toString('base64');
    return encodedKey;
}
function getPublicKeyFromCert(certPath) {
    const certData = fs.readFileSync(certPath);
    const cert = new crypto.X509Certificate(certData);
    const publicKey = cert.publicKey;
    return publicKey;
}

function encryptRSA(text, publicKeyPem) {
    const buffer = Buffer.from(text, 'utf8');
    const encrypted = crypto.publicEncrypt(
    {
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    buffer,
    );
    return encrypted;
}

function encryptAES(text, secretKey) {
    const key = Buffer.from(secretKey, 'base64');
    const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    return encrypted.toString('base64');
}

function decryptAES(text, secretKey) {
    const key = Buffer.from(secretKey, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-ecb', key, null);
    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(text, 'base64')),
        decipher.final(),
    ]);
    return decrypted.toString('utf8');
}
function bytesToHex(bytes) {
    return Buffer.from(bytes).toString('hex');
}
function hexToBytes(hexString) {
    return Buffer.from(hexString, 'hex');
}
module.exports = {getAESKey, getPublicKeyFromCert, encryptRSA, encryptAES, decryptAES, bytesToHex, hexToBytes};


