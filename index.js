const crypto =require('crypto');
const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const {getAESKey, getPublicKeyFromCert, encryptRSA, encryptAES, decryptAES, hexToBytes, bytesToHex} = require('./utils')

// console.log(getPublicKeyFromCert(certPath));
// Replace with your publicKey (obtained from the previous code snippet)
// const publicKeyPem = `${getPublicKeyFromCert(certPath).export({type:"pkcs1", format: "pem"})}`;
// const text = 'Your text to encrypt';
// const encryptedBuffer = encrypt(text, publicKeyPem);
// console.log(encryptedBuffer);



// const secretKey = `${getAESKey()}`;
// const textToEncrypt = 'Your text to encrypt';
// const encryptedText = encrypt(textToEncrypt, secretKey);
// console.log('Encrypted:', encryptedText);
// const decryptedText = decrypt(encryptedText, secretKey);
// console.log('Decrypted:', decryptedText);


// const hexString = '68656c6c6f20776f726c64'; // 'hello world' in hexadecimal
// const bytes = hexToBytes(hexString);
// console.log('Bytes:', bytes);
// const convertedHexString = bytesToHex(bytes);
// console.log('Hex string:', convertedHexString);
        
const app = express();
app.use(bodyParser.json());
app.post('/authenticate', async (req, res) => {
    const authenticateRequest = req.body;
    const authenticateURL = 'https://api.udiseplus.gov.in/school/v1.2/authenticate';
    try {
        const requestJson = JSON.stringify(authenticateRequest);
        const base64EncodedJson = Buffer.from(requestJson).toString('base64');
        const publicKey = getPublicKeyFromCert(certPath).export({type:"pkcs1", format: "pem"});
        
        const publicKeyPem = `${publicKey}`;
        console.log(publicKeyPem);

        const cipherText = encryptRSA(base64EncodedJson, publicKeyPem);
        const encryptedTextHex = bytesToHex(cipherText);
        const encryptedRequestBody = {
            data: encryptedTextHex,
        };
        console.log(1)
        const response = await axios.post(authenticateURL, encryptedRequestBody, {
            headers: {
                'Content-Type': 'application/json',
            },
        });
        console.log(2)
        const responseData = response.data;
        console.log(responseData.status);
        if (responseData.status) {
            const authResponse = responseData.data;
            console.log('authToken:', authResponse.authToken);
            console.log('sek:', authResponse.sek);
        }
        res.json(responseData);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.post('/testapicall', async (req, res) => {
    const schoolInfoByUdiseCodeRequest = req.body;
    const schoolInfoByUdiseCodeURL =
    'https://api.udiseplus.gov.in/school/v1.0/school-info/by-udise-code/public';
    try {
    const authToken = 'authToken received from Authentication API response';
    const sek = 'sek received from Authentication API response';
    const appKey = 'appKey that was sent in Authentication API request';
    const dsek = Buffer.from(sek, 'base64').toString('utf8');
    const decryptedSek = decryptAES(dsek, appKey);
    const objStr = JSON.stringify(schoolInfoByUdiseCodeRequest);
    const et = encrypt(objStr, decryptedSek);
    const etBase64 = Buffer.from(et).toString('base64');
    const encryptedRequestBody = {
    data: etBase64,
    };
    const response = await axios.post(schoolInfoByUdiseCodeURL, encryptedRequestBody, {
    headers: {
    Authorization: `Bearer ${authToken}`,
    },
    });
    const responseData = response.data;
res.json(responseData);
} catch (error) {
console.error(error);
res.status(500).json({ message: 'Internal Server Error' });
}});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});