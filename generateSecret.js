const crypto = require('crypto');

const generateSecretKey = () => {
    const length = 32; // Longitud en bytes (256 bits)
    return crypto.randomBytes(length).toString('hex');
};

const secretKey = generateSecretKey();
console.log(secretKey);

