import * as crypto from 'node:crypto';
function generateSecureToken(length = 32) {
    // randomBytes generates a Buffer of the specified size (in bytes).
    // The output hex string will be twice the length of the buffer size.
    const bufferSize = Math.ceil(length / 2);
    const token = crypto.randomBytes(bufferSize).toString('hex').slice(0, length);
    return token;
}
// Logging the token
const myToken = generateSecureToken(32);
console.log(`Generated Token: ${myToken}`);
//# sourceMappingURL=crypto.js.map