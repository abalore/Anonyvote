// ---------------------------------------------------------------------------
// The voter's cryptography, in the browser.
//
// Everything that protects anonymity happens HERE, on the machine of whoever votes: the token
// is generated locally, blinded before it leaves and unblinded when it comes back. The server
// never sees the unblinded token, so it cannot link whoever registers to whoever votes.
//
// RFC 9474, variant RSABSSA-SHA384-PSS-Randomized. WebCrypto does the hashing, encryption and
// verification; only the blinding and unblinding are done by hand with BigInt, because
// WebCrypto does not expose the raw RSA operation they need.
// ---------------------------------------------------------------------------

const HASH = 'SHA-384';
const HASH_LENGTH = 48;
const SALT_LENGTH = 48;
const PREFIX_LENGTH = 32;
const TOKEN_LENGTH = 32;

// --- Conversions ------------------------------------------------------------

export const toBase64 = bytes => btoa(String.fromCharCode(...bytes));

export const fromBase64 = text =>
    Uint8Array.from(atob(text), c => c.charCodeAt(0));

const concat = (...chunks) => {
    const total = chunks.reduce((n, c) => n + c.length, 0);
    const output = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.length; }
    return output;
};

const toInteger = bytes => {
    let value = 0n;
    for (const b of bytes) value = (value << 8n) | BigInt(b);
    return value;
};

const toBytes = (value, length) => {
    const output = new Uint8Array(length);
    for (let i = length - 1; i >= 0; i--) { output[i] = Number(value & 0xffn); value >>= 8n; }
    if (value !== 0n) throw new Error('the integer does not fit in the requested length');
    return output;
};

const fromBase64Url = text =>
    fromBase64(text.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(text.length / 4) * 4, '='));

const pemToBytes = pem =>
    fromBase64(pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''));

// --- Modular arithmetic -----------------------------------------------------

const modPow = (base, exponent, modulus) => {
    let result = 1n;
    base %= modulus;
    while (exponent > 0n) {
        if (exponent & 1n) result = (result * base) % modulus;
        base = (base * base) % modulus;
        exponent >>= 1n;
    }
    return result;
};

const modInverse = (a, m) => {
    let [r0, r1] = [((a % m) + m) % m, m];
    let [s0, s1] = [1n, 0n];
    while (r1 !== 0n) {
        const q = r0 / r1;
        [r0, r1] = [r1, r0 - q * r1];
        [s0, s1] = [s1, s0 - q * s1];
    }
    if (r0 !== 1n) return null;        // no inverse: retry with a different r
    return ((s0 % m) + m) % m;
};

const randomIntegerBelow = (limit, length) => {
    while (true) {
        const candidate = toInteger(crypto.getRandomValues(new Uint8Array(length)));
        if (candidate > 0n && candidate < limit) return candidate;
    }
};

// --- EMSA-PSS ---------------------------------------------------------------

const digest = async bytes => new Uint8Array(await crypto.subtle.digest(HASH, bytes));

const mgf1 = async (seed, length) => {
    const blocks = [];
    for (let counter = 0, produced = 0; produced < length; counter++, produced += HASH_LENGTH) {
        const c = new Uint8Array(4);
        new DataView(c.buffer).setUint32(0, counter, false);
        blocks.push(await digest(concat(seed, c)));
    }
    return concat(...blocks).slice(0, length);
};

const pssEncode = async (message, emBits) => {
    const emLength = Math.ceil(emBits / 8);
    if (emLength < HASH_LENGTH + SALT_LENGTH + 2)
        throw new Error('key too short for PSS');

    const messageHash = await digest(message);
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const h = await digest(concat(new Uint8Array(8), messageHash, salt));

    const db = new Uint8Array(emLength - HASH_LENGTH - 1);
    db[db.length - SALT_LENGTH - 1] = 0x01;
    db.set(salt, db.length - SALT_LENGTH);

    const mask = await mgf1(h, db.length);
    for (let i = 0; i < db.length; i++) db[i] ^= mask[i];

    const bitsToClear = 8 * emLength - emBits;
    if (bitsToClear > 0) db[0] &= 0xff >> bitsToClear;

    return concat(db, h, Uint8Array.of(0xbc));
};

// --- Public keys ------------------------------------------------------------

const importKey = async (pem, algorithm, usages) =>
    crypto.subtle.importKey('spki', pemToBytes(pem), algorithm, true, usages);

/** Extracts modulus and exponent via JWK, so no ASN.1 parser has to be written. */
export const registrarPublicKey = async pem => {
    const key = await importKey(pem, { name: 'RSA-PSS', hash: HASH }, ['verify']);
    const jwk = await crypto.subtle.exportKey('jwk', key);
    const modulus = fromBase64Url(jwk.n);
    return { key, n: toInteger(modulus), e: toInteger(fromBase64Url(jwk.e)), length: modulus.length };
};

export const electionPublicKey = pem =>
    importKey(pem, { name: 'RSA-OAEP', hash: 'SHA-256' }, ['encrypt']);

// --- The protocol -----------------------------------------------------------

/** Generates the voter's token and blinds it. The server will only ever see `blinded`. */
export const prepareAndBlind = async registrar => {
    const prepared = concat(
        crypto.getRandomValues(new Uint8Array(PREFIX_LENGTH)),
        crypto.getRandomValues(new Uint8Array(TOKEN_LENGTH)));

    const bits = registrar.length * 8;
    const m = toInteger(await pssEncode(prepared, bits - 1));
    if (m >= registrar.n) throw new Error('encoded message out of range');

    let r, inverse;
    do {
        r = randomIntegerBelow(registrar.n, registrar.length);
        inverse = modInverse(r, registrar.n);
    } while (inverse === null);

    const blinded = (m * modPow(r, registrar.e, registrar.n)) % registrar.n;

    return {
        prepared,
        blinded: toBytes(blinded, registrar.length),
        inverse
    };
};

/** Unblinds the signature and checks it. From here on nothing ties it to the registration. */
export const unblind = async (registrar, prepared, blindSignature, inverse) => {
    const s = (toInteger(blindSignature) * inverse) % registrar.n;
    const signature = toBytes(s, registrar.length);

    const valid = await crypto.subtle.verify(
        { name: 'RSA-PSS', saltLength: SALT_LENGTH }, registrar.key, signature, prepared);
    if (!valid) throw new Error('the registrar returned a signature that is not valid');

    return signature;
};

/** Encrypts the ballot under the election key. OAEP is already randomized: no nonce needed. */
export const encryptBallot = async (electionKey, choices) => {
    const ballot = new TextEncoder().encode(
        JSON.stringify({ choices: [...choices].sort((a, b) => a - b) }));
    return new Uint8Array(
        await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, electionKey, ballot));
};

// --- Verifying a published election, in the browser -------------------------
//
// The whole point of publishing the board and the election key is that the count does not
// depend on whoever ran the services. So the results page recomputes everything here, on the
// reader's machine, from the published file alone.

export const toHex = bytes =>
    [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');

export const fromHex = text =>
    Uint8Array.from(text.match(/../g) ?? [], h => parseInt(h, 16));

const sha256 = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

/** H0 = SHA256("anonyvote-board-v1:" || electionId) */
export const boardGenesis = electionId =>
    sha256(new TextEncoder().encode('anonyvote-board-v1:' + electionId));

/** Hi = SHA256(Hi-1 || u64be(index) || lp(nullifier) || lp(message) || lp(signature) || lp(ciphertext)) */
export const boardNext = (previousHash, index, nullifier, message, signature, ciphertext) => {
    const indexBytes = new Uint8Array(8);
    new DataView(indexBytes.buffer).setBigUint64(0, BigInt(index), false);

    const withLength = bytes => {
        const length = new Uint8Array(4);
        new DataView(length.buffer).setUint32(0, bytes.length, false);
        return concat(length, bytes);
    };

    return sha256(concat(
        previousHash, indexBytes,
        withLength(nullifier), withLength(message),
        withLength(signature), withLength(ciphertext)));
};

export const nullifierOf = async message => toHex(await sha256(message));

/** The credential's signature is a plain RSA-PSS signature; nothing blind about verifying it. */
export const verifyCredential = (registrar, message, signature) =>
    crypto.subtle.verify(
        { name: 'RSA-PSS', saltLength: SALT_LENGTH }, registrar.key, signature, message);

export const electionPrivateKey = pem =>
    crypto.subtle.importKey('pkcs8', pemToBytes(pem),
        { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);

export const decryptBallot = async (key, ciphertext) => {
    const plain = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, key, ciphertext);
    return JSON.parse(new TextDecoder().decode(plain)).choices ?? [];
};

/** Modulus and exponent of a key, to check a private key against the announced public one. */
export const keyIdentity = async key => {
    const jwk = await crypto.subtle.exportKey('jwk', key);
    return `${jwk.n}.${jwk.e}`;
};

/** AGPL s.13: if this deployment says where its source is, put it in front of the voter. */
export const showSourceLink = (element, url) => {
    if (!url) return;
    const link = document.createElement('a');
    link.href = url;
    link.rel = 'noopener';
    link.textContent = 'Source';
    element.append(link, ' \u00b7 ');
};

// --- Talking to the services ------------------------------------------------

export const api = async (path, body) => {
    const response = await fetch(path, body === undefined ? {} : {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });

    const text = await response.text();
    const data = text ? JSON.parse(text) : null;

    if (!response.ok) throw new Error(data?.error ?? `error ${response.status}`);
    return data;
};
