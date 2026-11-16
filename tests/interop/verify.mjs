// Recomputes a published election with the SAME module the results page runs in the browser,
// and prints the outcome as JSON so it can be compared against the C# verifier.
//
// This is what makes the results page trustworthy as a claim: if the browser's hash chain,
// signature checks or decryption disagreed with the reference implementation in any way, the
// two outputs would differ here.
//
//   node verify.mjs --results results.json
//   node verify.mjs --url http://127.0.0.1:5901/api/results

import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';

globalThis.crypto ??= webcrypto;

const {
    fromBase64, toHex, boardGenesis, boardNext, nullifierOf,
    registrarPublicKey, electionPublicKey, electionPrivateKey,
    decryptBallot, verifyCredential, keyIdentity
} = await import('../../web/common/anonyvote.js');

const arg = name => {
    const i = process.argv.indexOf(`--${name}`);
    return i > 0 ? process.argv[i + 1] : null;
};

const published = arg('url')
    ? await (await fetch(arg('url'))).json()
    : JSON.parse(await readFile(arg('results'), 'utf8'));

const election = published.election;
const board = published.board;
const problems = [];

const registrar = await registrarPublicKey(election.registrarPublicKeyPem);
const privateKey = await electionPrivateKey(published.electionPrivateKeyPem);

if (await keyIdentity(privateKey) !== await keyIdentity(await electionPublicKey(election.electionPublicKeyPem)))
    problems.push('the published private key does not match the manifest public key');

const fromHex = text => Uint8Array.from(text.match(/../g) ?? [], h => parseInt(h, 16));

const seen = new Set();
let hash = await boardGenesis(election.id);

for (const [position, entry] of board.entries()) {
    if (entry.index !== position) problems.push(`entry ${position}: index jumps to ${entry.index}`);

    const message = fromBase64(entry.message);
    const signature = fromBase64(entry.signature);
    const ciphertext = fromBase64(entry.ciphertext);

    hash = await boardNext(hash, entry.index, fromHex(entry.nullifier), message, signature, ciphertext);
    if (toHex(hash) !== entry.hash.toLowerCase()) {
        problems.push(`entry ${entry.index}: hash chain mismatch`);
        hash = fromHex(entry.hash);
    }

    if (!await verifyCredential(registrar, message, signature))
        problems.push(`entry ${entry.index}: credential not signed by the registrar`);

    if (await nullifierOf(message) !== entry.nullifier.toLowerCase())
        problems.push(`entry ${entry.index}: nullifier does not match the message`);

    if (seen.has(entry.nullifier)) problems.push(`entry ${entry.index}: repeated credential`);
    seen.add(entry.nullifier);
}

if (board.length > published.issuedCredentials)
    problems.push('more votes than credentials issued');
if (published.issuedCredentials > published.censusSize)
    problems.push('more credentials issued than the census holds');

const tally = new Map(election.candidates.map(c => [c.id, 0]));
const valid = new Set(election.candidates.map(c => c.id));
let blank = 0, spoilt = 0;

for (const entry of board) {
    let choices;
    try {
        choices = await decryptBallot(privateKey, fromBase64(entry.ciphertext));
    } catch {
        spoilt++;
        continue;
    }

    const wellFormed = Array.isArray(choices)
        && choices.length <= election.maxChoices
        && new Set(choices).size === choices.length
        && choices.every(id => valid.has(id));

    if (!wellFormed) { spoilt++; continue; }
    if (choices.length === 0) { blank++; continue; }
    for (const id of choices) tally.set(id, tally.get(id) + 1);
}

console.log(JSON.stringify({
    ok: problems.length === 0,
    head: toHex(hash),
    ballots: board.length,
    census: published.censusSize,
    credentials: published.issuedCredentials,
    blank,
    spoilt,
    tally: Object.fromEntries([...tally].map(([id, votes]) => [String(id), votes])),
    problems
}, null, 2));

process.exit(problems.length === 0 ? 0 : 1);
