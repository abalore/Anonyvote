// Runs the SAME cryptography module that runs in the browser, but from Node, against the real
// services. It is the proof that the web client really does interoperate with the C# server:
// if the browser's blinding and the registrar's signing did not match byte for byte, it would
// show up here.
//
//   node voter.mjs register --registrar URL --code CODE --out credential.json
//   node voter.mjs vote     --ballotbox URL --credential credential.json --choices 1,2

import { readFile, writeFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';

// Node 18 does not expose WebCrypto as a global yet; the browser does. The client module is
// left untouched: it is handed the same `crypto` it would have in a tab.
globalThis.crypto ??= webcrypto;

import {
    registrarPublicKey, electionPublicKey, prepareAndBlind, unblind,
    encryptBallot, toBase64, fromBase64, api
} from '../../web/common/anonyvote.js';

const arg = name => {
    const i = process.argv.indexOf(`--${name}`);
    return i > 0 ? process.argv[i + 1] : null;
};

const command = process.argv[2];

try {
    if (command === 'register') {
        const base = arg('registrar').replace(/\/$/, '');
        const election = await api(`${base}/api/election`);
        const registrar = await registrarPublicKey(election.registrarPublicKeyPem);

        const { prepared, blinded, inverse } = await prepareAndBlind(registrar);
        const response = await api(`${base}/api/register`, {
            code: arg('code'),
            blindedMessage: toBase64(blinded)
        });

        // unblind() verifies the signature with WebCrypto: if the server had signed badly, or
        // if our PSS encoding were not theirs, this would throw right here.
        const signature = await unblind(
            registrar, prepared, fromBase64(response.blindSignature), inverse);

        await writeFile(arg('out'), JSON.stringify({
            electionId: election.id,
            message: toBase64(prepared),
            signature: toBase64(signature)
        }));
        console.log('  JS client: credential obtained and verified with WebCrypto');

    } else if (command === 'vote') {
        const base = arg('ballotbox').replace(/\/$/, '');
        const election = await api(`${base}/api/election`);
        const credential = JSON.parse(await readFile(arg('credential'), 'utf8'));
        const choices = (arg('choices') ?? '').split(',').filter(Boolean).map(Number);

        const key = await electionPublicKey(election.electionPublicKeyPem);
        const receipt = await api(`${base}/api/cast`, {
            message: credential.message,
            signature: credential.signature,
            ciphertext: toBase64(await encryptBallot(key, choices))
        });

        console.log(`  JS client: vote accepted at position ${receipt.index}`);
        if (arg('out')) await writeFile(arg('out'), JSON.stringify(receipt));

    } else {
        console.error('usage: voter.mjs register|vote ...');
        process.exit(2);
    }
} catch (error) {
    console.error(`  JS client: ERROR — ${error.message}`);
    process.exit(1);
}
