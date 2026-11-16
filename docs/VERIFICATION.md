# How to count an election for yourself

At closing time the organiser publishes a single file — `results.json` — containing the
manifest, the whole board, the size of the census, how many credentials were issued and **the
election's private key**. With that, counting the votes depends neither on the organiser nor
on this software.

```
anonyvote-verify results.json
anonyvote-verify results.json --receipt YOUR_RECEIPT
anonyvote-verify results.json --json            # output for automated audits
```

It returns 0 when everything adds up and 1 when it finds any problem.

## What it checks, and why each check matters

1. **The published private key matches the manifest's public key.** Otherwise you would be
   counting ballots other than the ones that were announced.
2. **The hash chain.** Each entry chains to the one before it; altering, inserting, deleting
   or reordering a single ballot changes every hash after it.
3. **Every signature.** Every credential must have been signed by the registrar: it is the
   only proof of eligibility that exists anywhere in the system.
4. **Each entry's nullifier** derives from its message, and none repeats: nobody voted twice.
5. **Census >= credentials issued >= votes.** This is the chain of quantities that stops
   ballots appearing out of nowhere. The published census is also what makes turnout
   computable and comparable against how many codes were really handed out.
6. **The tally**, by decrypting each ballot. Ballots that fail to decrypt or that are invalid
   are counted as spoilt rather than silently dropped.

## The board format, in case you want to reimplement it

It is deliberately plain so that this program is not required:

```
H0 = SHA256( "anonyvote-board-v1:" || electionId )
Hi = SHA256( Hi-1 || u64be(index) || lp(nullifier) || lp(message) || lp(signature) || lp(ciphertext) )

lp(x) = u32be(length(x)) || x
```

The length prefix stops two different entries from producing the same byte sequence. The
fields come off the board as raw bytes (the JSON carries them base64-encoded, except the
nullifier, which is hexadecimal).

- **Signature**: standard RSA-PSS, SHA-384, 48-byte salt, over the whole `message` field. Any
  crypto library validates it; nothing about blind signatures is needed here.
- **Nullifier**: `SHA256(message)`, lowercase hexadecimal.
- **Ballot**: RSA-OAEP with SHA-256. Decrypted, it reads `{"choices":[sorted ids]}`.

## Checking your own vote

The receipt the ballot box gave you is the hash of your entry. `--receipt` looks it up on the
published board and tells you where it sits. While voting is open you can do the same against
the live board:

```
curl "https://ballotbox.example.org/api/board?from=YOUR_INDEX&limit=1"
```

If your receipt does not show up, keep it: it is the evidence that the ballot box took your
ballot and then failed to publish it.

## What this verification CANNOT tell you

Whether the census was legitimate. The verifier checks that the quantities agree with one
another — census, credentials and votes — but the census size is declared by the organiser
themselves: if they generated 300 codes and only handed out 250, the arithmetic still adds up.
That part rests on the published figure being checked against the list of people who were
actually given a code.

Whether the election key was used early. The manifest states whether it is split with a
threshold and among how many trustees, but nothing can prove that K of them did not get
together before closing.

Whether anyone voted under duress: see [THREAT-MODEL.md](THREAT-MODEL.md).
