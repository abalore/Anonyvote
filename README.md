# Anonyvote

Remote internet voting, anonymous and verifiable. The voter picks up to 3 candidates from a
list; nobody can link a vote to whoever cast it; anyone can redo the count for themselves.

Self-hosted from end to end: two self-contained binaries, SQLite, no third-party services and
no network dependencies at runtime.

## How it achieves anonymity

RSA blind signatures (RFC 9474, RSABSSA-SHA384-PSS) across two separate services and two
phases that are disjoint in time:

|                | knows WHO | knows WHAT was voted |
|----------------|:---------:|:--------------------:|
| **Registrar**  |    yes    |          no          |
| **Ballot box** |    no     |         yes          |

1. **Registration.** The voter redeems a single-use code. Their browser generates a random
   token, **blinds** it and sends it to the registrar, which signs it without being able to
   see it. The browser **unblinds** the signature and ends up with an anonymous credential.
2. **Voting** (opens once registration has closed). The browser sends the ballot box, with no
   authentication of any kind, the credential and the encrypted ballot. The ballot box checks
   the signature, rejects credentials already spent and appends the ballot to a public,
   hash-chained board.
3. **Closing.** The board and the election's private key are published. `anonyvote-verify` —
   which anyone can run — decrypts, checks signatures and chain, and counts.

The disjoint phases are deliberate: by the time the first vote is cast, every credential has
already been handed out, so there is no timing correlation between registering and voting.

## What it does NOT guarantee

**It is not receipt-free**: a voter can prove to a third party how they voted, so the system
is vulnerable to coercion and vote buying. That is inherent to remote verifiable voting, not
an implementation flaw. Fit for associations, communities and committees; **not** for binding
political elections.

The remaining limitations and trust assumptions are in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
Read it before using this for anything that matters.

## Trying the whole thing in a minute

```bash
./scripts/simulation.sh 1000
```

It sets up an eight-candidate election, generates 1000 codes, starts both services, registers
1000 blind credentials, changes phase, votes, closes, publishes, counts with the independent
verifier, checks the tally ballot by ballot, verifies a receipt and confirms that flipping a
single bit on the board is detected. Along the way it also runs the real browser client under
Node, to prove that the JavaScript blinding interoperates with the C# signing.

Unit tests — including the official RFC 9474 vectors — with `dotnet test`.

## Running it for real

```bash
dotnet publish src/Anonyvote.Registrar -c Release -r linux-x64 --self-contained
dotnet publish src/Anonyvote.BallotBox -c Release -r linux-x64 --self-contained
```

Each one ends up as an executable with its `wwwroot` beside it. Configuration through
environment variables (or `appsettings.json`, or `--Anonyvote:Key=value`):

| Variable | Service | What it is |
|---|---|---|
| `Anonyvote__Election` | both | path to `election.json` |
| `Anonyvote__Database` | both | path to the SQLite file (one per service, never shared) |
| `Anonyvote__PrivateKey` | registrar | path to `registrar-private.pem` |
| `Anonyvote__RateLimit__PerSecond` | ballot box | requests per second allowed (500 by default; 0 removes the limit) |
| `Anonyvote__RateLimit__Queue` | ballot box | how many wait in line before 429s start (200 by default) |

**Deploy them on different machines.** The entire anonymity guarantee rests on whoever runs
the ballot box not also holding the registrar's records. And do not put a proxy in front that
writes access logs with IP addresses: that file alone would be the list of who voted when.

## The life of an election

```bash
anonyvote-admin init   --dir election --name "Board 2027" --candidates candidates.txt \
                       --trustees 5 --threshold 3        # the ballot box key, split
anonyvote-admin codes  --db registrar.db --count 300 --out codes.txt   # hand out off-band
anonyvote-admin phase  --db registrar.db --election election/election.json --set registration
#   ... voters register ...
anonyvote-admin phase  --db registrar.db  --election election/election.json --set closed
anonyvote-admin phase  --db ballotbox.db --election election/election.json --set voting
#   ... voting happens ...
anonyvote-admin phase  --db ballotbox.db --election election/election.json --set closed
anonyvote-admin publish --ballotbox-db ballotbox.db --registrar-db registrar.db \
                        --election election/election.json --out results.json \
                        --share share-1.json --share share-3.json --share share-5.json
anonyvote-verify results.json
```

The phase change is manual and deliberate: voting must not open until registration has fully
closed.

With `--trustees N --threshold K`, the election's private key is split into N shares and never
written anywhere whole: opening the ballot box requires gathering K of them. Without those
options the key stays in a `.pem` held by the organiser and is published with `--key`. The
public manifest states which of the two was done.

Publication includes the **census size**, not just the votes: without that figure there is no
way to judge turnout, nor to notice credentials being issued beyond it.

## Layout

```
src/Anonyvote.Crypto/      RSA blind signatures (blind / sign / unblind / verify)
src/Anonyvote.Core/        models, ballot, hash chain, storage
src/Anonyvote.Registrar/   the phase 1 service
src/Anonyvote.BallotBox/   the phase 2 service plus the public board
src/Anonyvote.Admin/       the organiser's CLI
src/Anonyvote.Verify/      the independent counting CLI
web/                       the browser client (HTML + JS, no frameworks, no npm)
tools/Anonyvote.Simulator/ synthetic voter for the acceptance test
tests/                     unit tests and JS-to-C# interoperability
docs/THREAT-MODEL.md       what is guaranteed and what is not
docs/VERIFICATION.md       how to count for yourself, and the board format
```

The web client is three static files with no build step: they are copied next to each
service's binary. There are no JavaScript dependencies, on purpose — a ballot has to be
auditable by reading the page's own source.

## License

Copyright (C) 2026 abalore

Anonyvote is free software: you can redistribute it and modify it under the terms of the GNU
Affero General Public License as published by the Free Software Foundation, either version 3
of the License, or (at your option) any later version. The full text is in [LICENSE](LICENSE).

It is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even
the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

The AGPL is a deliberate choice for this particular program rather than a default. Section 13
means that anyone who modifies Anonyvote and then lets people vote through it over a network
owes those voters the corresponding source. A system whose entire premise is that the voter
need not trust whoever runs it should not be deployable as a closed modification.

That is an obligation, not a proof: the licence cannot demonstrate that the binary serving an
election is the source that was published. Reproducible builds would, and they do not exist
here yet.

## Status

Working end to end and exercised with 1000 voters: blind signatures checked against the
official RFC vectors, threshold key splitting, rate limiting and a reproducible count.

Outstanding before using it for a vote that matters:

- **An outside cryptographic audit.** This was written by one head.
- **Real threshold decryption** (ElGamal with zero-knowledge proofs), so the election key is
  never reconstructed on a single machine. What exists today is key sharing: see
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
- **Rate limiting on the registrar too**, which currently has none.
