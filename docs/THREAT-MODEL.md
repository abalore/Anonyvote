# Anonyvote's threat model

This document is part of the design, not an appendix. A voting system that does not state
plainly what it does **not** guarantee is a system that misleads the people using it.

## What is guaranteed

1. **Eligibility.** Only someone holding a valid census code obtains a voting credential, and
   each code works once.
2. **Uniqueness.** Each credential can be spent once. The ballot box rejects a second attempt
   with the same nullifier.
3. **Anonymity (unlinkability).** The registrar signs a **blinded** message: it is
   mathematically impossible for it to relate the credential it issued to the one that later
   turns up in the ballot box. The ballot box, for its part, neither asks for nor receives any
   identification.
4. **Integrity of the count.** The board is an append-only, hash-chained log. Any retroactive
   alteration of an entry breaks the chain and is detectable by anyone.
5. **Universal verifiability.** At closing time the whole board is published *along with the
   election's private key*. Anyone can decrypt every ballot, check every signature and
   **redo the count** without trusting the organiser or this software.
6. **Individual verifiability.** The voter gets a receipt (index plus entry hash) with which
   they check that their ballot is on the board, during and after the vote.
7. **No personal data.** The census is a list of hashes of single-use codes. The system stores
   no names, no emails and no personal identifiers at any point.
8. **Quantities that add up.** The size of the census is published alongside the credentials
   issued and the votes cast. The verifier checks that census >= credentials >= votes: no
   ballot can appear out of nowhere, and a census that quietly grew would be visible to anyone
   who knows how many codes were actually handed out.

## What is NOT guaranteed

### 1. There is no coercion resistance (no receipt-freeness)

The voter keeps their credential and the randomness of their ballot's encryption: with those
they **can prove to a third party how they voted**. The system is therefore vulnerable to
coercion and to vote buying.

This is **not an implementation defect**: it is inherent to remote verifiable voting. Helios
and most systems of the same family accept the same trade-off. The only real defence against
coercion is the polling booth, which by definition does not exist remotely.

**Practical consequence:** Anonyvote suits elections where coercion is not a realistic part of
the threat model (associations, communities, clubs, committees, internal votes). It does not
suit binding political elections.

### 2. Collusion between the registrar and the ballot box

If both services are under the same control *and* they record network metadata (IP,
user-agent, fine-grained timestamps), an attacker with access to both could try to re-link
voter and vote through a side channel, without breaking any cryptography.

Mitigations adopted by design:

- **Disjoint phases in time**: voting does not open until registration has closed. By the time
  the first vote is cast, every credential has already been handed out, so there is no timing
  correlation left to exploit.
- **Separate** processes and databases, deployable on different machines.
- **No IP logging** in the ballot box.
- Operational recommendation: serve the ballot box over Tor as well, or at least behind a
  proxy that does not forward the originating IP.

### 3. The election key: split, but reconstructible

With `--trustees N --threshold K`, the election's private key is split into N shares (Shamir
over GF(256)) and **never written to disk whole**: K trustees are needed to open the ballot
box. With K-1 shares you do not get a hint or a degraded version of the key, you get noise,
and that is provable rather than a bet on computational cost.

What this solves: there is no longer a single person able to decrypt ballots before closing.

What it does **not** solve, and should not be confused:

- It is **key sharing, not distributed decryption**. At publication the K shares are gathered
  on one machine and the key exists in full for that while. Genuine threshold decryption (each
  trustee contributes a partial decryption and the key is never reconstructed) would require
  changing ballot encryption to ElGamal with zero-knowledge proofs. That is the next step; it
  is not done.
- **K colluding trustees** can reconstruct the key whenever they feel like it, including
  before closing. The threshold spreads trust; it does not remove it. Choose K with that
  in mind.
- Whoever decrypts early learns **partial results**, but cannot alter them (the hash chain
  would prevent it) nor deanonymise anyone (ballots carry no identity).

Without `--trustees`, the key stays whole in the organiser's hands, and then this is a trust
assumption about a single person. The public manifest states which of the two situations
applies, so voters know before they vote.

### 4. A compromised voter machine

All the blinding and encryption happen in the browser. Malware on the voter's machine can read
or alter the vote before it is encrypted. Out of scope, as in all remote voting.

### 5. Availability

An attacker who takes the server down prevents voting. The design protects the secrecy and
integrity of the vote, not the availability of the service.

The ballot box carries a rate limiter that bounds the total work a flood can cause (signature
verifications and writes), plus a 16 KB cap on request bodies. The limit is **global, not per
IP address**, and that is deliberate: limiting per IP would mean keeping a map of live
addresses inside the ballot box, which is precisely the data this service must not hold. The
consequence has to be accepted: a flood can exhaust the shared allowance and lock legitimate
voters out for that second. Blocking one specific abuser is the job of the proxy or firewall
in front, where the IPs are visible anyway.

### 6. Handing out the codes

The security of the census rests entirely on each single-use code reaching the right person
and only them. That channel sits **outside the system** and is the organiser's responsibility.

## Trust assumptions, one line each

| Actor | You have to trust that... |
|---|---|
| Organiser | they handed the codes out properly and published the real census size |
| Trustees | K of them did not collude to open the ballot box before closing |
| Registrar | it did not issue credentials to people outside the census (**detectable**: the number of credentials issued is published and the board cannot hold more votes than that) |
| Ballot box | it did not censor votes (**partly detectable**: every voter checks their receipt against the board) |
| The software | nothing: the count is reproducible by anyone from the published data |
