# @lp-labs/document-integrity-chain

Append and verify a local append-only chain of SHA-256 digests. Each digest commits to a version
marker, sequence index, timestamp, prior hash, payload length, and exact payload bytes.

## Install

```bash
npm install @lp-labs/document-integrity-chain
```

No runtime dependencies; includes ESM, CommonJS, and TypeScript declarations.

## Quickstart

```js
import { webcrypto } from 'node:crypto';
import { createIntegrityChain, verifyIntegrityChain } from '@lp-labs/document-integrity-chain';

const chain = createIntegrityChain(webcrypto.subtle);
await chain.append(new TextEncoder().encode('document imported'), Date.now());
const result = await verifyIntegrityChain(chain.entries(), webcrypto.subtle);
if (!result.valid) throw new Error('Integrity chain failed');
```

## API and customization

`createIntegrityChain(subtle?)` returns an in-memory chain with asynchronous
`append(payload, timestamp?)` and detached `entries()` snapshots. `verifyIntegrityChain(entries,
subtle?)` returns `{ valid, verifiedEntries, error? }`; the first malformed link or changed payload
reports the index. `IntegrityEntry`, `IntegrityChain`, and `IntegrityVerification` are type exports.
Supply a WebCrypto SHA-256 provider when the global provider is absent.

Chains allow up to 100,000 entries, payloads up to 1,000,000 bytes each, and 64 MiB aggregate
payload. Timestamps are nonnegative Unix milliseconds and nondecreasing. Appends are serialized by rejecting concurrent attempts; failed
digest calls do not add an entry. Empty chains verify successfully. Input/payload bytes are copied.

## Runtime and scope

Requires WebCrypto SubtleCrypto SHA-256. The chain is local bookkeeping, not a signature, trusted
timestamp, remote audit log, append-only storage guarantee, or proof against an attacker who can
rewrite the whole chain. Protect and anchor the final digest in a separately trusted system when
tamper evidence matters. This does not validate document semantics or certificate trust.

## Exports

Runtime: `createIntegrityChain`, `verifyIntegrityChain`.
Types: `IntegrityEntry`, `IntegrityChain`, `IntegrityVerification`.

## Support

If this library is useful to you, consider supporting its maintenance with a [donation via PayPal](https://www.paypal.me/LibinPrasanth).

## Author

Created by [Libin Prasanth](https://www.linkedin.com/in/libinprasanth/). Connect on LinkedIn for updates and discussion.
