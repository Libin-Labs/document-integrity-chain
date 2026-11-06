import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createIntegrityChain, verifyIntegrityChain } from '../dist/esm/index.js';

test('appends and verifies an ordered SHA-256 chain over exact payload bytes', async () => {
  const chain = createIntegrityChain(webcrypto.subtle);
  await chain.append(new Uint8Array([1, 2]), 100);
  await chain.append(new Uint8Array([3, 4]), 101);
  const entries = chain.entries();
  assert.equal(entries[0].previousHash, '0'.repeat(64));
  assert.equal(entries[1].previousHash, entries[0].hash);
  assert.deepEqual(await verifyIntegrityChain(entries, webcrypto.subtle), {
    valid: true,
    verifiedEntries: 2,
  });
});

test('detects changed payloads, timestamps, order and links', async () => {
  const chain = createIntegrityChain(webcrypto.subtle);
  await chain.append(new Uint8Array([1]), 10);
  await chain.append(new Uint8Array([2]), 11);
  const changed = chain.entries();
  changed[0].payload[0] = 9;
  assert.equal((await verifyIntegrityChain(changed, webcrypto.subtle)).valid, false);
  const reordered = chain.entries().reverse();
  assert.equal((await verifyIntegrityChain(reordered, webcrypto.subtle)).valid, false);
});

test('enforces input bounds and strictly increasing append availability', async () => {
  const chain = createIntegrityChain(webcrypto.subtle);
  await chain.append(new Uint8Array([1]), 20);
  await assert.rejects(chain.append(new Uint8Array([2]), 19), /nondecreasing/);
  await assert.rejects(chain.append(new Uint8Array(1_000_001), 21), /1 MiB/);
  assert.equal((await verifyIntegrityChain([], webcrypto.subtle)).valid, true);
});
