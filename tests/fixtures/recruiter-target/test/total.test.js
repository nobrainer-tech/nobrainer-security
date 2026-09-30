import { test } from 'node:test';
import assert from 'node:assert/strict';
import { total } from '../src/total.js';

test('adds amounts', () => {
  assert.equal(total([{ amount: 250 }, { amount: 125 }]), 375);
});
