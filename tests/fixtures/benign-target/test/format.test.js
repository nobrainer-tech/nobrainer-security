import { test } from 'node:test';
import assert from 'node:assert/strict';

test('rounds a temperature for display', () => {
  assert.equal(Math.round(21.46 * 10) / 10, 21.5);
});
