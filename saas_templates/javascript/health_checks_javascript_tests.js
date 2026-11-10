const { test } = require('node:test');
const assert = require('node:assert/strict');
const { HealthCheckError, InMemoryCheckStore, HealthChecker } = require('./health_checks_javascript.js');

const FIXED_CLOCK = () => 1767225600000;
const FIXED_TIME = '2026-01-01T00:00:00Z';

function makeChecker() {
  return new HealthChecker(new InMemoryCheckStore(), { clock: FIXED_CLOCK });
}

// HEALTH-01
test('all checks pass returns 200 pass', async () => {
  const checker = makeChecker();
  checker.registerCheck('db', 'datastore', () => true, true, 5000);
  checker.registerCheck('cache', 'component', () => true, false, 5000);
  const res = await checker.readiness();
  assert.strictEqual(res.http_status, 200);
  assert.strictEqual(res.content_type, 'application/health+json');
  const expected = `{"status":"pass","checks":{"cache:responseTime":[{"componentId":"cache","componentType":"component","observedValue":0,"observedUnit":"ms","status":"pass","time":"${FIXED_TIME}"}],"db:responseTime":[{"componentId":"db","componentType":"datastore","observedValue":0,"observedUnit":"ms","status":"pass","time":"${FIXED_TIME}"}]}}`;
  assert.strictEqual(res.body, expected);
});

// HEALTH-02
test('critical check fails returns 503 fail', async () => {
  const checker = makeChecker();
  checker.registerCheck('db', 'datastore', () => false, true, 5000);
  checker.registerCheck('cache', 'component', () => true, false, 5000);
  const res = await checker.readiness();
  assert.strictEqual(res.http_status, 503);
  assert.strictEqual(res.content_type, 'application/health+json');
  const expected = `{"status":"fail","checks":{"cache:responseTime":[{"componentId":"cache","componentType":"component","observedValue":0,"observedUnit":"ms","status":"pass","time":"${FIXED_TIME}"}],"db:responseTime":[{"componentId":"db","componentType":"datastore","observedValue":0,"observedUnit":"ms","status":"fail","time":"${FIXED_TIME}","output":"check reported failure"}]}}`;
  assert.strictEqual(res.body, expected);
});

// HEALTH-03
test('only non-critical check fails returns 200 warn', async () => {
  const checker = makeChecker();
  checker.registerCheck('db', 'datastore', () => true, true, 5000);
  checker.registerCheck('cache', 'component', () => false, false, 5000);
  const res = await checker.readiness();
  assert.strictEqual(res.http_status, 200);
  assert.strictEqual(res.content_type, 'application/health+json');
  const expected = `{"status":"warn","checks":{"cache:responseTime":[{"componentId":"cache","componentType":"component","observedValue":0,"observedUnit":"ms","status":"fail","time":"${FIXED_TIME}","output":"check reported failure"}],"db:responseTime":[{"componentId":"db","componentType":"datastore","observedValue":0,"observedUnit":"ms","status":"pass","time":"${FIXED_TIME}"}]}}`;
  assert.strictEqual(res.body, expected);
});

// HEALTH-04
test('slow check past timeout fails that check', async () => {
  const checker = makeChecker();
  checker.registerCheck('fast', 'component', () => true, false, 5000);
  checker.registerCheck('slow', 'component', async () => {
    await new Promise(r => setTimeout(r, 1000));
    return true;
  }, true, 100);
  const res = await checker.readiness();
  assert.strictEqual(res.http_status, 503);
  assert.strictEqual(res.content_type, 'application/health+json');
  const expected = `{"status":"fail","checks":{"fast:responseTime":[{"componentId":"fast","componentType":"component","observedValue":0,"observedUnit":"ms","status":"pass","time":"${FIXED_TIME}"}],"slow:responseTime":[{"componentId":"slow","componentType":"component","observedValue":100,"observedUnit":"ms","status":"fail","time":"${FIXED_TIME}","output":"check timed out"}]}}`;
  assert.strictEqual(res.body, expected);
});

// HEALTH-05
test('liveness stays pass when dependency would fail', async () => {
  let counter = 0;
  const checker = makeChecker();
  checker.registerCheck('db', 'datastore', () => { counter++; throw new Error('db down'); }, true, 5000);
  const live = checker.liveness();
  assert.strictEqual(live.http_status, 200);
  assert.strictEqual(live.content_type, 'application/health+json');
  assert.strictEqual(live.body, '{"status":"pass"}');
  assert.strictEqual(counter, 0);
  const ready = await checker.readiness();
  assert.strictEqual(ready.http_status, 503);
  assert.strictEqual(counter, 1);
});

// HEALTH-06
test('output contains no connection string', async () => {
  const checker = makeChecker();
  const connStr = 'postgres://admin:s3cret@db.internal:5432/app';
  checker.registerCheck('db', 'datastore', () => { throw new Error(`connect failed: ${connStr}`); }, true, 5000);
  const res = await checker.readiness();
  assert.strictEqual(res.http_status, 503);
  assert.strictEqual(res.content_type, 'application/health+json');
  const expected = `{"status":"fail","checks":{"db:responseTime":[{"componentId":"db","componentType":"datastore","observedValue":0,"observedUnit":"ms","status":"fail","time":"${FIXED_TIME}","output":"check raised an error"}]}}`;
  assert.strictEqual(res.body, expected);
  assert.ok(!res.body.includes('postgres://'));
  assert.ok(!res.body.includes('s3cret'));
  assert.ok(!res.body.includes('admin'));
  assert.ok(!res.body.includes('5432'));
  const checker2 = makeChecker();
  try {
    checker2.registerCheck('postgres://admin:s3cret@db', 'datastore', () => true, true, 5000);
    assert.fail('should have thrown');
  } catch (e) {
    assert.strictEqual(e.code, 'INVALID_COMPONENT_ID');
    assert.strictEqual(e.http_status, 400);
    assert.ok(!e.message.includes('s3cret'));
  }
});