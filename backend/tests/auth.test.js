import test from 'node:test';
import assert from 'node:assert/strict';
import { generateOtp, hashOtp, isOtpFormat, maskEmail } from '../src/utils/otp.js';
import { passwordProblems, hashPassword, verifyPassword } from '../src/utils/password.js';
import { keyedHash, randomToken, safeEqual, sha256, signAccessToken, verifyAccessToken } from '../src/utils/token.js';
import { describeDevice, parseCookies } from '../src/utils/http.js';
import { csrfProtection } from '../src/middlewares/csrf.middleware.js';
import { renderTemplateString } from '../src/services/email.service.js';
import { loginSchema, inviteUserSchema } from '../src/validators/auth.validator.js';
import { verifyOtpSchema } from '../src/validators/otp.validator.js';
import { changePasswordSchema } from '../src/validators/password.validator.js';
import { SignJWT } from 'jose';
import { config } from '../src/config/index.js';

test('OTPs are 6 digits, uniformly generated and hashed with a server key bound to the challenge', () => {
  const codes = new Set(Array.from({ length: 2000 }, generateOtp));
  for (const code of codes) assert.ok(isOtpFormat(code));
  assert.ok(codes.size > 1900, 'codes should not repeat often');
  assert.notEqual(hashOtp('a', '123456'), hashOtp('b', '123456'));
  assert.equal(hashOtp('a', '123456'), keyedHash('a:123456'));
  assert.ok(!hashOtp('a', '123456').includes('123456'));
  assert.equal(isOtpFormat('12345'), false);
  assert.equal(isOtpFormat('12345a'), false);
});

test('email addresses are masked in API responses', () => {
  assert.equal(maskEmail('jane.doe@example.com'), 'j******e@example.com');
  assert.equal(maskEmail('al@example.com'), 'a@example.com');
});

test('password policy enforces length, character classes, identity and common passwords', () => {
  assert.deepEqual(passwordProblems('Corr3ct-Horse-Battery!'), []);
  assert.ok(passwordProblems('Short1!').includes('be at least 12 characters long'));
  assert.ok(passwordProblems('alllowercase123!').includes('include an uppercase letter'));
  assert.ok(passwordProblems('NoDigitsHere!!x').includes('include a number'));
  assert.ok(passwordProblems('NoSpecials12345').includes('include a special character'));
  assert.ok(passwordProblems('Jsmith-Secure-99!', { username: 'jsmith' }).includes('not contain your username or email'));
  assert.ok(passwordProblems('Password1234!').includes('not be a commonly used password'));
  assert.ok(passwordProblems('Welcome12345#').includes('not be a commonly used password'));
  assert.ok(passwordProblems('Aaaaa1!bcdefgh').includes('not repeat a character 4 or more times in a row'));
});

test('passwords are stored as Argon2id hashes', async () => {
  const hash = await hashPassword('Corr3ct-Horse-Battery!');
  assert.match(hash, /^\$argon2id\$/);
  assert.equal(await verifyPassword(hash, 'Corr3ct-Horse-Battery!'), true);
  assert.equal(await verifyPassword(hash, 'wrong'), false);
  assert.equal(await verifyPassword(null, 'x'), false);
});

test('access tokens carry the session id and require the access audience', async () => {
  const token = await signAccessToken({ id: 7 }, 42);
  const payload = await verifyAccessToken(token);
  assert.equal(payload.sub, '7');
  assert.equal(payload.sid, '42');
  const foreign = await new SignJWT({ rid: '1' }).setProtectedHeader({ alg: 'HS256' }).setAudience('report-download').setExpirationTime('1h').sign(new TextEncoder().encode(config.secret));
  await assert.rejects(verifyAccessToken(foreign), /Invalid session/);
  const expired = await new SignJWT({ sid: '1' }).setProtectedHeader({ alg: 'HS256' }).setSubject('1').setAudience('siem-access').setIssuedAt(1).setExpirationTime(2).sign(new TextEncoder().encode(config.secret));
  await assert.rejects(verifyAccessToken(expired), (error) => error.code === 'TOKEN_EXPIRED');
});

test('random tokens and constant-time comparison', () => {
  assert.ok(randomToken().length >= 43);
  assert.notEqual(randomToken(), randomToken());
  assert.equal(sha256('x').length, 64);
  assert.equal(safeEqual('abc', 'abc'), true);
  assert.equal(safeEqual('abc', 'abd'), false);
  assert.equal(safeEqual('abc', 'abcd'), false);
});

function fakeReqRes({ method = 'POST', cookie = '', headers = {} }) {
  const res = { statusCode: 200, body: null, cookies: [], cookie(name, value) { this.cookies.push([name, value]); }, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
  return { req: { method, headers: { cookie, ...headers } }, res };
}

test('CSRF: state-changing cookie requests need a matching header; bearer-only clients are exempt', () => {
  let passed = 0;
  const next = () => { passed += 1; };
  const token = 'A'.repeat(40);
  let { req, res } = fakeReqRes({ cookie: `siem_at=x; siem_csrf=${token}` });
  csrfProtection(req, res, next);
  assert.equal(res.statusCode, 403);
  ({ req, res } = fakeReqRes({ cookie: `siem_at=x; siem_csrf=${token}`, headers: { 'x-csrf-token': token } }));
  csrfProtection(req, res, next);
  assert.equal(passed, 1);
  ({ req, res } = fakeReqRes({ cookie: `siem_at=x; siem_csrf=${token}`, headers: { 'x-csrf-token': 'B'.repeat(40) } }));
  csrfProtection(req, res, next);
  assert.equal(res.statusCode, 403);
  ({ req, res } = fakeReqRes({ headers: { authorization: 'Bearer abc' } }));
  csrfProtection(req, res, next);
  assert.equal(passed, 2);
  ({ req, res } = fakeReqRes({ method: 'GET' }));
  csrfProtection(req, res, next);
  assert.equal(passed, 3);
  assert.equal(res.cookies[0][0], 'siem_csrf');
});

test('cookie parsing and device description', () => {
  assert.deepEqual(parseCookies('a=1; b=hello%20world;bad'), { a: '1', b: 'hello world' });
  assert.equal(describeDevice('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36'), 'Chrome on Windows');
  assert.equal(describeDevice('Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Version/17.0 Safari/605.1.15'), 'Safari on macOS');
});

test('email templates escape values unless explicitly raw', () => {
  const out = renderTemplateString('<p>{{name}}</p>{{{html}}}{{#show}}yes{{/show}}{{#hide}}no{{/hide}}', { name: '<script>', html: '<b>x</b>', show: true, hide: '' });
  assert.equal(out, '<p>&lt;script&gt;</p><b>x</b>yes');
});

test('auth request validation', () => {
  assert.equal(loginSchema.safeParse({ identifier: 'admin', password: 'x' }).success, true);
  assert.equal(loginSchema.safeParse({ identifier: '', password: 'x' }).success, false);
  assert.equal(verifyOtpSchema.safeParse({ challenge_id: '3b241101-e2bb-4255-8caf-4136c566a962', otp: '012345' }).success, true);
  assert.equal(verifyOtpSchema.safeParse({ challenge_id: 'nope', otp: '012345' }).success, false);
  assert.equal(changePasswordSchema.safeParse({ current_password: 'a', new_password: 'b', confirm_password: 'c' }).success, false);
  assert.equal(inviteUserSchema.safeParse({ full_name: 'Jane', email: 'jane@example.com', username: 'jane', role: 'SOC Analyst' }).success, true);
  assert.equal(inviteUserSchema.safeParse({ full_name: 'Jane', email: 'jane@example.com', username: 'ja ne', role: 'SOC Analyst' }).success, false);
});
