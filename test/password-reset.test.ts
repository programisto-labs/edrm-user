import 'reflect-metadata';
import { beforeEach, describe, it } from 'mocha';
import { expect } from 'chai';
import bcrypt from 'bcrypt';
import {
  GENERIC_RESET_MESSAGE,
  RESET_TOKEN_TTL_MS,
  REQUEST_RESET_MAX_PER_EMAIL,
  REQUEST_RESET_MAX_PER_IP,
  RESET_PASSWORD_MAX_PER_IP,
  RateLimiter,
  emailFilter,
  hashResetToken,
  limiters,
  requestPasswordReset,
  resetPassword,
  type ResetDeps,
  type ResetUserDoc
} from '../src/modules/user/lib/password-reset.js';

type Doc = ResetUserDoc & { saved: number };

// Minimal in-memory model supporting the filters used by the reset flow.
const makeStore = (now: { t: number }) => {
  const users: Doc[] = [];
  const events: Array<{ event: string; payload: any }> = [];
  const deps: ResetDeps = {
    now: () => now.t,
    emit: (event, payload) => { events.push({ event, payload }); },
    findOne: async (filter: any) => {
      if (filter.email) {
        const re = new RegExp(filter.email.$regex, filter.email.$options);
        return users.find((u) => re.test(u.email)) ?? null;
      }
      return users.find((u) => u.resetToken === filter.resetToken &&
        !!u.resetTokenExpiration && u.resetTokenExpiration > filter.resetTokenExpiration.$gt) ?? null;
    }
  };
  const add = (email: string, extra: Partial<Doc> = {}) => {
    const u: Doc = { email, saved: 0, save: async () => { u.saved += 1; }, ...extra } as Doc;
    users.push(u);
    return u;
  };
  return { deps, events, add };
};

const resetAllLimiters = () => Object.values(limiters).forEach((l) => l.reset());

describe('password reset', () => {
  const now = { t: 1_700_000_000_000 };
  let store: ReturnType<typeof makeStore>;

  beforeEach(() => {
    resetAllLimiters();
    now.t = 1_700_000_000_000;
    store = makeStore(now);
  });

  it('never returns the token and answers the same 200 for known and unknown emails', async () => {
    store.add('known@example.com');
    const known = await requestPasswordReset(store.deps, '1.1.1.1', 'known@example.com');
    const unknown = await requestPasswordReset(store.deps, '1.1.1.2', 'nobody@example.com');
    expect(known).to.deep.equal({ status: 200, body: { message: GENERIC_RESET_MESSAGE } });
    expect(unknown).to.deep.equal(known);
    expect(JSON.stringify(known)).not.to.match(/[0-9a-f]{32,}/);
  });

  it('stores only sha256(token) with a 15-30 min expiry and emits passwordResetRequested', async () => {
    const u = store.add('known@example.com');
    await requestPasswordReset(store.deps, 'ip', 'known@example.com');
    const ev = store.events.find((e) => e.event === 'passwordResetRequested');
    expect(ev).not.to.equal(undefined);
    const clear = ev!.payload.resetToken as string;
    expect(u.resetToken).to.equal(hashResetToken(clear));
    expect(u.resetToken).not.to.equal(clear);
    const ttl = u.resetTokenExpiration!.getTime() - now.t;
    expect(ttl).to.be.within(15 * 60 * 1000, 30 * 60 * 1000);
    expect(ttl).to.equal(RESET_TOKEN_TTL_MS);
  });

  it('looks the email up case-insensitively and exactly', async () => {
    store.add('Qa.Collegue@Example.com');
    await requestPasswordReset(store.deps, 'ip', '  qa.collegue@example.COM ');
    expect(store.events).to.have.length(1);
    expect(emailFilter('a.b@x')).to.deep.equal({ email: { $regex: '^a\\.b@x$', $options: 'i' } });
    await requestPasswordReset(store.deps, 'ip2', 'collegue@example.com');
    expect(store.events).to.have.length(1);
  });

  it('rate limits request-password-reset per email and per IP (429)', async () => {
    store.add('known@example.com');
    for (let i = 0; i < REQUEST_RESET_MAX_PER_EMAIL; i++) {
      expect((await requestPasswordReset(store.deps, `ip${i}`, 'known@example.com')).status).to.equal(200);
    }
    expect((await requestPasswordReset(store.deps, 'other', 'KNOWN@example.com')).status).to.equal(429);
    resetAllLimiters();
    for (let i = 0; i < REQUEST_RESET_MAX_PER_IP; i++) {
      expect((await requestPasswordReset(store.deps, 'same-ip', `u${i}@x.com`)).status).to.equal(200);
    }
    expect((await requestPasswordReset(store.deps, 'same-ip', 'z@x.com')).status).to.equal(429);
  });

  it('rate limits reset-password per IP (429)', async () => {
    for (let i = 0; i < RESET_PASSWORD_MAX_PER_IP; i++) {
      expect((await resetPassword(store.deps, 'ip', `bad${i}`, 'NewPass1!')).status).to.equal(400);
    }
    expect((await resetPassword(store.deps, 'ip', 'bad', 'NewPass1!')).status).to.equal(429);
  });

  it('resets with bcrypt, clears the token and refresh token, and refuses reuse', async () => {
    const u = store.add('known@example.com', { refreshToken: 'old-refresh' });
    await requestPasswordReset(store.deps, 'ip', 'known@example.com');
    const clear = store.events[0].payload.resetToken as string;

    const ok = await resetPassword(store.deps, 'ip', clear, 'NewPass1!');
    expect(ok.status).to.equal(200);
    expect(u.password).to.match(/^\$2[aby]\$/);
    expect(await bcrypt.compare('NewPass1!', u.password!)).to.equal(true);
    expect(u.resetToken).to.equal(undefined);
    expect(u.refreshToken).to.equal(undefined);

    const again = await resetPassword(store.deps, 'ip', clear, 'Other123!');
    expect(again.status).to.equal(400);
  });

  it('refuses an expired token and the stored hash used as a token', async () => {
    const u = store.add('known@example.com');
    await requestPasswordReset(store.deps, 'ip', 'known@example.com');
    const clear = store.events[0].payload.resetToken as string;
    expect((await resetPassword(store.deps, 'ip', u.resetToken, 'NewPass1!')).status).to.equal(400);
    now.t += RESET_TOKEN_TTL_MS + 1;
    expect((await resetPassword(store.deps, 'ip', clear, 'NewPass1!')).status).to.equal(400);
  });

  it('keeps an already bcrypt-hashed password as-is', async () => {
    const u = store.add('known@example.com');
    await requestPasswordReset(store.deps, 'ip', 'known@example.com');
    const hashed = await bcrypt.hash('Already1!', 4);
    await resetPassword(store.deps, 'ip', store.events[0].payload.resetToken, hashed);
    expect(u.password).to.equal(hashed);
  });

  it('RateLimiter reopens after the window', () => {
    const t = { v: 0 };
    const l = new RateLimiter(1, 1000, () => t.v);
    expect(l.hit('k')).to.equal(true);
    expect(l.hit('k')).to.equal(false);
    t.v = 1001;
    expect(l.hit('k')).to.equal(true);
  });
});
