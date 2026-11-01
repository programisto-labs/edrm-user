import 'reflect-metadata';
import { beforeEach, describe, it } from 'mocha';
import { expect } from 'chai';
import bcrypt from 'bcrypt';
import { EventEmitter } from 'events';
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
  setPasswordResetDeliveryHandler,
  type PasswordResetDelivery,
  type ResetDeps,
  type ResetUserDoc
} from '../src/modules/user/lib/password-reset.js';

type Doc = ResetUserDoc & { saved: number };

// Minimal in-memory model supporting the filters used by the reset flow.
const makeStore = (now: { t: number }) => {
  const users: Doc[] = [];
  const events: Array<{ event: string; payload: any }> = [];
  const deliveries: PasswordResetDelivery[] = [];
  const deps: ResetDeps = {
    now: () => now.t,
    emit: (event, payload) => { events.push({ event, payload }); },
    deliver: (d) => { deliveries.push(d); },
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
  return { deps, events, deliveries, add };
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
    const clear = store.deliveries[0].resetToken;
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
    const clear = store.deliveries[0].resetToken;

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
    const clear = store.deliveries[0].resetToken;
    expect((await resetPassword(store.deps, 'ip', u.resetToken, 'NewPass1!')).status).to.equal(400);
    now.t += RESET_TOKEN_TTL_MS + 1;
    expect((await resetPassword(store.deps, 'ip', clear, 'NewPass1!')).status).to.equal(400);
  });

  it('keeps an already bcrypt-hashed password as-is', async () => {
    const u = store.add('known@example.com');
    await requestPasswordReset(store.deps, 'ip', 'known@example.com');
    const hashed = await bcrypt.hash('Already1!', 4);
    await resetPassword(store.deps, 'ip', store.deliveries[0].resetToken, hashed);
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

  describe('#1992 token never broadcast', () => {
    const makeBus = () => {
      // Same shape as endurance's emitter: named listeners + onAny-style global listeners.
      const bus = new EventEmitter();
      const seen: string[] = [];
      const origEmit = bus.emit.bind(bus);
      bus.emit = ((event: string, ...args: unknown[]) => {
        seen.push(JSON.stringify([event, ...args]));
        return origEmit(event, ...args);
      }) as typeof bus.emit;
      bus.on('passwordResetRequested', (p) => seen.push(JSON.stringify(p)));
      return { bus, seen };
    };

    it('global payload carries only userId, entityId and expiresAt; the handler alone gets the token', async () => {
      const { bus, seen } = makeBus();
      const got: PasswordResetDelivery[] = [];
      const unregister = setPasswordResetDeliveryHandler((d) => { got.push(d); });
      try {
        store.add('known@example.com', { _id: 'u1', entityId: 'e1', password: '$2b$10$hashhashhash' } as any);
        const deps: ResetDeps = { ...store.deps, deliver: undefined, emit: (e, p) => { bus.emit(e, p); } };
        await requestPasswordReset(deps, 'ip', 'known@example.com');
        expect(got).to.have.length(1);
        const token = got[0].resetToken;
        expect(token).to.match(/^[0-9a-f]{64}$/);
        expect(got[0].user.email).to.equal('known@example.com');
        const ev = JSON.parse(seen[0])[1];
        expect(Object.keys(ev).sort()).to.deep.equal(['entityId', 'expiresAt', 'userId']);
        expect(ev.userId).to.equal('u1');
        expect(ev.entityId).to.equal('e1');
        for (const line of seen) {
          expect(line).not.to.include(token);
          expect(line).not.to.include(hashResetToken(token));
          expect(line).not.to.include('$2b$10$');
        }
      } finally {
        unregister();
      }
    });

    it('no handler: no token anywhere, generic response, warning without secrets', async () => {
      const { bus, seen } = makeBus();
      store.add('known@example.com');
      const warn = console.warn;
      const logs: string[] = [];
      console.warn = (...a: unknown[]) => { logs.push(a.join(' ')); };
      try {
        const res = await requestPasswordReset({ ...store.deps, deliver: undefined, emit: (e, p) => { bus.emit(e, p); } }, 'ip', 'known@example.com');
        expect(res.body.message).to.equal(GENERIC_RESET_MESSAGE);
      } finally {
        console.warn = warn;
      }
      expect(logs.join('')).to.include('no delivery handler');
      for (const line of [...seen, ...logs]) expect(line).not.to.match(/[0-9a-f]{64}/);
    });

    it('a throwing handler is logged generically and does not change the response', async () => {
      store.add('known@example.com');
      const err = console.error;
      const logs: string[] = [];
      console.error = (...a: unknown[]) => { logs.push(a.map(String).join(' ')); };
      let token = '';
      try {
        const res = await requestPasswordReset({ ...store.deps, deliver: (d) => { token = d.resetToken; throw new Error(`smtp ${d.resetToken}`); } }, 'ip', 'known@example.com');
        expect(res.status).to.equal(200);
      } finally {
        console.error = err;
      }
      expect(token).to.have.length(64);
      expect(logs.join('')).not.to.include(token);
    });
  });
});
