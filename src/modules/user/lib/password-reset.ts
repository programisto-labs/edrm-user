import crypto from 'crypto';
import bcrypt from 'bcrypt';

export const GENERIC_RESET_MESSAGE = 'If an account exists for this email, a password reset link has been sent.';
export const RESET_TOKEN_TTL_MS = 20 * 60 * 1000;
export const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
export const REQUEST_RESET_MAX_PER_IP = 10;
export const REQUEST_RESET_MAX_PER_EMAIL = 5;
export const RESET_PASSWORD_MAX_PER_IP = 10;
export const RESET_PASSWORD_MAX_PER_TOKEN = 5;

export const hashResetToken = (token: string): string =>
  crypto.createHash('sha256').update(token).digest('hex');

export const generateResetToken = (): string => crypto.randomBytes(32).toString('hex');

const escapeRegex = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Mongo filter matching an email case-insensitively and exactly (no partial match). */
export const emailFilter = (email: string) => ({
  email: { $regex: `^${escapeRegex(email.trim())}$`, $options: 'i' }
});

export const normalizeEmail = (email: unknown): string | null =>
  typeof email === 'string' && email.trim() ? email.trim().toLowerCase() : null;

export const hashPasswordIfNeeded = async (password: string): Promise<string> =>
  password.startsWith('$2') ? password : bcrypt.hash(password, 10);

/** Fixed-window in-memory limiter. hit() returns false once the key exceeds max in the window. */
export class RateLimiter {
  private hits = new Map<string, { count: number; resetAt: number }>();

  private max: number;
  private windowMs: number;
  private now: () => number;

  constructor (max: number, windowMs: number = RATE_LIMIT_WINDOW_MS, now: () => number = Date.now) {
    this.max = max;
    this.windowMs = windowMs;
    this.now = now;
  }

  hit (key: string): boolean {
    const t = this.now();
    const entry = this.hits.get(key);
    if (!entry || entry.resetAt <= t) {
      this.hits.set(key, { count: 1, resetAt: t + this.windowMs });
      if (this.hits.size > 10000) this.prune(t);
      return true;
    }
    entry.count += 1;
    return entry.count <= this.max;
  }

  reset (): void {
    this.hits.clear();
  }

  private prune (t: number): void {
    for (const [k, v] of this.hits) if (v.resetAt <= t) this.hits.delete(k);
  }
}

export const limiters = {
  requestPerIp: new RateLimiter(REQUEST_RESET_MAX_PER_IP),
  requestPerEmail: new RateLimiter(REQUEST_RESET_MAX_PER_EMAIL),
  resetPerIp: new RateLimiter(RESET_PASSWORD_MAX_PER_IP),
  resetPerToken: new RateLimiter(RESET_PASSWORD_MAX_PER_TOKEN)
};

export interface ResetUserDoc {
  email: string;
  password?: string;
  resetToken?: string | null;
  resetTokenExpiration?: Date | null;
  refreshToken?: string | null;
  save: () => Promise<unknown>;
}

/** Internal-only delivery input: carries the clear token, never broadcast on the event bus. */
export interface PasswordResetDelivery {
  user: ResetUserDoc;
  resetToken: string;
  expiresAt: Date;
}

export type PasswordResetDeliveryHandler = (delivery: PasswordResetDelivery) => void | Promise<void>;

/** Global (broadcast) payload of passwordResetRequested: no token, no password hash. */
export interface PasswordResetRequestedEvent {
  userId: string | null;
  entityId: string | null;
  expiresAt: Date;
}

let deliveryHandler: PasswordResetDeliveryHandler | null = null;

/**
 * Registers the single in-process handler (e.g. the host app's mailer) that receives the clear
 * reset token. Direct function call: listeners on the event bus (webhooks, distributed events,
 * onAny) never see the token. Returns an unregister function.
 */
export function setPasswordResetDeliveryHandler (handler: PasswordResetDeliveryHandler | null): () => void {
  deliveryHandler = handler;
  return () => { if (deliveryHandler === handler) deliveryHandler = null; };
}

export interface ResetDeps {
  findOne: (filter: Record<string, unknown>) => Promise<ResetUserDoc | null>;
  emit: (event: string, payload: unknown) => void;
  now?: () => number;
  /** Overrides the registered delivery handler (tests). */
  deliver?: PasswordResetDeliveryHandler;
}

const idOf = (v: unknown): string | null => (v === undefined || v === null || v === '' ? null : String(v));

async function deliverResetToken (deps: ResetDeps, delivery: PasswordResetDelivery): Promise<void> {
  const handler = deps.deliver ?? deliveryHandler;
  if (!handler) {
    console.warn('[edrm-user] password reset requested but no delivery handler is registered; no email sent.');
    return;
  }
  try {
    await handler(delivery);
  } catch {
    // Generic message only: the error may carry the token or the link.
    console.error('[edrm-user] password reset delivery handler failed.');
  }
}

export type ResetResult = { status: number; body: { message: string } };

const tooMany: ResetResult = { status: 429, body: { message: 'Too many requests, please try again later.' } };

/**
 * Generates a single-use token, stores only its sha256, hands the clear token to the internal
 * delivery handler, emits passwordResetRequested WITHOUT the token, and always answers the same generic 200.
 */
export async function requestPasswordReset (deps: ResetDeps, ip: string, rawEmail: unknown): Promise<ResetResult> {
  const email = normalizeEmail(rawEmail);
  if (!limiters.requestPerIp.hit(`ip:${ip}`)) return tooMany;
  if (email && !limiters.requestPerEmail.hit(`email:${email}`)) return tooMany;

  const generic: ResetResult = { status: 200, body: { message: GENERIC_RESET_MESSAGE } };
  if (!email) return generic;

  const user = await deps.findOne(emailFilter(email));
  if (!user) return generic;

  const now = (deps.now ?? Date.now)();
  const resetToken = generateResetToken();
  user.resetToken = hashResetToken(resetToken);
  user.resetTokenExpiration = new Date(now + RESET_TOKEN_TTL_MS);
  await user.save();

  const expiresAt = user.resetTokenExpiration;
  await deliverResetToken(deps, { user, resetToken, expiresAt });
  const anyUser = user as unknown as { _id?: unknown; id?: unknown; entityId?: unknown };
  const event: PasswordResetRequestedEvent = {
    userId: idOf(anyUser._id ?? anyUser.id),
    entityId: idOf(anyUser.entityId),
    expiresAt
  };
  deps.emit('passwordResetRequested', event);
  return generic;
}

/** Looks the token up by its hash, hashes the new password, clears the token and the refresh token. */
export async function resetPassword (deps: ResetDeps, ip: string, rawToken: unknown, newPassword: unknown): Promise<ResetResult> {
  if (!limiters.resetPerIp.hit(`ip:${ip}`)) return tooMany;
  const invalid: ResetResult = { status: 400, body: { message: 'Invalid or expired reset token' } };
  if (typeof rawToken !== 'string' || !rawToken) return invalid;
  const tokenHash = hashResetToken(rawToken);
  if (!limiters.resetPerToken.hit(`token:${tokenHash}`)) return tooMany;
  if (typeof newPassword !== 'string' || newPassword.length < 8) {
    return { status: 400, body: { message: 'New password must be at least 8 characters' } };
  }

  const now = (deps.now ?? Date.now)();
  const user = await deps.findOne({ resetToken: tokenHash, resetTokenExpiration: { $gt: new Date(now) } });
  if (!user) return invalid;

  user.password = await hashPasswordIfNeeded(newPassword);
  user.resetToken = undefined;
  user.resetTokenExpiration = undefined;
  user.refreshToken = undefined;
  await user.save();

  deps.emit('passwordReset', user);
  return { status: 200, body: { message: 'Password has been reset successfully' } };
}
