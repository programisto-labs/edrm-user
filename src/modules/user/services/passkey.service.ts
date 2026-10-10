import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse
} from '@simplewebauthn/server';
import { Buffer } from 'buffer';
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
  WebAuthnCredential
} from '@simplewebauthn/server';
import type { PasskeyCredentialType } from '../types/user.js';

export const PASSKEY_CHALLENGE_TTL_MS = 5 * 60 * 1000;

export type PasskeyUser = {
  _id: { toString(): string };
  email: string;
  firstname: string;
  lastname: string;
  passkeys?: PasskeyCredentialType[];
};

export function getPasskeyConfig(): { rpID: string; rpName: string; origin: string } {
  const rpID = process.env.PASSKEY_RP_ID?.trim();
  const origin = process.env.PASSKEY_ORIGIN?.trim();
  const rpName = process.env.PASSKEY_RP_NAME?.trim() || 'Endurance';

  if (!rpID || !origin) {
    throw new Error('PASSKEY_RP_ID and PASSKEY_ORIGIN must be configured');
  }

  let parsedOrigin: URL;
  try {
    parsedOrigin = new URL(origin);
  } catch {
    throw new Error('PASSKEY_ORIGIN must be a valid origin URL');
  }

  if (parsedOrigin.origin !== origin || (parsedOrigin.protocol !== 'https:' && parsedOrigin.hostname !== 'localhost')) {
    throw new Error('PASSKEY_ORIGIN must be an HTTPS origin (HTTP is only allowed for localhost)');
  }

  if (rpID.includes('://') || (parsedOrigin.hostname !== rpID && !parsedOrigin.hostname.endsWith(`.${rpID}`))) {
    throw new Error('PASSKEY_RP_ID must be the origin hostname or one of its parent domains');
  }

  return { rpID, rpName, origin };
}

export async function createPasskeyRegistrationOptions(user: PasskeyUser) {
  const { rpID, rpName } = getPasskeyConfig();

  return generateRegistrationOptions({
    rpID,
    rpName,
    userID: Buffer.from(user._id.toString(), 'utf8'),
    userName: user.email,
    userDisplayName: `${user.firstname} ${user.lastname}`.trim(),
    attestationType: 'none',
    excludeCredentials: (user.passkeys || []).map(passkey => ({
      id: passkey.credentialId,
      transports: passkey.transports
    })),
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'required'
    }
  });
}

export async function verifyPasskeyRegistration(
  response: RegistrationResponseJSON,
  expectedChallenge: string,
  name?: string
): Promise<PasskeyCredentialType> {
  const { rpID, origin } = getPasskeyConfig();
  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    requireUserVerification: true
  });

  if (!verification.verified || !verification.registrationInfo) {
    throw new Error('Passkey registration could not be verified');
  }

  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
  return {
    credentialId: credential.id,
    publicKey: Buffer.from(credential.publicKey).toString('base64url'),
    counter: credential.counter,
    transports: credential.transports,
    deviceType: credentialDeviceType,
    backedUp: credentialBackedUp,
    name: name?.trim().slice(0, 100) || undefined,
    createdAt: new Date()
  };
}

export async function createPasskeyAuthenticationOptions(passkeys: PasskeyCredentialType[]) {
  const { rpID } = getPasskeyConfig();

  return generateAuthenticationOptions({
    rpID,
    allowCredentials: passkeys.map(passkey => ({
      id: passkey.credentialId,
      transports: passkey.transports
    })),
    userVerification: 'required'
  });
}

export async function verifyPasskeyAuthentication(
  response: AuthenticationResponseJSON,
  expectedChallenge: string,
  passkey: PasskeyCredentialType
): Promise<number> {
  const { rpID, origin } = getPasskeyConfig();
  const credential: WebAuthnCredential = {
    id: passkey.credentialId,
    publicKey: new Uint8Array(Buffer.from(passkey.publicKey, 'base64url')),
    counter: passkey.counter,
    transports: passkey.transports
  };
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    credential,
    requireUserVerification: true
  });

  if (!verification.verified) {
    throw new Error('Passkey authentication could not be verified');
  }

  return verification.authenticationInfo.newCounter;
}
