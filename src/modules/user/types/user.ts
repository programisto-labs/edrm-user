import { RoleType } from './role.js';

export type PasskeyCredentialType = {
  credentialId: string;
  publicKey: string;
  counter: number;
  transports?: string[];
  deviceType: 'singleDevice' | 'multiDevice';
  backedUp: boolean;
  name?: string;
  createdAt: Date;
};

export type UserType = {
  id: number;
  uid?: number;
  email: string;
  password?: string;
  firstname: string;
  lastname: string;
  roles?: RoleType[];
  refreshToken?: string | null;
  resetToken?: string | null;
  resetTokenExpiration?: Date | null;
  passkeys?: PasskeyCredentialType[];
  passkeyRegistrationChallenge?: string | null;
  passkeyRegistrationChallengeExpiration?: Date | null;
  passkeyAuthenticationChallenge?: string | null;
  passkeyAuthenticationChallengeExpiration?: Date | null;
};
