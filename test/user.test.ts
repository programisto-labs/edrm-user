import { afterEach, describe, it } from 'mocha';
import { expect } from 'chai';
import {
  createPasskeyAuthenticationOptions,
  createPasskeyRegistrationOptions,
  getPasskeyConfig
} from '../src/modules/user/services/passkey.service.js';

const runtimeProcess = (globalThis as any).process;
const originalEnv = { ...runtimeProcess.env };

describe('passkey service', () => {
  afterEach(() => {
    runtimeProcess.env = { ...originalEnv };
  });

  it('validates and returns the relying party configuration', () => {
    runtimeProcess.env.PASSKEY_RP_ID = 'example.com';
    runtimeProcess.env.PASSKEY_ORIGIN = 'https://app.example.com';
    runtimeProcess.env.PASSKEY_RP_NAME = 'Example';

    expect(getPasskeyConfig()).to.deep.equal({
      rpID: 'example.com',
      origin: 'https://app.example.com',
      rpName: 'Example'
    });
  });

  it('rejects an insecure remote origin', () => {
    runtimeProcess.env.PASSKEY_RP_ID = 'example.com';
    runtimeProcess.env.PASSKEY_ORIGIN = 'http://example.com';

    expect(() => getPasskeyConfig()).to.throw('HTTPS origin');
  });

  it('generates discoverable registration options and excludes existing credentials', async () => {
    runtimeProcess.env.PASSKEY_RP_ID = 'localhost';
    runtimeProcess.env.PASSKEY_ORIGIN = 'http://localhost:3000';

    const options = await createPasskeyRegistrationOptions({
      _id: { toString: () => '507f1f77bcf86cd799439011' },
      email: 'person@example.com',
      firstname: 'Pass',
      lastname: 'Key',
      passkeys: [{
        credentialId: 'registered-credential',
        publicKey: 'public-key',
        counter: 0,
        deviceType: 'multiDevice',
        backedUp: true,
        createdAt: new Date(),
        transports: ['internal']
      }]
    });

    expect(options.rp.id).to.equal('localhost');
    expect(options.user.name).to.equal('person@example.com');
    expect(options.authenticatorSelection?.residentKey).to.equal('required');
    expect(options.authenticatorSelection?.userVerification).to.equal('required');
    expect(options.excludeCredentials?.[0].id).to.equal('registered-credential');
  });

  it('generates authentication options restricted to the account passkeys', async () => {
    runtimeProcess.env.PASSKEY_RP_ID = 'localhost';
    runtimeProcess.env.PASSKEY_ORIGIN = 'http://localhost:3000';

    const options = await createPasskeyAuthenticationOptions([{
      credentialId: 'registered-credential',
      publicKey: 'public-key',
      counter: 2,
      deviceType: 'singleDevice',
      backedUp: false,
      createdAt: new Date()
    }]);

    expect(options.rpId).to.equal('localhost');
    expect(options.userVerification).to.equal('required');
    expect(options.allowCredentials?.[0].id).to.equal('registered-credential');
  });
});
