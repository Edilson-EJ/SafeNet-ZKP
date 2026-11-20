import { TestBed } from '@angular/core/testing';
import { expect, it, vi } from 'vitest';
import { PortalApi } from './portal-api.service';
import { PasskeyService } from './passkey.service';

it('decodes the challenge and sends the existing WebAuthn assertion contract', async () => {
  const api = {
    assertionOptions: vi.fn().mockResolvedValue({
      operationId: 'a'.repeat(64),
      options: { challenge: 'AQI', rpId: 'localhost', allowCredentials: [{ type: 'public-key', id: 'Aw' }] },
    }),
    completeAssertion: vi.fn().mockResolvedValue(undefined),
  };
  const buffer = (byte: number) => Uint8Array.of(byte).buffer;
  const get = vi.fn().mockResolvedValue({
    id: 'Aw', rawId: buffer(3), type: 'public-key',
    response: { clientDataJSON: buffer(4), authenticatorData: buffer(5), signature: buffer(6), userHandle: buffer(7) },
    getClientExtensionResults: () => ({}),
  });
  vi.stubGlobal('navigator', { credentials: { get } });
  try {
    TestBed.configureTestingModule({ providers: [{ provide: PortalApi, useValue: api }] });
    await TestBed.inject(PasskeyService).signIn();
    const { publicKey } = get.mock.calls[0][0];
    expect([...new Uint8Array(publicKey.challenge)]).toEqual([1, 2]);
    expect([...new Uint8Array(publicKey.allowCredentials[0].id)]).toEqual([3]);
    expect(api.completeAssertion).toHaveBeenCalledWith('a'.repeat(64), {
      id: 'Aw', rawId: 'Aw', type: 'public-key',
      response: { clientDataJSON: 'BA', authenticatorData: 'BQ', signature: 'Bg', userHandle: 'Bw' },
      clientExtensionResults: {},
    });
  } finally {
    vi.unstubAllGlobals();
  }
});
