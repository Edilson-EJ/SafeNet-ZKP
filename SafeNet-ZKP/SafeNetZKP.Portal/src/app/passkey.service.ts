import { inject, Injectable } from '@angular/core';
import { PortalApi } from './portal-api.service';

function decode(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')),
    byte => byte.charCodeAt(0)).buffer;
}

function encode(value: ArrayBuffer): string {
  const bytes = Array.from(new Uint8Array(value), byte => String.fromCharCode(byte)).join('');
  return btoa(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

@Injectable({ providedIn: 'root' })
export class PasskeyService {
  private readonly api = inject(PortalApi);

  supported(): boolean {
    return window.location.protocol === 'https:' && window.isSecureContext &&
      !!window.PublicKeyCredential && !!navigator.credentials?.get;
  }

  async signIn(): Promise<void> {
    const { operationId, options } = await this.api.assertionOptions();
    const credential = await navigator.credentials.get({
      publicKey: {
        ...options,
        challenge: decode(options.challenge),
        allowCredentials: options.allowCredentials?.map(item => ({ ...item, id: decode(item.id) })),
      },
    }) as PublicKeyCredential | null;
    if (!credential) throw new DOMException('The assertion was cancelled.', 'NotAllowedError');

    const assertion = credential.response as AuthenticatorAssertionResponse;
    await this.api.completeAssertion(operationId, {
      id: credential.id,
      rawId: encode(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: encode(assertion.clientDataJSON),
        authenticatorData: encode(assertion.authenticatorData),
        signature: encode(assertion.signature),
        userHandle: assertion.userHandle === null ? null : encode(assertion.userHandle),
      },
      clientExtensionResults: credential.getClientExtensionResults(),
    });
  }
}
