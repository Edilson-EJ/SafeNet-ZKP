import { Injectable } from '@angular/core';
import { AssertionOptions, NetworkGrant, NetworkOperation, OperationReceipt, SessionUser } from './portal.models';

const root = '/api/captive-portal';
const guidPattern = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;

export class PortalFailure extends Error {
  constructor(readonly status: number, readonly retryAfter?: number) {
    super('Portal request failed');
  }
}

export function errorMessage(error: unknown): string {
  if (error instanceof DOMException && ['NotAllowedError', 'AbortError'].includes(error.name)) {
    return 'A autenticação com passkey foi cancelada ou expirou.';
  }
  if (!(error instanceof PortalFailure)) return 'Não foi possível concluir esta etapa.';

  switch (error.status) {
    case 0: return 'Falha de conexão. Tente novamente quando a API estiver acessível.';
    case 400: return 'O servidor não aceitou esta solicitação. Atualize a página e tente novamente.';
    case 401: return 'A sessão web terminou. Entre novamente com a passkey.';
    case 403: return 'A operação foi recusada ou não está disponível para esta sessão.';
    case 404: return 'Esse registro não está disponível para esta sessão.';
    case 409: return 'Já existe uma solicitação em andamento para essa conexão.';
    case 429: return `Limite de consultas atingido. Aguarde ${error.retryAfter ?? 60} s antes de tentar novamente.`;
    case 503: return 'O serviço está temporariamente indisponível.';
    default: return 'Não foi possível validar a resposta do serviço.';
  }
}

export function operationPath(operationId: string): string {
  if (!guidPattern.test(operationId)) throw new PortalFailure(502);
  return `${root}/operations/${operationId}`;
}

export function followUpPath(location: string | null, operationId: string, origin: string): string | null {
  if (!location) return null;
  try {
    const expected = operationPath(operationId);
    const url = new URL(location, origin);
    return url.origin === origin && !url.username && !url.password && !url.search && !url.hash &&
      url.pathname.toLowerCase() === expected.toLowerCase() ? url.pathname : null;
  } catch {
    return null;
  }
}

@Injectable({ providedIn: 'root' })
export class PortalApi {
  private retryAt = 0;

  async session(signal?: AbortSignal): Promise<SessionUser | null> {
    try {
      return await this.get<SessionUser>('/api/auth/me', signal);
    } catch (error) {
      if (error instanceof PortalFailure && error.status === 401) return null;
      throw error;
    }
  }

  async assertionOptions(): Promise<AssertionOptions> {
    return (await this.request('/api/webauthn/authentication/options', { method: 'POST' })).json();
  }

  async completeAssertion(operationId: string, response: unknown): Promise<void> {
    await this.request('/api/webauthn/authentication/complete', this.jsonPost({ operationId, response }));
  }

  async logout(): Promise<void> {
    await this.protectedPost('/api/auth/logout');
  }

  grants(): Promise<NetworkGrant[]> {
    return this.get<NetworkGrant[]>(`${root}/grants`);
  }

  operation(operationId: string, location?: string, signal?: AbortSignal): Promise<NetworkOperation> {
    const path = location === undefined ? operationPath(operationId) :
      followUpPath(location, operationId, window.location.origin);
    if (path === null) throw new PortalFailure(502);
    return this.get<NetworkOperation>(path, signal);
  }

  revoke(operationId: string): Promise<OperationReceipt> {
    return this.mutation(`${operationPath(operationId)}/revocation`);
  }

  // Called only by a future UI that receives a reference from trusted ingress.
  async associate(reference: string): Promise<{ associationId: string }> {
    return (await this.protectedPost(`${root}/associations`, { reference })).json();
  }

  authorize(associationId: string, idempotencyKey: string): Promise<OperationReceipt> {
    return this.mutation(`${root}/operations`, { associationId, idempotencyKey });
  }

  private async mutation(path: string, body?: unknown): Promise<OperationReceipt> {
    const response = await this.protectedPost(path, body, [403]);
    const operation = await response.json() as NetworkOperation;
    if (response.status === 403 && operation.state !== 'denied') throw new PortalFailure(403);
    const location = response.status === 202 ?
      followUpPath(response.headers.get('Location'), operation.operationId, window.location.origin) : null;
    return { operation, location };
  }

  private async protectedPost(path: string, body?: unknown, accepted?: number[]): Promise<Response> {
    const { token } = await this.get<{ token: string }>('/api/auth/csrf');
    const request = this.jsonPost(body);
    return this.request(path, {
      ...request,
      headers: { ...request.headers, 'X-CSRF-TOKEN': token },
    }, accepted);
  }

  private jsonPost(body?: unknown): RequestInit {
    return body === undefined ? { method: 'POST' } : {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    };
  }

  private async get<T>(path: string, signal?: AbortSignal): Promise<T> {
    return (await this.request(path, { signal })).json();
  }

  private async request(path: string, init: RequestInit, accepted: number[] = []): Promise<Response> {
    const remaining = Math.ceil((this.retryAt - Date.now()) / 1000);
    if (remaining > 0) throw new PortalFailure(429, remaining);

    let response: Response;
    try {
      response = await fetch(path, { ...init, credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
    } catch (error) {
      if (init.signal?.aborted) throw error;
      throw new PortalFailure(0);
    }

    if (response.status === 429) {
      const header = response.headers.get('Retry-After')?.trim();
      const seconds = !header ? 60 : /^\d+$/.test(header) ? Number(header) :
        Math.ceil((Date.parse(header) - Date.now()) / 1000);
      const delay = Number.isFinite(seconds) ? Math.max(1, seconds) : 60;
      this.retryAt = Date.now() + delay * 1000;
      throw new PortalFailure(429, delay);
    }
    if (!response.ok && !accepted.includes(response.status)) throw new PortalFailure(response.status);
    return response;
  }
}
