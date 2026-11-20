import { afterEach, describe, expect, it, vi } from 'vitest';
import { PortalApi, PortalFailure, errorMessage, followUpPath } from './portal-api.service';

const id = '12345678-1234-1234-1234-123456789abc';
const path = `/api/captive-portal/operations/${id}`;
const json = (payload: unknown, init?: ResponseInit) => Response.json(payload, init);

afterEach(() => vi.unstubAllGlobals());

describe('PortalApi', () => {
  it('loads the current session and treats 401 as anonymous', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(json({ userId: id, name: 'Ana' }))
      .mockResolvedValueOnce(new Response(null, { status: 401 }));
    vi.stubGlobal('fetch', fetchMock);
    const api = new PortalApi();
    expect(await api.session()).toEqual({ userId: id, name: 'Ana' });
    expect(await api.session()).toBeNull();
    expect(fetchMock).toHaveBeenCalledWith('/api/auth/me',
      expect.objectContaining({ credentials: 'same-origin', cache: 'no-store', redirect: 'error' }));
  });

  it('obtains CSRF and sends it only in the logout request header', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(json({ token: 'test-csrf' }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);
    await new PortalApi().logout();
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/auth/csrf', expect.objectContaining({ credentials: 'same-origin' }));
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/auth/logout', expect.objectContaining({
      method: 'POST', headers: { 'X-CSRF-TOKEN': 'test-csrf' }, credentials: 'same-origin',
    }));
  });

  it('loads grants and follows an accepted receipt only at the expected operation path', async () => {
    const grants = [{ operationId: id, lastKnownState: 'authorized', accessUntil: '2026-11-20T12:00:00Z' }];
    const fetchMock = vi.fn().mockResolvedValueOnce(json(grants)).mockResolvedValueOnce(json({ token: 'test' }))
      .mockResolvedValueOnce(json({ operationId: id, state: 'pending', expiresAt: null },
        { status: 202, headers: { Location: path } }))
      .mockResolvedValueOnce(json({ operationId: id, state: 'indeterminate', expiresAt: null }));
    vi.stubGlobal('fetch', fetchMock);
    const api = new PortalApi();
    expect(await api.grants()).toEqual(grants);
    const receipt = await api.revoke(id);
    expect(receipt.location).toBe(path);
    expect((await api.operation(id, receipt.location!)).state).toBe('indeterminate');
    expect(fetchMock).toHaveBeenLastCalledWith(path, expect.objectContaining({ credentials: 'same-origin' }));
  });

  it('rejects foreign origins, unrelated routes, alternate IDs and URL parameters', () => {
    const origin = 'https://localhost:4200';
    expect(followUpPath(origin + path, id, origin)).toBe(path);
    for (const url of [
      'https://example.com' + path, 'http://localhost:4200' + path, '/api/auth/me',
      path + '?token=value', path + '#fragment', path.replace('12345678', '02345678'),
      path + '/revocation', 'https://user@localhost:4200' + path,
    ]) {
      expect(followUpPath(url, id, origin)).toBeNull();
    }
  });

  it('keeps an invalid Location out of the accepted receipt', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(json({ token: 'test' }))
      .mockResolvedValueOnce(json({ operationId: id, state: 'indeterminate', expiresAt: null },
        { status: 202, headers: { Location: 'https://example.com' + path } })));
    const receipt = await new PortalApi().revoke(id);
    expect(receipt.location).toBeNull();
    expect(receipt.operation.state).toBe('indeterminate');
  });

  it.each([403, 404])('normalizes HTTP %s without exposing the response', async status => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ detail: 'private diagnostic' }, { status })));
    await expect(new PortalApi().grants()).rejects.toMatchObject({ status });
    expect(errorMessage(new PortalFailure(status))).not.toContain('private diagnostic');
  });

  it('respects 429 Retry-After and suppresses further requests during the cooldown', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 429, headers: { 'Retry-After': '20' } }));
    vi.stubGlobal('fetch', fetchMock);
    const api = new PortalApi();
    await expect(api.grants()).rejects.toMatchObject({ status: 429, retryAfter: 20 });
    await expect(api.grants()).rejects.toMatchObject({ status: 429 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('maps transport failures without displaying raw diagnostics', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('private network information')));
    await expect(new PortalApi().grants()).rejects.toMatchObject({ status: 0 });
    expect(errorMessage(new PortalFailure(0))).toContain('Falha de conexão');
  });
});
