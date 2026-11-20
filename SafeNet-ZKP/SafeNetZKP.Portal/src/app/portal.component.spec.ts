import { TestBed } from '@angular/core/testing';
import { afterEach, expect, it, vi } from 'vitest';
import { PasskeyService } from './passkey.service';
import { PortalApi, PortalFailure } from './portal-api.service';
import { PortalComponent } from './portal.component';
import { NetworkOperation } from './portal.models';

const id = '12345678-1234-1234-1234-123456789abc';
const path = `/api/captive-portal/operations/${id}`;
const session = { userId: id, name: 'Ana de Souza' };
const pending: NetworkOperation = { operationId: id, state: 'pending', expiresAt: null };

async function setup(initial = session as typeof session | null) {
  const api = {
    session: vi.fn().mockResolvedValue(initial),
    grants: vi.fn().mockResolvedValue([]),
    operation: vi.fn().mockResolvedValue(pending),
    logout: vi.fn().mockResolvedValue(undefined),
    revoke: vi.fn().mockResolvedValue({ operation: pending, location: path }),
  };
  const passkey = { supported: () => true, signIn: vi.fn().mockResolvedValue(undefined) };
  TestBed.configureTestingModule({
    providers: [{ provide: PortalApi, useValue: api }, { provide: PasskeyService, useValue: passkey }],
  });
  const fixture = TestBed.createComponent(PortalComponent);
  fixture.detectChanges();
  await fixture.whenStable();
  await Promise.resolve();
  fixture.detectChanges();
  return { fixture, component: fixture.componentInstance, api, passkey };
}

afterEach(() => vi.useRealTimers());

it('renders the authenticated name and blocks new connection registration in the UI', async () => {
  const { fixture } = await setup();
  const page = fixture.nativeElement as HTMLElement;
  expect(page.textContent).toContain('Ana de Souza');
  expect(page.textContent).toContain('observação confiável do gateway');
  expect(page.querySelector('input')).toBeNull();
  expect([...page.querySelectorAll('button')].some(button => /associar|autorizar/i.test(button.textContent ?? '')))
    .toBe(false);
});

it('shows passkey login when anonymous and loads the session after login', async () => {
  const { fixture, component, api, passkey } = await setup(null);
  expect(fixture.nativeElement.textContent).toContain('Entrar com passkey');
  api.session.mockResolvedValue(session);
  await component.signIn();
  fixture.detectChanges();
  expect(passkey.signIn).toHaveBeenCalledOnce();
  expect(fixture.nativeElement.textContent).toContain('Ana de Souza');
});

it('renders grant history separately from confirmed simulated network access', async () => {
  const { fixture, component, api } = await setup();
  api.grants.mockResolvedValue([{ operationId: id, lastKnownState: 'authorized', accessUntil: '2026-11-20T12:00:00Z' }]);
  component.navigate('grants');
  await fixture.whenStable();
  fixture.detectChanges();
  expect(fixture.nativeElement.textContent).toContain('Histórico desta sessão');
  expect(fixture.nativeElement.textContent).not.toContain('Concessão confirmada');
  api.operation.mockResolvedValue({ ...pending, state: 'authorized', expiresAt: '2026-11-20T12:00:00Z' });
  await component.selectOperation(id);
  fixture.detectChanges();
  expect(fixture.nativeElement.textContent).toContain('Concessão confirmada pelo gateway simulado');
  expect(fixture.nativeElement.textContent).toContain('não libera tráfego Wi-Fi real');
});

it('follows a 202 Location at a bounded interval and reports pending revocation until confirmed', async () => {
  const { fixture, component, api } = await setup();
  vi.useFakeTimers();
  await component.selectOperation(id);
  await component.requestRevocation();
  fixture.detectChanges();
  expect(fixture.nativeElement.textContent).toContain('Revogação pendente');
  expect(api.operation).toHaveBeenCalledTimes(1);
  api.operation.mockResolvedValueOnce({ ...pending, state: 'indeterminate' })
    .mockResolvedValueOnce({ ...pending, state: 'revoked' });
  await vi.advanceTimersByTimeAsync(12_000);
  expect(api.operation).toHaveBeenLastCalledWith(id, path, expect.any(AbortSignal));
  expect(component.operation()?.state).toBe('indeterminate');
  await vi.advanceTimersByTimeAsync(12_000);
  fixture.detectChanges();
  expect(fixture.nativeElement.textContent).toContain('Revogado');
  expect(component.following()).toBe(false);
});

it('stops polling on rate limiting and clears private data when the session expires', async () => {
  const { component, fixture, api } = await setup();
  vi.useFakeTimers();
  await component.selectOperation(id);
  await component.requestRevocation();
  api.operation.mockRejectedValueOnce(new PortalFailure(429, 30));
  await vi.advanceTimersByTimeAsync(12_000);
  fixture.detectChanges();
  expect(component.following()).toBe(false);
  expect(fixture.nativeElement.textContent).toContain('Aguarde 30 s');
  api.operation.mockRejectedValueOnce(new PortalFailure(401));
  await component.refreshOperation();
  expect(component.session()).toBeNull();
  expect(component.operation()).toBeNull();
});

it('clears private data after logout while describing the separate network state', async () => {
  const { fixture, component, api } = await setup();
  await component.logout();
  fixture.detectChanges();
  expect(api.logout).toHaveBeenCalledOnce();
  expect(fixture.nativeElement.textContent).toContain('Sua sessão web foi encerrada');
  expect(fixture.nativeElement.textContent).toContain('revogação de rede pode continuar pendente');
  expect(fixture.nativeElement.textContent).not.toContain(session.name);
});
