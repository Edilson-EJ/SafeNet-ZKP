import { DatePipe } from '@angular/common';
import { Component, inject, OnDestroy, OnInit, signal } from '@angular/core';
import { PortalApi, PortalFailure, errorMessage } from './portal-api.service';
import { PasskeyService } from './passkey.service';
import { PasskeyPanelComponent } from './passkey-panel.component';
import { NetworkGrant, NetworkOperation, SessionUser, stateLabel } from './portal.models';

type View = 'session' | 'grants' | 'operation' | 'logout';

@Component({
  selector: 'portal-root',
  imports: [DatePipe, PasskeyPanelComponent],
  templateUrl: './portal.component.html',
})
export class PortalComponent implements OnInit, OnDestroy {
  private readonly api = inject(PortalApi);
  private readonly passkey = inject(PasskeyService);
  private timer?: ReturnType<typeof setTimeout>;
  private pendingRequest?: AbortController;

  readonly labels = stateLabel;
  readonly passkeyAvailable = this.passkey.supported();
  readonly session = signal<SessionUser | null>(null);
  readonly grants = signal<NetworkGrant[]>([]);
  readonly operation = signal<NetworkOperation | null>(null);
  readonly view = signal<View>('session');
  readonly busy = signal(false);
  readonly error = signal('');
  readonly notice = signal('');
  readonly following = signal(false);
  readonly revoking = signal(false);

  ngOnInit(): void {
    void this.refreshSession();
  }

  ngOnDestroy(): void {
    this.stopFollowing();
  }

  refreshSession(): Promise<void> {
    return this.run(async () => {
      const session = await this.api.session();
      if (session) this.session.set(session);
      else this.clearSession();
    });
  }

  signIn(): Promise<void> {
    if (!this.passkeyAvailable) return Promise.resolve();
    return this.run(async () => {
      this.notice.set('');
      await this.passkey.signIn();
      const session = await this.api.session();
      if (!session) throw new PortalFailure(401);
      this.session.set(session);
    });
  }

  navigate(view: View): void {
    this.stopFollowing();
    this.error.set('');
    this.view.set(view);
    if (view === 'grants') void this.refreshGrants();
  }

  refreshGrants(): Promise<void> {
    return this.run(async () => this.grants.set(await this.api.grants()));
  }

  selectOperation(operationId: string): Promise<void> {
    this.navigate('operation');
    this.operation.set(null);
    this.revoking.set(false);
    return this.run(async () => this.operation.set(await this.api.operation(operationId)));
  }

  refreshOperation(): Promise<void> {
    const id = this.operation()?.operationId;
    if (!id) return Promise.resolve();
    this.stopFollowing();
    return this.run(async () => this.showOperation(await this.api.operation(id)));
  }

  requestRevocation(): Promise<void> {
    const id = this.operation()?.operationId;
    if (!id) return Promise.resolve();
    this.stopFollowing();
    return this.run(async () => {
      const { operation, location } = await this.api.revoke(id);
      this.operation.set(operation);
      this.revoking.set(operation.state === 'pending' || operation.state === 'indeterminate');
      if (location) this.follow(id, location, 5);
    });
  }

  logout(): Promise<void> {
    return this.run(async () => {
      await this.api.logout();
      this.clearSession();
      this.notice.set('Sua sessão web foi encerrada. Se havia concessões, a revogação de rede pode continuar pendente.');
    });
  }

  private follow(id: string, location: string, remaining: number): void {
    if (remaining === 0) {
      this.stopFollowing();
      return;
    }

    this.following.set(true);
    this.timer = setTimeout(async () => {
      const controller = new AbortController();
      this.pendingRequest = controller;
      try {
        const operation = await this.api.operation(id, location, controller.signal);
        if (controller.signal.aborted) return;
        this.showOperation(operation);
        if (operation.state === 'pending' || operation.state === 'indeterminate') {
          this.follow(id, location, remaining - 1);
        } else {
          this.stopFollowing();
        }
      } catch (error) {
        if (controller.signal.aborted) return;
        this.stopFollowing();
        this.handleError(error);
      }
    }, 12_000);
  }

  private stopFollowing(): void {
    clearTimeout(this.timer);
    this.pendingRequest?.abort();
    this.pendingRequest = undefined;
    this.following.set(false);
  }

  private showOperation(operation: NetworkOperation): void {
    this.operation.set(operation);
    if (operation.state !== 'pending' && operation.state !== 'indeterminate') this.revoking.set(false);
  }

  private async run(action: () => Promise<void>): Promise<void> {
    if (this.busy()) return;
    this.busy.set(true);
    this.error.set('');
    try {
      await action();
    } catch (error) {
      this.handleError(error);
    } finally {
      this.busy.set(false);
    }
  }

  private handleError(error: unknown): void {
    if (error instanceof PortalFailure && error.status === 401) this.clearSession();
    this.error.set(errorMessage(error));
  }

  private clearSession(): void {
    this.stopFollowing();
    this.session.set(null);
    this.grants.set([]);
    this.operation.set(null);
    this.revoking.set(false);
    this.view.set('session');
  }
}
