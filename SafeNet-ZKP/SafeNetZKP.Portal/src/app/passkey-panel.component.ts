import { Component, input, output } from '@angular/core';

@Component({
  selector: 'portal-passkey-panel',
  template: `
    <section class="hero" aria-labelledby="login-heading">
      <div class="hero-art" aria-hidden="true">
        <div class="rings"></div>
        <div class="signal-mark"><div></div><div></div><div></div><i></i></div>
      </div>
      <div class="hero-copy">
        <span class="hero-label"><i aria-hidden="true"></i>AUTENTICAÇÃO WEBAUTHN</span>
        <h1 id="login-heading">Acesse o portal<br>com sua passkey.</h1>
        <p>Entre com uma passkey cadastrada para consultar sua sessão e acompanhar o acesso à rede.</p>
        <button type="button" class="primary" [disabled]="busy() || !available()" (click)="signIn.emit()">
          <span class="icon key" aria-hidden="true"></span>{{ busy() ? 'Aguarde…' : 'Entrar com passkey' }}
        </button>
        @if (!available()) { <p class="support">Use um navegador compatível com passkeys em HTTPS.</p> }
      </div>
    </section>
  `,
})
export class PasskeyPanelComponent {
  readonly busy = input.required<boolean>();
  readonly available = input.required<boolean>();
  readonly signIn = output<void>();
}
