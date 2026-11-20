export interface SessionUser {
  userId: string;
  name: string;
}

export type NetworkState = 'pending' | 'authorized' | 'denied' | 'indeterminate' | 'expired' | 'revoked';

export interface NetworkOperation {
  operationId: string;
  state: NetworkState;
  expiresAt: string | null;
}

export interface NetworkGrant {
  operationId: string;
  lastKnownState: NetworkState;
  accessUntil: string;
}

export interface OperationReceipt {
  operation: NetworkOperation;
  location: string | null;
}

export interface AssertionOptions {
  operationId: string;
  options: Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & {
    challenge: string;
    allowCredentials?: (Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string })[];
  };
}

export const stateLabel: Record<NetworkState, string> = {
  pending: 'Pendente',
  authorized: 'Autorizado',
  denied: 'Negado',
  indeterminate: 'Indeterminado',
  expired: 'Expirado',
  revoked: 'Revogado',
};
