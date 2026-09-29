import type { CeremonyAuthorizationSessionView } from "./protocol";

export type CeremonyAuthorizationDecision = {
  approved: boolean;
  credentialId: string | null;
};

export type CeremonyAuthorizationRegistryOptions = {
  now?: () => number;
  schedule?: (callback: () => void, delayMs: number) => number;
  cancelSchedule?: (handle: number) => void;
  closeWindow?: (windowId: number) => void;
};

type PendingCeremonyAuthorization = {
  view: CeremonyAuthorizationSessionView;
  resolve: (decision: CeremonyAuthorizationDecision) => void;
  reject: (error: unknown) => void;
  timeoutHandle: number;
  windowId: number | null;
};

export class CeremonyAuthorizationRegistry {
  private readonly now: () => number;
  private readonly schedule: (callback: () => void, delayMs: number) => number;
  private readonly cancelSchedule: (handle: number) => void;
  private readonly closeWindow: (windowId: number) => void;
  private pending: PendingCeremonyAuthorization | null = null;

  public constructor(options: CeremonyAuthorizationRegistryOptions = {}) {
    this.now = options.now ?? Date.now;
    this.schedule = options.schedule ?? ((callback, delayMs) => globalThis.setTimeout(callback, delayMs));
    this.cancelSchedule = options.cancelSchedule ?? ((handle) => globalThis.clearTimeout(handle));
    this.closeWindow = options.closeWindow ?? (() => {});
  }

  public begin(view: CeremonyAuthorizationSessionView): Promise<CeremonyAuthorizationDecision> {
    this.expireIfNeeded();
    if (this.pending) {
      throw new DOMException("Another passkey request is already awaiting approval.", "NotAllowedError");
    }

    const expiresAtMs = Date.parse(view.expiresAt);
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= this.now()) {
      throw new DOMException("The passkey authorization request is already expired.", "NotAllowedError");
    }

    let resolveDecision!: (decision: CeremonyAuthorizationDecision) => void;
    let rejectDecision!: (error: unknown) => void;
    const decision = new Promise<CeremonyAuthorizationDecision>((resolve, reject) => {
      resolveDecision = resolve;
      rejectDecision = reject;
    });
    const timeoutHandle = this.schedule(() => {
      this.cancel(view.sessionId);
    }, expiresAtMs - this.now());

    this.pending = {
      view: structuredClone(view),
      resolve: resolveDecision,
      reject: rejectDecision,
      timeoutHandle,
      windowId: null
    };
    return decision;
  }

  public getView(sessionId: string): CeremonyAuthorizationSessionView {
    return structuredClone(this.requireActive(sessionId).view);
  }

  public attachWindow(sessionId: string, windowId: number): boolean {
    this.expireIfNeeded();
    if (!this.pending || this.pending.view.sessionId !== sessionId) {
      return false;
    }

    this.pending.windowId = windowId;
    return true;
  }

  public approve(sessionId: string, credentialId?: string): void {
    const session = this.requireActive(sessionId);
    const options = session.view.credentialOptions;
    if (options.length === 0 && credentialId !== undefined) {
      throw new DOMException("This passkey request does not accept an account selection.", "SecurityError");
    }

    if (options.length > 0 && !options.some((option) => option.credentialId === credentialId)) {
      throw new DOMException("Select one of the passkeys offered for this request.", "NotAllowedError");
    }

    this.settle(sessionId, { approved: true, credentialId: credentialId ?? null });
  }

  public cancel(sessionId: string): boolean {
    return this.settle(sessionId, { approved: false, credentialId: null });
  }

  public cancelByWindowId(windowId: number): boolean {
    this.expireIfNeeded();
    if (!this.pending || this.pending.windowId !== windowId) {
      return false;
    }

    this.pending.windowId = null;
    return this.cancel(this.pending.view.sessionId);
  }

  public cancelByCeremonyId(ceremonyId: string): boolean {
    this.expireIfNeeded();
    if (!this.pending || this.pending.view.ceremonyId !== ceremonyId) {
      return false;
    }

    return this.cancel(this.pending.view.sessionId);
  }

  public cancelAll(): void {
    if (this.pending) {
      this.cancel(this.pending.view.sessionId);
    }
  }

  public fail(sessionId: string, error: unknown): boolean {
    const session = this.take(sessionId);
    if (!session) {
      return false;
    }

    session.reject(error);
    return true;
  }

  private requireActive(sessionId: string): PendingCeremonyAuthorization {
    this.expireIfNeeded();
    if (!this.pending || this.pending.view.sessionId !== sessionId) {
      throw new DOMException("The passkey authorization request expired, was cancelled, or belongs to a prior worker instance.", "NotAllowedError");
    }

    return this.pending;
  }

  private expireIfNeeded(): void {
    if (this.pending && Date.parse(this.pending.view.expiresAt) <= this.now()) {
      this.cancel(this.pending.view.sessionId);
    }
  }

  private settle(sessionId: string, decision: CeremonyAuthorizationDecision): boolean {
    const session = this.take(sessionId);
    if (!session) {
      return false;
    }

    session.resolve(decision);
    return true;
  }

  private take(sessionId: string): PendingCeremonyAuthorization | null {
    if (!this.pending || this.pending.view.sessionId !== sessionId) {
      return null;
    }

    const session = this.pending;
    this.pending = null;
    this.cancelSchedule(session.timeoutHandle);
    if (session.windowId !== null) {
      this.closeWindow(session.windowId);
    }
    return session;
  }
}
