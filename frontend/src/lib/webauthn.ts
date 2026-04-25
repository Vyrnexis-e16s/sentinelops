/**
 * Browser-side helpers for the WebAuthn ceremony.
 *
 * The FastAPI backend sends/receives the WebAuthn structs as JSON with
 * base64url-encoded byte fields (challenge, credential id, …). The browser's
 * `navigator.credentials.create/get` APIs need real `BufferSource` values, so
 * we convert in both directions here.
 */

/** base64url string -> Uint8Array (backed by a fresh ArrayBuffer so it
 *  satisfies the DOM `BufferSource` type used by WebAuthn). */
export function b64urlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const pad = "=".repeat((4 - (value.length % 4)) % 4);
  const b64 = (value + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const buf = new ArrayBuffer(bin.length);
  const out = new Uint8Array(buf);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

/** ArrayBuffer or typed array -> base64url string (no padding) */
export function bytesToB64url(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.byteLength; i += 1) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

type B64Cred = { id: string; type: string; transports?: string[] };

interface RegistrationOptionsJSON {
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  excludeCredentials?: B64Cred[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
  extensions?: AuthenticationExtensionsClientInputs;
}

interface AuthenticationOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: B64Cred[];
  userVerification?: UserVerificationRequirement;
  extensions?: AuthenticationExtensionsClientInputs;
}

/** Convert the JSON registration options from the backend into a real
 * `PublicKeyCredentialCreationOptions` the browser API can consume. */
export function decodeRegistrationOptions(
  opts: RegistrationOptionsJSON
): PublicKeyCredentialCreationOptions {
  return {
    ...opts,
    challenge: b64urlToBytes(opts.challenge),
    user: { ...opts.user, id: b64urlToBytes(opts.user.id) },
    excludeCredentials:
      opts.excludeCredentials?.map((c) => ({
        id: b64urlToBytes(c.id),
        type: c.type as PublicKeyCredentialType,
        transports: c.transports as AuthenticatorTransport[] | undefined
      })) ?? []
  };
}

export function decodeAuthenticationOptions(
  opts: AuthenticationOptionsJSON
): PublicKeyCredentialRequestOptions {
  return {
    ...opts,
    challenge: b64urlToBytes(opts.challenge),
    allowCredentials:
      opts.allowCredentials?.map((c) => ({
        id: b64urlToBytes(c.id),
        type: c.type as PublicKeyCredentialType,
        transports: c.transports as AuthenticatorTransport[] | undefined
      })) ?? []
  };
}

/** Flatten a freshly-created registration credential into the JSON shape the
 * backend's `verify_registration_response` expects. */
export function encodeRegistrationCredential(cred: PublicKeyCredential): Record<string, unknown> {
  const att = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: bytesToB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? null,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: bytesToB64url(att.clientDataJSON),
      attestationObject: bytesToB64url(att.attestationObject),
      transports:
        typeof att.getTransports === "function" ? att.getTransports() : undefined
    }
  };
}

export function encodeAuthenticationCredential(
  cred: PublicKeyCredential
): Record<string, unknown> {
  const ass = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bytesToB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? null,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: bytesToB64url(ass.clientDataJSON),
      authenticatorData: bytesToB64url(ass.authenticatorData),
      signature: bytesToB64url(ass.signature),
      userHandle: ass.userHandle ? bytesToB64url(ass.userHandle) : null
    }
  };
}
