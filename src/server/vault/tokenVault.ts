import crypto from 'node:crypto';
import { EntityType } from '../types.ts';

// Process-scoped ephemeral AES-256 key (generated once per runtime; never logged or exported)
const VAULT_MASTER_KEY = crypto.randomBytes(32);

export interface VaultEntry {
  token: string;
  entity_type: EntityType;
  canonical_key: string;
  encrypted_value: string;
  iv: string;
  auth_tag: string;
  person_group_id: string;
  expires_at: number;
}

export interface RequestVault {
  request_id: string;
  entries: Map<string, VaultEntry>; // token -> entry
  canonicalToToken: Map<string, string>; // `${entity_type}:${canonical}` -> token
  typeCounters: Map<EntityType, number>;
}

const activeVaults = new Map<string, RequestVault>();

function canonicalizeForMatch(entityType: EntityType, raw: string): string {
  const trimmed = raw.trim();
  if (
    entityType === 'AADHAAR' ||
    entityType === 'PHONE' ||
    entityType === 'CARD_NUMBER'
  ) {
    return trimmed.replace(/[\s\-+]/g, '').replace(/^91(?=\d{10}$)/, '');
  }
  return trimmed.toLowerCase().replace(/\s+/g, ' ');
}

function encryptValue(plaintext: string): {
  encrypted_value: string;
  iv: string;
  auth_tag: string;
} {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', VAULT_MASTER_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    encrypted_value: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    auth_tag: authTag.toString('base64'),
  };
}

function decryptValue(entry: VaultEntry): string {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    VAULT_MASTER_KEY,
    Buffer.from(entry.iv, 'base64')
  );
  decipher.setAuthTag(Buffer.from(entry.auth_tag, 'base64'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(entry.encrypted_value, 'base64')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

export function createRequestVault(requestId: string): RequestVault {
  purgeExpiredVaults();
  const vault: RequestVault = {
    request_id: requestId,
    entries: new Map(),
    canonicalToToken: new Map(),
    typeCounters: new Map(),
  };
  activeVaults.set(requestId, vault);
  return vault;
}

export function issueRequestScopedToken(
  vault: RequestVault,
  entityType: EntityType,
  rawValue: string,
  personGroupId: string,
  ttlSeconds = 1800
): string {
  const canonical = canonicalizeForMatch(entityType, rawValue);
  const lookupKey = `${entityType}:${canonical}`;
  const existing = vault.canonicalToToken.get(lookupKey);
  if (existing) {
    return existing;
  }

  const nextIdx = (vault.typeCounters.get(entityType) ?? 0) + 1;
  vault.typeCounters.set(entityType, nextIdx);
  const token = `<${entityType}_${nextIdx}>`;

  const enc = encryptValue(rawValue);
  vault.entries.set(token, {
    token,
    entity_type: entityType,
    canonical_key: canonical,
    ...enc,
    person_group_id: personGroupId,
    expires_at: Date.now() + ttlSeconds * 1000,
  });
  vault.canonicalToToken.set(lookupKey, token);

  return token;
}

export function resolveTokenFromVault(
  requestId: string,
  token: string
): { value: string; entity_type: EntityType; person_group_id: string } | null {
  const vault = activeVaults.get(requestId);
  if (!vault) return null;
  const entry = vault.entries.get(token);
  if (!entry) return null;
  if (Date.now() > entry.expires_at) {
    vault.entries.delete(token);
    return null;
  }
  return {
    value: decryptValue(entry),
    entity_type: entry.entity_type,
    person_group_id: entry.person_group_id,
  };
}

export function listAllowedTokensForRequest(requestId: string): string[] {
  const vault = activeVaults.get(requestId);
  if (!vault) return [];
  return Array.from(vault.entries.keys());
}

export function getTokenPersonGroups(requestId: string): Map<string, string> {
  const vault = activeVaults.get(requestId);
  const map = new Map<string, string>();
  if (!vault) return map;
  for (const [token, entry] of vault.entries.entries()) {
    map.set(token, entry.person_group_id);
  }
  return map;
}

export function purgeExpiredVaults(): void {
  const now = Date.now();
  for (const [reqId, vault] of activeVaults.entries()) {
    for (const [tok, entry] of vault.entries.entries()) {
      if (now > entry.expires_at) {
        vault.entries.delete(tok);
      }
    }
    if (vault.entries.size === 0) {
      activeVaults.delete(reqId);
    }
  }
}
