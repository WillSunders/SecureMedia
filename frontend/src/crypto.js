const encoder = new TextEncoder();
const decoder = new TextDecoder();

//convert uint8array to base64 string
function toBase64(bytes) {
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary);
}
//normalise base64
function normalizeBase64(base64) {
  const normalized = base64.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return normalized + pad;
}

//convert from base64 string to uint8array
function fromBase64(base64) {
  const binary = atob(normalizeBase64(base64));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

//wrap key bytes into PEM format
function wrapPem(label, bytes) {
  const base64 = toBase64(new Uint8Array(bytes));
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

//extract key bytes from PEM format
function unwrapPem(pem) {
  const lines = pem.trim().split(/\r?\n/);
  const base64 = lines.filter((line) => !line.startsWith("-----")).join("");
  return fromBase64(base64).buffer;
}

//Generate ECDSA and ECDH key pairs for the user
export async function generateUserKeys() {
  const signing = await crypto.subtle.generateKey(
    {name: "ECDSA", namedCurve: "P-256"},
    true,
    ["sign", "verify"]
  );
  const agreement = await crypto.subtle.generateKey(
    {name: "ECDH", namedCurve: "P-256"},
    true,
    ["deriveBits"]
  );
  return { signing, agreement };
}

//export a public key to PEM
export async function exportPublicKeyPem(key) {
  const spki = await crypto.subtle.exportKey("spki", key);
  return wrapPem("PUBLIC KEY", spki);
}

//export a private key to PEM
export async function exportPrivateKeyPem(key) {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", key);
  return wrapPem("PRIVATE KEY", pkcs8);
}

//import Pem to a public key
export async function importPublicKeyPem(pem, usage) {
  const spki = unwrapPem(pem);
  if (usage === "verify") {
      return crypto.subtle.importKey("spki", spki, {name: "ECDSA", namedCurve: "P-256"}, true,["verify"]
    );
  }
  if (usage === "derive") {
    return crypto.subtle.importKey("spki", spki, {name: "ECDH", namedCurve: "P-256"}, true, []);
  }
  throw new Error("Unknown usage for public key");
}

//import Pem to a private key
export async function importPrivateKeyPem(pem, usage) {
  const pkcs8 = unwrapPem(pem);
  if (usage === "sign") {
    return crypto.subtle.importKey("pkcs8", pkcs8, {name: "ECDSA", namedCurve: "P-256"}, true, ["sign"]);
  }
  if (usage === "derive") {
    return crypto.subtle.importKey("pkcs8", pkcs8, {name: "ECDH", namedCurve: "P-256"}, true, ["deriveBits"]);
  }
  throw new Error("Unknown usage for private key");
}

//sign a string with ECDSA and return a signature
export async function signMessage(privateKey, message) {
  const data = typeof message === "string" ? encoder.encode(message) : message;
  const sig = await crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, privateKey, data);
  return toBase64(new Uint8Array(sig));
}

//verify ECDSA signature
export async function verifyMessage(publicKey, message, signatureBase64) {
  const data = typeof message === "string" ? encoder.encode(message) : message;
  const sig = fromBase64(signatureBase64);
  return crypto.subtle.verify({name: "ECDSA", hash: "SHA-256"}, publicKey, sig, data);
}

//generate a group key
export function generateGroupKey() {
  const key = new Uint8Array(32);
  crypto.getRandomValues(key);
  return key;
}

//create AES-GCM key for wrapping from ECDH
async function deriveWrapKey(sharedSecret, context) {
  const keyMaterial = await crypto.subtle.importKey("raw", sharedSecret, {name: "HKDF"}, false,["deriveKey"]);
  return crypto.subtle.deriveKey(
    {name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: encoder.encode(context)},
    keyMaterial,
    {name: "AES-GCM", length: 256},
    false,
    ["encrypt", "decrypt"]
  );
}

//wrap groupkey using ECDH + HKDF + AES
export async function wrapGroupKey(groupKeyBytes, userAgreementPublicKeyPem, context) {
  const userPublicKey = await importPublicKeyPem(userAgreementPublicKeyPem, "derive");
  const ephemeral = await crypto.subtle.generateKey(
    {name: "ECDH", namedCurve: "P-256"},
    true,
    ["deriveBits"]
  );
  const sharedSecret = await crypto.subtle.deriveBits(
    {name: "ECDH", public: userPublicKey},
    ephemeral.privateKey,
    256
  );
  const wrapKey = await deriveWrapKey(sharedSecret, context);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    {name: "AES-GCM", iv: nonce, additionalData: encoder.encode(context)},
    wrapKey,
    groupKeyBytes
  );
  const ephPubPem = await exportPublicKeyPem(ephemeral.publicKey);
  const payload = {ephemeral_pub_key_pem: ephPubPem, nonce: toBase64(nonce), ciphertext: toBase64(new Uint8Array(ciphertext))};
  return toBase64(encoder.encode(JSON.stringify(payload)));
}

//unwrap GroupKey
export async function unwrapGroupKey(wrapped, userAgreementPrivateKeyPem, context) {
  const payloadJson = decoder.decode(fromBase64(wrapped));
  const payload = JSON.parse(payloadJson);
  const ephPub = await importPublicKeyPem(payload.ephemeral_pub_key_pem, "derive");
  const userPriv = await importPrivateKeyPem(userAgreementPrivateKeyPem, "derive");
  const sharedSecret = await crypto.subtle.deriveBits(
    {name: "ECDH", public: ephPub},
    userPriv,
    256
  );
  const wrapKey = await deriveWrapKey(sharedSecret, context);
  const nonce = fromBase64(payload.nonce);
  const ciphertext = fromBase64(payload.ciphertext);
  const plain = await crypto.subtle.decrypt(
    {name: "AES-GCM", iv: nonce, additionalData: encoder.encode(context)},
    wrapKey,
    ciphertext
  );
  return new Uint8Array(plain);
}

//encrypts the post with the group key
export async function encryptPost(groupKeyBytes, plaintext, aad = "") {
  const key = await crypto.subtle.importKey("raw", groupKeyBytes, {name: "AES-GCM"}, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = typeof plaintext === "string" ? encoder.encode(plaintext) : plaintext;
  const cipher = await crypto.subtle.encrypt(
    {name: "AES-GCM", iv, additionalData: encoder.encode(aad)},
    key,
    data
  );
  return {iv: toBase64(iv), ciphertext: toBase64(new Uint8Array(cipher)), aad};
}

//decrypts the post
export async function decryptPost(groupKeyBytes, ivBase64, ciphertextBase64, aad = "") {
  const key = await crypto.subtle.importKey("raw", groupKeyBytes, {name: "AES-GCM"}, false, ["decrypt"]);
  const iv = fromBase64(ivBase64);
  const ciphertext = fromBase64(ciphertextBase64);
  const plain = await crypto.subtle.decrypt(
    {name: "AES-GCM", iv, additionalData: encoder.encode(aad)},
    key,
    ciphertext
  );
  return decoder.decode(plain);
}
