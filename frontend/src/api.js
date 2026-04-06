const appServer = import.meta.env.VITE_APP_SERVER_URL || "http://localhost:8000";
const keyServer = import.meta.env.VITE_KEY_SERVER_URL || "http://localhost:8001";

const TOKEN_KEY = "securemedia_token";

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

export async function fetchHealth() {
  const res = await fetch(`${appServer}/health`);
  if (!res.ok) {
    throw new Error(`Health check failed (${res.status})`);
  }
  return res.json();
}

export { appServer };

function authHeaders() {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function registerUser(username, password) {
  const res = await fetch(`${appServer}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });
  if (!res.ok) {
    throw new Error("Registration failed");
  }
  return res.json();
}

export async function loginUser(username, password) {
  const res = await fetch(`${appServer}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });
  if (!res.ok) {
    throw new Error("Login failed");
  }
  return res.json();
}

export async function fetchMe() {
  const res = await fetch(`${appServer}/auth/me`, {
    headers: { ...authHeaders() }
  });
  if (!res.ok) throw new Error("Fetch current user failed");
  return res.json();
}

export async function registerCertificate(certPem, userId) {
  const res = await fetch(`${appServer}/certificates/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({ cert_pem: certPem, user_id: userId })
  });
  if (!res.ok) throw new Error("Register certificate failed");
  return res.json();
}

export async function createGroup(name) {
  const res = await fetch(`${appServer}/groups`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({ name })
  });
  if (!res.ok) throw new Error("Create group failed");
  return res.json();
}

export async function addMember(groupId, userId) {
  const res = await fetch(`${appServer}/groups/${groupId}/members`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({ user_id: Number(userId) })
  });
  if (!res.ok) throw new Error("Add member failed");
  return res.json();
}

export async function addMemberByName(groupName, username) {
  const res = await fetch(`${appServer}/groups/by-name/${groupName}/members`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({ username })
  });
  if (!res.ok) throw new Error("Add member failed");
  return res.json();
}

export async function getGroupByName(groupName) {
  const res = await fetch(`${appServer}/groups/by-name/${groupName}`, {
    headers: { ...authHeaders() }
  });
  if (!res.ok) {
    let detail = "";
    try {
      const data = await res.json();
      detail = data.detail ? `: ${data.detail}` : "";
    } catch {
      detail = "";
    }
    throw new Error(`Get group failed${detail}`);
  }
  return res.json();
}

export async function getGroup(groupId) {
  const res = await fetch(`${appServer}/groups/${groupId}`, {
    headers: { ...authHeaders() }
  });
  if (!res.ok) {
    let detail = "";
    try {
      const data = await res.json();
      detail = data.detail ? `: ${data.detail}` : "";
    } catch {
      detail = "";
    }
    throw new Error(`Get group failed${detail}`);
  }
  return res.json();
}

export async function listMyGroups() {
  const res = await fetch(`${appServer}/groups`, {
    headers: { ...authHeaders() }
  });
  if (!res.ok) throw new Error("Fetch groups failed");
  return res.json();
}

export async function createPost(groupId, payload) {
  const res = await fetch(`${appServer}/groups/${groupId}/posts`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error("Create post failed");
  return res.json();
}

export async function createPostByName(groupName, payload) {
  const res = await fetch(`${appServer}/groups/by-name/${groupName}/posts`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    let detail = "";
    try {
      const data = await res.json();
      detail = data.detail ? `: ${data.detail}` : "";
    } catch {
      detail = "";
    }
    throw new Error(`Create post failed${detail}`);
  }
  return res.json();
}

export async function listPosts(groupId) {
  const res = await fetch(`${appServer}/groups/${groupId}/posts`, {
    headers: { ...authHeaders() }
  });
  if (!res.ok) throw new Error("Fetch posts failed");
  return res.json();
}

export async function listAllPosts() {
  const res = await fetch(`${appServer}/posts`, {
    headers: { ...authHeaders() }
  });
  if (!res.ok) throw new Error("Fetch posts failed");
  return res.json();
}

export async function requestCertificate(payload) {
  const res = await fetch(`${keyServer}/certificates/request`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error("Certificate request failed");
  return res.json();
}

export async function getCaCertificate() {
  const res = await fetch(`${keyServer}/ca/certificate`);
  if (!res.ok) throw new Error("Fetch CA certificate failed");
  return res.json();
}

export async function getCurrentWrappedKey(groupId, userId) {
  const res = await fetch(
    `${keyServer}/groups/${groupId}/keys/current?user_id=${encodeURIComponent(userId)}`
  );
  if (!res.ok) throw new Error("Fetch wrapped key failed");
  return res.json();
}

export async function getWrappedKey(groupId, version, userId) {
  const res = await fetch(
    `${keyServer}/groups/${groupId}/keys/${version}/wrapped/${encodeURIComponent(userId)}`
  );
  if (!res.ok) throw new Error("Fetch wrapped key failed");
  return res.json();
}

export async function getPublicKeys(userId) {
  const res = await fetch(`${keyServer}/public-keys/${userId}`);
  if (!res.ok) throw new Error("Fetch public keys failed");
  return res.json();
}

export async function createGroupKeys(groupId, memberUserIds) {
  const res = await fetch(`${keyServer}/groups/${groupId}/keys/create`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ group_id: String(groupId), member_user_ids: memberUserIds })
  });
  if (!res.ok) {
    let detail = "";
    try {
      const data = await res.json();
      detail = data.detail ? `: ${data.detail}` : "";
    } catch {
      detail = "";
    }
    throw new Error(`Create group keys failed${detail}`);
  }
  return res.json();
}
