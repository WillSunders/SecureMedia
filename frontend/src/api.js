const appServer = import.meta.env.VITE_APP_SERVER_URL || "http://localhost:8000";

export async function fetchHealth() {
  const res = await fetch(`${appServer}/health`);
  if (!res.ok) {
    throw new Error(`Health check failed (${res.status})`);
  }
  return res.json();
}

export { appServer };
