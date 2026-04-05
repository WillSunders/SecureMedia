import React from "react";

const appServer = import.meta.env.VITE_APP_SERVER_URL || "http://localhost:8000";
const keyServer = import.meta.env.VITE_KEY_SERVER_URL || "http://localhost:8001";

export default function App() {
  return (
    <div style={{ fontFamily: "system-ui, sans-serif", padding: "2rem" }}>
      <h1>SecureMedia</h1>
      <p>React frontend is running.</p>
      <ul>
        <li>App Server: {appServer}</li>
        <li>Key Server: {keyServer}</li>
      </ul>
    </div>
  );
}
