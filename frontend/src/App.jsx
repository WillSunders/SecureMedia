import React, { useEffect, useState } from "react";
import { appServer, fetchHealth } from "./api.js";
import {
  currentUser,
  feed,
  navItems,
  suggestions,
  trends
} from "./data/fakeData.js";

const keyServer = import.meta.env.VITE_KEY_SERVER_URL || "http://localhost:8001";

export default function App() {
  const [health, setHealth] = useState({ status: "loading" });
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    fetchHealth()
      .then((data) => {
        if (!cancelled) setHealth(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err.message || "Health check failed");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="logo" />
          SecureMedia
        </div>
        <nav className="nav">
          {navItems.map((item) => (
            <a
              key={item.label}
              className={item.active ? "active" : ""}
              href="#"
            >
              {item.label}
            </a>
          ))}
        </nav>
        <button className="new-post">New encrypted post</button>
      </aside>

      <main className="main">
        <section className="hero">
          <h1>Encrypted groups, visible momentum.</h1>
          <p>
            {currentUser.name} {currentUser.handle} · {currentUser.status}
          </p>
        </section>

        <section className="compose">
          <div className="avatar" />
          <textarea
            rows="3"
            placeholder="Share an update with your group..."
          />
          <div className="actions">
            <span className="tag">Group: Core Team</span>
            <button className="new-post">Send</button>
          </div>
        </section>

        <section className="feed">
          {feed.map((post) => (
            <article key={post.id} className="card">
              <div className="card-header">
                <div className="user">
                  <div className="avatar" />
                  <div>
                    <h3>{post.name}</h3>
                    <span>
                      {post.handle} · {post.time}
                    </span>
                  </div>
                </div>
                <span className="pill">Verified</span>
              </div>
              <p>{post.content}</p>
              <div className="meta">
                <span>{post.tags.join(" ")}</span>
                <span>{post.stats.replies} replies</span>
                <span>{post.stats.reposts} reposts</span>
                <span>{post.stats.likes} likes</span>
              </div>
            </article>
          ))}
        </section>
      </main>

      <aside className="right">
        <div className="panel">
          <h4>System status</h4>
          <ul>
            <li>
              App Server <span className="pill">{appServer}</span>
            </li>
            <li>
              Key Server <span className="pill">{keyServer}</span>
            </li>
            <li>
              Health{" "}
              <span className="pill">
                {error ? "error" : health?.status || "unknown"}
              </span>
            </li>
          </ul>
        </div>
        <div className="panel">
          <h4>Trending</h4>
          <ul>
            {trends.map((trend) => (
              <li key={trend.topic}>
                {trend.topic} <span className="pill">{trend.count}</span>
              </li>
            ))}
          </ul>
        </div>
        <div className="panel">
          <h4>Suggested groups</h4>
          <ul>
            {suggestions.map((group) => (
              <li key={group.name}>
                {group.name} <span className="pill">{group.members}</span>
              </li>
            ))}
          </ul>
        </div>
      </aside>
    </div>
  );
}
