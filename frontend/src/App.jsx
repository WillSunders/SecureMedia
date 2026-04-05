import React, { useEffect, useState } from "react";
import {
  clearToken,
  createGroupKeys,
  createGroup,
  createPost,
  fetchMe,
  getToken,
  getCurrentWrappedKey,
  getWrappedKey,
  getCaCertificate,
  getPublicKeys,
  loginUser,
  registerCertificate,
  requestCertificate,
  registerUser,
  setToken,
  addMember,
  listPosts
} from "./api.js";
import { currentUser, feed } from "./data/fakeData.js";
import {
  decryptPost,
  encryptPost,
  exportPrivateKeyPem,
  exportPublicKeyPem,
  generateUserKeys,
  importPrivateKeyPem,
  importPublicKeyPem,
  signMessage,
  unwrapGroupKey,
  verifyMessage
} from "./crypto.js";

export default function App() {
  const [authError, setAuthError] = useState("");
  const [authStatus, setAuthStatus] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [token, setTokenState] = useState(getToken());
  const [userId, setUserId] = useState("");
  const [certStatus, setCertStatus] = useState("");
  const [caStatus, setCaStatus] = useState("");
  const [groupName, setGroupName] = useState("");
  const [groupId, setGroupId] = useState("");
  const [memberId, setMemberId] = useState("");
  const [postText, setPostText] = useState("");
  const [feedData, setFeedData] = useState([]);
  const [flowStatus, setFlowStatus] = useState("");

  useEffect(() => {
    if (!token) return;
    fetchMe()
      .then((me) => setUserId(String(me.id)))
      .catch(() => {});
  }, [token]);

  useEffect(() => {
    getCaCertificate()
      .then((data) => {
        localStorage.setItem("ca_cert_pem", data.certificate_pem);
        setCaStatus("CA certificate loaded.");
      })
      .catch(() => setCaStatus("CA certificate unavailable."));
  }, []);

  useEffect(() => {
    if (!groupId) return;
    handleFetchPosts();
  }, [groupId]);

  const handleRegister = async () => {
    setAuthError("");
    setAuthStatus("Registering...");
    try {
      const data = await registerUser(username, password);
      setToken(data.access_token);
      setTokenState(data.access_token);
      setAuthStatus("Registered and logged in.");
      const me = await fetchMe();
      setUserId(String(me.id));
    } catch (err) {
      setAuthError(err.message || "Registration failed");
      setAuthStatus("");
    }
  };

  const handleLogin = async () => {
    setAuthError("");
    setAuthStatus("Logging in...");
    try {
      const data = await loginUser(username, password);
      setToken(data.access_token);
      setTokenState(data.access_token);
      setAuthStatus("Logged in.");
      const me = await fetchMe();
      setUserId(String(me.id));
    } catch (err) {
      setAuthError(err.message || "Login failed");
      setAuthStatus("");
    }
  };

  const handleLogout = () => {
    clearToken();
    setTokenState(null);
    setAuthStatus("Logged out.");
  };

  const handleKeyRegistration = async () => {
    setCertStatus("Generating keys...");
    try {
      const keys = await generateUserKeys();
      const signingPub = await exportPublicKeyPem(keys.signing.publicKey);
      const agreementPub = await exportPublicKeyPem(keys.agreement.publicKey);
      const signingPriv = await exportPrivateKeyPem(keys.signing.privateKey);
      const agreementPriv = await exportPrivateKeyPem(keys.agreement.privateKey);
      localStorage.setItem("signing_private_pem", signingPriv);
      localStorage.setItem("agreement_private_pem", agreementPriv);
      const cert = await requestCertificate({
        user_id: String(userId),
        username,
        signing_public_key_pem: signingPub,
        agreement_public_key_pem: agreementPub
      });
      localStorage.setItem("cert_pem", cert.cert_pem);
      const appCert = await registerCertificate(cert.cert_pem, Number(userId));
      localStorage.setItem("app_cert_id", String(appCert.cert_id));
      setCertStatus("Keys registered and certificate issued.");
    } catch (err) {
      setCertStatus(err.message || "Key registration failed");
    }
  };

  const handleCreateGroup = async () => {
    setFlowStatus("Creating group...");
    try {
      if (!userId) throw new Error("Missing user ID");
      const hasAgreement = localStorage.getItem("agreement_private_pem");
      if (!hasAgreement) throw new Error("Generate keys + request certificate first");
      const group = await createGroup(groupName);
      setGroupId(String(group.id));
      await createGroupKeys(String(group.id), [String(userId)]);
      setFlowStatus(`Group created (#${group.id}).`);
    } catch (err) {
      setFlowStatus(err.message || "Create group failed");
    }
  };

  const handleAddMember = async () => {
    setFlowStatus("Adding member...");
    try {
      await addMember(groupId, memberId);
      setFlowStatus("Member added.");
    } catch (err) {
      setFlowStatus(err.message || "Add member failed");
    }
  };

  const handlePost = async () => {
    setFlowStatus("Encrypting and posting...");
    try {
      const wrapped = await getCurrentWrappedKey(groupId, userId);
      const agreementPrivPem = localStorage.getItem("agreement_private_pem");
      if (!agreementPrivPem) throw new Error("Missing agreement private key");
      const context = `${groupId}:${wrapped.version}:${userId}`;
      const groupKey = await unwrapGroupKey(
        wrapped.wrapped_key,
        agreementPrivPem,
        context
      );
      const encrypted = await encryptPost(groupKey, postText, `group:${groupId}`);
      const signingPrivPem = localStorage.getItem("signing_private_pem");
      if (!signingPrivPem) throw new Error("Missing signing private key");
      const signingPriv = await importPrivateKeyPem(signingPrivPem, "sign");
      const payloadToSign = JSON.stringify({
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.iv,
        auth_tag: ""
      });
      const signature = await signMessage(signingPriv, payloadToSign);
      const storedCertId = localStorage.getItem("app_cert_id");
      const certId = Number(storedCertId || 1);
      await createPost(groupId, {
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.iv,
        auth_tag: "",
        signature,
        cert_id: certId,
        key_version: wrapped.version
      });
      setFlowStatus("Post sent.");
      await handleFetchPosts();
    } catch (err) {
      setFlowStatus(err.message || "Post failed");
    }
  };

  const handleFetchPosts = async () => {
    if (!groupId) return;
    setFlowStatus("Fetching posts...");
    try {
      const posts = await listPosts(groupId);
      const agreementPrivPem = localStorage.getItem("agreement_private_pem");
      const decrypted = [];
      for (const post of posts) {
        let plaintext = null;
        let verified = false;
        try {
          if (agreementPrivPem) {
            const wrapped = await getWrappedKey(groupId, post.key_version, userId);
            const context = `${groupId}:${wrapped.version}:${userId}`;
            const groupKey = await unwrapGroupKey(
              wrapped.wrapped_key,
              agreementPrivPem,
              context
            );
            plaintext = await decryptPost(
              groupKey,
              post.nonce,
              post.ciphertext,
              `group:${groupId}`
            );
          }
        } catch {
          plaintext = null;
        }
        try {
          const keys = await getPublicKeys(String(post.author_id));
          const pubKey = await importPublicKeyPem(
            keys.signing_public_key_pem,
            "verify"
          );
          const payloadToVerify = JSON.stringify({
            ciphertext: post.ciphertext,
            nonce: post.nonce,
            auth_tag: post.auth_tag
          });
          verified = await verifyMessage(pubKey, payloadToVerify, post.signature);
        } catch {
          verified = false;
        }
        decrypted.push({ ...post, plaintext, verified });
      }
      setFeedData(decrypted);
      setFlowStatus("Posts loaded.");
    } catch (err) {
      setFlowStatus(err.message || "Fetch posts failed");
    }
  };

  return (
    <div className="app split">
      <section className="left">
        <section className="hero">
          <h1>Encrypted groups, visible momentum.</h1>
          <p>
            {currentUser.name} {currentUser.handle} · {currentUser.status}
          </p>
          <div className="auth">
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
            />
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
            />
            <div className="row">
              <button type="button" onClick={handleRegister}>
                Register
              </button>
              <button type="button" className="secondary" onClick={handleLogin}>
                Login
              </button>
            </div>
            <div className="row">
              <button type="button" className="secondary" onClick={handleLogout}>
                Logout
              </button>
            </div>
            <div className="status">
              {authError || authStatus || (token ? "Authenticated" : "Not logged in")}
            </div>
            <input
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              placeholder="User ID (numeric)"
            />
            <button type="button" onClick={handleKeyRegistration}>
              Generate keys + request certificate
            </button>
            <div className="status">{caStatus}</div>
            <div className="status">{certStatus}</div>
          </div>
        </section>

        <section className="card">
          <h3>Create group</h3>
          <div className="auth">
            <input
              value={groupName}
              onChange={(e) => setGroupName(e.target.value)}
              placeholder="Group name"
            />
            <button type="button" onClick={handleCreateGroup}>
              Create group
            </button>
            <input
              value={groupId}
              onChange={(e) => setGroupId(e.target.value)}
              placeholder="Group ID"
            />
            <input
              value={memberId}
              onChange={(e) => setMemberId(e.target.value)}
              placeholder="Member user ID"
            />
            <button type="button" onClick={handleAddMember}>
              Add member
            </button>
          </div>
        </section>

      </section>

      <section className="right feed-pane">
        <section className="compose">
          <div className="avatar" />
          <textarea
            rows="3"
            value={postText}
            onChange={(e) => setPostText(e.target.value)}
            placeholder="Share an update with your group..."
          />
          <div className="actions">
            <input
              value={groupId}
              onChange={(e) => setGroupId(e.target.value)}
              placeholder="Group ID"
            />
            <button type="button" className="new-post" onClick={handlePost}>
              Send
            </button>
          </div>
          <div className="status">{flowStatus}</div>
        </section>
        <section className="feed">
          {feedData.length > 0
            ? feedData.map((post) => (
                <article key={post.id} className="card">
                  <div className="card-header">
                    <div className="user">
                      <div className="avatar" />
                      <div>
                        <h3>User {post.author_id}</h3>
                        <span>Key v{post.key_version}</span>
                      </div>
                    </div>
                    <span className="pill">
                      {post.verified ? "Verified" : "Encrypted"}
                    </span>
                  </div>
                  <p>{post.plaintext || post.ciphertext}</p>
                </article>
              ))
            : feed.map((post) => (
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
                  </div>
                  <p>{post.content}</p>
                </article>
              ))}
        </section>
      </section>
    </div>
  );
}
