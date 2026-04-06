import React, { useEffect, useState } from "react";
import {
  clearToken,
  createGroupKeys,
  createGroup,
  createPostByName,
  deleteGroup,
  fetchMe,
  getToken,
  getCurrentWrappedKey,
  getWrappedKey,
  getCaCertificate,
  getPublicKeys,
  getGroup,
  getGroupByName,
  listMyGroups,
  loginUser,
  registerCertificate,
  requestCertificate,
  registerUser,
  setToken,
  addMemberByName,
  listPosts,
  listAllPosts
} from "./api.js";
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
  const [postGroupName, setPostGroupName] = useState("");
  const [memberName, setMemberName] = useState("");
  const [postText, setPostText] = useState("");
  const [feedData, setFeedData] = useState([]);
  const [flowStatus, setFlowStatus] = useState("");
  const [myGroups, setMyGroups] = useState([]);
  const [me, setMe] = useState({ id: "", username: "" });

  useEffect(() => {
    if (!token) return;
    fetchMe()
      .then((data) => {
        setUserId(String(data.id));
        setMe({ id: String(data.id), username: data.username });
      })
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
    if (!token) return;
    handleFetchPosts();
    const interval = setInterval(() => {
      handleFetchPosts();
    }, 8000);
    return () => clearInterval(interval);
  }, [token]);

  useEffect(() => {
    if (!token) return;
    refreshGroups();
  }, [token]);

  useEffect(() => {
    if (!token) return;
    if (!postGroupName) return;
    handleFetchPosts();
  }, [postGroupName, token]);

  const refreshGroups = async () => {
    if (!token) return;
    try {
      const groups = await listMyGroups();
      setMyGroups(groups);
    } catch {
      setMyGroups([]);
    }
  };

  const handleRegister = async () => {
    setAuthError("");
    setAuthStatus("Registering...");
    try {
      const data = await registerUser(username, password);
      setToken(data.access_token);
      setTokenState(data.access_token);
      setAuthStatus("Registered and logged in.");
      const dataMe = await fetchMe();
      const currentUserId = String(dataMe.id);
      setUserId(currentUserId);
      setMe({ id: currentUserId, username: dataMe.username });
      const keyOwner = localStorage.getItem("key_owner_user_id");
      const hasLegacyKeys =
        localStorage.getItem("signing_private_pem") ||
        localStorage.getItem("agreement_private_pem") ||
        localStorage.getItem("app_cert_id");
      if (!keyOwner && hasLegacyKeys) {
        localStorage.removeItem("signing_private_pem");
        localStorage.removeItem("agreement_private_pem");
        localStorage.removeItem("cert_pem");
        localStorage.removeItem("app_cert_id");
        setCertStatus("Legacy keys detected. Please register keys again.");
      } else if (keyOwner && keyOwner !== currentUserId) {
        localStorage.removeItem("signing_private_pem");
        localStorage.removeItem("agreement_private_pem");
        localStorage.removeItem("cert_pem");
        localStorage.removeItem("app_cert_id");
        localStorage.removeItem("key_owner_user_id");
        setCertStatus("Keys belonged to another user. Please register keys again.");
      }
      await refreshGroups();
      await handleFetchPosts();
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
      const dataMe = await fetchMe();
      const currentUserId = String(dataMe.id);
      setUserId(currentUserId);
      setMe({ id: currentUserId, username: dataMe.username });
      const keyOwner = localStorage.getItem("key_owner_user_id");
      const hasLegacyKeys =
        localStorage.getItem("signing_private_pem") ||
        localStorage.getItem("agreement_private_pem") ||
        localStorage.getItem("app_cert_id");
      if (!keyOwner && hasLegacyKeys) {
        localStorage.removeItem("signing_private_pem");
        localStorage.removeItem("agreement_private_pem");
        localStorage.removeItem("cert_pem");
        localStorage.removeItem("app_cert_id");
        setCertStatus("Legacy keys detected. Please register keys again.");
      } else if (keyOwner && keyOwner !== currentUserId) {
        localStorage.removeItem("signing_private_pem");
        localStorage.removeItem("agreement_private_pem");
        localStorage.removeItem("cert_pem");
        localStorage.removeItem("app_cert_id");
        localStorage.removeItem("key_owner_user_id");
        setCertStatus("Keys belonged to another user. Please register keys again.");
      }
      await refreshGroups();
      await handleFetchPosts();
    } catch (err) {
      setAuthError(err.message || "Login failed");
      setAuthStatus("");
    }
  };

  const handleLogout = () => {
    clearToken();
    setTokenState(null);
    setUsername("");
    setPassword("");
    setUserId("");
    setMe({ id: "", username: "" });
    setAuthStatus("Logged out.");
    setFeedData([]);
    setMyGroups([]);
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
      localStorage.setItem("key_owner_user_id", String(userId));
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
      await createGroupKeys(String(group.id), [String(userId)]);
      setFlowStatus(`Group created (#${group.id}).`);
      await refreshGroups();
      await handleFetchPosts();
    } catch (err) {
      setFlowStatus(err.message || "Create group failed");
    }
  };

  const handleAddMember = async () => {
    setFlowStatus("Adding member...");
    try {
      await addMemberByName(groupName, memberName);
      const group = await getGroupByName(groupName);
      const memberIds = group.members.map((id) => String(id));
      await createGroupKeys(String(group.id), memberIds);
      setFlowStatus("Member added and key wrapped.");
      await refreshGroups();
      await handleFetchPosts();
    } catch (err) {
      setFlowStatus(err.message || "Add member failed");
    }
  };

  const handleDeleteGroup = async (groupId, name) => {
    if (!window.confirm(`Delete group "${name}"? This cannot be undone.`)) {
      return;
    }
    setFlowStatus("Deleting group...");
    try {
      await deleteGroup(groupId);
      if (postGroupName === name) setPostGroupName("");
      if (groupName === name) setGroupName("");
      setFlowStatus("Group deleted.");
      await refreshGroups();
      await handleFetchPosts();
    } catch (err) {
      setFlowStatus(err.message || "Delete group failed");
    }
  };

  const handlePost = async () => {
    setFlowStatus("Encrypting and posting...");
    try {
      if (!userId) throw new Error("Missing user ID");
      if (!postGroupName) throw new Error("Enter a group name to post");
      const keyOwner = localStorage.getItem("key_owner_user_id");
      const hasLegacyKeys =
        localStorage.getItem("signing_private_pem") ||
        localStorage.getItem("agreement_private_pem") ||
        localStorage.getItem("app_cert_id");
      if (!keyOwner && hasLegacyKeys) {
        throw new Error("Legacy keys detected. Register keys again.");
      }
      if (keyOwner && keyOwner !== String(userId)) {
        throw new Error("Local keys belong to another user. Register keys again.");
      }
      const certId = localStorage.getItem("app_cert_id");
      if (!certId) throw new Error("Register keys + certificate first");
      const group = await getGroupByName(postGroupName);
      let wrapped;
      try {
        wrapped = await getCurrentWrappedKey(group.id, userId);
      } catch (err) {
        const memberIds = group.members.map((id) => String(id));
        await createGroupKeys(String(group.id), memberIds);
        wrapped = await getCurrentWrappedKey(group.id, userId);
      }
      const agreementPrivPem = localStorage.getItem("agreement_private_pem");
      if (!agreementPrivPem) throw new Error("Missing agreement private key");
      const context = `${group.id}:${wrapped.version}:${userId}`;
      const groupKey = await unwrapGroupKey(
        wrapped.wrapped_key,
        agreementPrivPem,
        context
      );
      const encrypted = await encryptPost(
        groupKey,
        postText,
        `group:${group.id}`
      );
      const signingPrivPem = localStorage.getItem("signing_private_pem");
      if (!signingPrivPem) throw new Error("Missing signing private key");
      const signingPriv = await importPrivateKeyPem(signingPrivPem, "sign");
      const payloadToSign = JSON.stringify({
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.iv,
        auth_tag: ""
      });
      const signature = await signMessage(signingPriv, payloadToSign);
      await createPostByName(postGroupName, {
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.iv,
        auth_tag: "",
        signature,
        cert_id: Number(certId),
        key_version: wrapped.version
      });
      setFlowStatus("Post sent.");
      await handleFetchPosts();
    } catch (err) {
      const message =
        (err && err.message) ||
        (err && err.name) ||
        (typeof err === "string" ? err : JSON.stringify(err));
      console.error("Post failed:", err);
      setFlowStatus(message || "Post failed");
    }
  };

  const handleFetchPosts = async () => {
    setFlowStatus("Fetching posts...");
    try {
      const posts = await listAllPosts();
      const agreementPrivPem = localStorage.getItem("agreement_private_pem");
      const repairedGroups = new Set();
      const decrypted = [];
      for (const post of posts) {
        let plaintext = null;
        let verified = false;
        try {
          if (agreementPrivPem && userId) {
            const wrapped = await getWrappedKey(
              post.group_id,
              post.key_version,
              userId
            );
            const context = `${post.group_id}:${wrapped.version}:${userId}`;
            const groupKey = await unwrapGroupKey(
              wrapped.wrapped_key,
              agreementPrivPem,
              context
            );
            plaintext = await decryptPost(
              groupKey,
              post.nonce,
              post.ciphertext,
              `group:${post.group_id}`
            );
          }
        } catch {
          plaintext = null;
          if (
            agreementPrivPem &&
            userId &&
            !repairedGroups.has(post.group_id)
          ) {
            try {
              const group = await getGroup(post.group_id);
              const memberIds = group.members.map((id) => String(id));
              await createGroupKeys(String(group.id), memberIds);
              repairedGroups.add(post.group_id);
              const wrapped = await getWrappedKey(
                post.group_id,
                post.key_version,
                userId
              );
              const context = `${post.group_id}:${wrapped.version}:${userId}`;
              const groupKey = await unwrapGroupKey(
                wrapped.wrapped_key,
                agreementPrivPem,
                context
              );
              plaintext = await decryptPost(
                groupKey,
                post.nonce,
                post.ciphertext,
                `group:${post.group_id}`
              );
            } catch {
              plaintext = null;
            }
          }
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
            {token && me.username
              ? `${me.username} @${me.username} · Active`
              : "Not logged in"}
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
              value={me.username ? `@${me.username}` : ""}
              readOnly
              placeholder="@username"
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
              value={memberName}
              onChange={(e) => setMemberName(e.target.value)}
              placeholder="Member username"
            />
            <button type="button" onClick={handleAddMember}>
              Add member
            </button>
          </div>
        </section>

        <section className="card">
          <h3>Your groups</h3>
          <div className="auth">
            <div className="feed">
              {myGroups.map((group) => (
                <article key={group.id} className="card">
                  <div className="card-header">
                    <div className="user">
                      <div className="avatar" />
                      <div>
                        <h3>{group.name}</h3>
                        <span>
                          Owner{" "}
                          {group.owner_username
                            ? `@${group.owner_username}`
                            : `#${group.owner_id}`}
                        </span>
                      </div>
                    </div>
                    {String(group.owner_id) === String(userId) ? (
                      <button
                        type="button"
                        className="secondary"
                        onClick={() => handleDeleteGroup(group.id, group.name)}
                      >
                        Delete
                      </button>
                    ) : null}
                  </div>
                </article>
              ))}
            </div>
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
              value={postGroupName}
              onChange={(e) => setPostGroupName(e.target.value)}
              placeholder="Group name (for posting)"
            />
            <button type="button" className="new-post" onClick={handlePost}>
              Send
            </button>
          </div>
          <div className="status">{flowStatus}</div>
        </section>
        <section className="feed">
          {feedData.map((post) => (
            <article key={post.id} className="card">
              <div className="card-header">
                <div className="user">
                  <div className="avatar" />
                  <div>
                    <h3>{post.author_username || `User ${post.author_id}`}</h3>
                    <span>
                      {post.author_username
                        ? `@${post.author_username}`
                        : `@user${post.author_id}`}
                    </span>
                  </div>
                </div>
                <span className="pill">
                  {post.verified ? "Verified" : "Encrypted"}
                </span>
              </div>
              <p>{post.plaintext || post.ciphertext}</p>
            </article>
          ))}
        </section>
      </section>
    </div>
  );
}
