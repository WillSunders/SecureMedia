export const currentUser = {
  name: "Elena Park",
  handle: "@elena",
  status: "Active in SecureMedia"
};

export const navItems = [
  { label: "Home", active: true },
  { label: "Groups", active: false },
  { label: "Keys", active: false },
  { label: "Alerts", active: false },
  { label: "Profile", active: false }
];

export const feed = [
  {
    id: 1,
    name: "Ravi Patel",
    handle: "@ravi",
    time: "2m",
    content:
      "Spin-up complete. The app server is accepting encrypted posts, and the key server is tracking group key versions.",
    tags: ["#crypto", "#deployment"],
    stats: { replies: 4, reposts: 11, likes: 29 }
  },
  {
    id: 2,
    name: "Sasha Lee",
    handle: "@sashalee",
    time: "11m",
    content:
      "Client-side signing now shows a clean verification badge when the certificate is valid.",
    tags: ["#auth", "#client"],
    stats: { replies: 1, reposts: 6, likes: 18 }
  },
  {
    id: 3,
    name: "Kai Moreno",
    handle: "@kai",
    time: "35m",
    content:
      "Planning a key rotation window for tomorrow. If anyone is testing group removal, ping me.",
    tags: ["#keys", "#ops"],
    stats: { replies: 3, reposts: 2, likes: 12 }
  }
];

export const trends = [
  { topic: "#group-keys", count: "128" },
  { topic: "#client-encryption", count: "92" },
  { topic: "#fastapi", count: "64" }
];

export const suggestions = [
  { name: "Crypto Guild", members: "1.2k" },
  { name: "Blue Team", members: "860" },
  { name: "SecureOps", members: "640" }
];
