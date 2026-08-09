<p align="center">
  <img src="./NodeWarden.svg" alt="NodeWarden Logo" />
</p>

<p align="center">
  Bitwarden-compatible server running on Cloudflare Workers
</p>

<p align="center">
  <a href="https://workers.cloudflare.com/"><img src="https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare&logoColor=white" alt="Powered by Cloudflare" /></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-LGPL--3.0-2ea44f" alt="License: LGPL-3.0" /></a>
  <a href="https://github.com/shuaiplus/NodeWarden/releases/latest"><img src="https://img.shields.io/github/v/release/shuaiplus/NodeWarden?display_name=tag" alt="Latest Release" /></a>

</p>

<p align="center">
  <a href="https://t.me/NodeWarden_News">Telegram Channel</a> |
  <a href="https://t.me/NodeWarden_Official">Telegram Group</a>
</p>

<p align="center">
  <a href="./README_ZH.md">中文</a> |
  <a href="./CONTRIBUTING.md">Contributing</a> |
  <a href="https://nodewarden.app">Official wiki</a>
</p>

> **Disclaimer**  
> This project is for learning and discussion purposes only. Please back up your vault regularly.  
> This project is not affiliated with Bitwarden. Please do not report NodeWarden issues to the official Bitwarden team.

---

## Feature comparison with the official Bitwarden server

| Feature | Bitwarden Free | NodeWarden | Notes |
|---|---|---|---|
| Web vault | ✅ | ✅ | **Original Web Vault UI** |
| TOTP | ❌ | ✅ | Includes `steam://` support |
| **PWA / offline** | ❌ | ✅ | **Installable, offline** |
| **Passkey login** | ✅ | ✅ | **passwordless auth** |
| API keys | ✅ | ✅ | CLI keys; create and rotate |
| Login 2FA | ✅ | ✅ | TOTP, YubiKey, Passkey |
| 2FA recovery codes | ✅ | ✅ | One-time 2FA disable codes |
| Real-time push sync | ✅ | ✅ | All device sync |
| Attachments / Send | ✅ | ✅ | Cloudflare R2 or KV |
| Import / export | ✅ | ✅ | Bitwarden JSON / CSV / **password-encrypted ZIP** |
| **Cloud backup center** | ❌ | ✅ | **Encrypted scheduled WebDAV / S3 incrementals** |
| Device management | ✅ | ✅ | **Remove devices; trust controls** |
| Login requests | ✅ | ✅ | **Cross-device login approval/unlock** |
| **Multi-user** | ✅ | ✅ | Invite-code registration |
| Domain rules | ✅ | ✅ | Equivalent domains, global exclusions |
| Fill-assist | ✅ | ✅ | `POST /fill-assist`|
| Organizations / collections / roles | ✅ | ❌ | Not implemented |
| SSO / SCIM / directory | ✅ | ❌ | Not implemented |

---

## Tested clients

- ✅ Windows desktop
- ✅ Mobile app
- ✅ Browser extension
- ✅ Linux desktop
- ⚠️ macOS desktop not fully verified yet

---

## Visual quick deploy

1. Fork the NodeWarden repository to your GitHub account
2. Open [Cloudflare Workers & Pages](https://dash.cloudflare.com/?to=/:account/workers-and-pages/create)
3. Choose **Continue with GitHub** and select your fork
4. Set **build command** to `npm run build` and **deploy command** to `npm run deploy`
   - For KV mode, change the deploy command to `npm run deploy:kv`
5. After deployment finishes, save the private Web Vault path printed by the deploy command, then open the Workers URL with that path appended

- The default Workers hostname may be unreachable on some networks. To use a custom domain, add it in [Workers settings](https://dash.cloudflare.com/?to=/:account/workers/services/view/nodewarden/production/settings).

- If the site reports a missing `JWT_SECRET`, add it as a **Secret** in Workers settings. In production use a random string of at least 32 characters; do not use temporary or example values. Keep this secret stable and backed up securely: it signs sessions and protects server-managed credential envelopes. After an intentional rotation, sign in again and rotate or reconfigure affected API/provider credentials.

- To hide the Web Vault completely, add a text variable named `HIDE_WEB_VAULT` with the value `1` under **Workers settings → Variables and Secrets**. While enabled, server-hosted frontend pages and static assets return `404 Not Found`, while the login, sync, attachment, icon, notification, and other server endpoints used by Bitwarden clients remain available. Delete the variable (or change it to anything other than `1`) to restore the privately gated Web Vault.

- A private Web Vault entry is mandatory. The normal `npm run deploy` and `npm run deploy:kv` commands check for the `WEB_VAULT_ENTRY_PATH` Secret; when it is missing, deployment generates a high-entropy path, stores it as a Cloudflare Secret, and prints it once after a successful deploy. Save that output immediately. You may instead provide your own 16-128 character URL-safe segment through the deployment environment variable `WEB_VAULT_ENTRY_PATH`. The conventional `/` and `/index.html` paths always return a generic `404`, even to an authorized browser. Open `https://your-vault.example/<private-path>` to display the login panel at the private URL and receive a seven-day, signed, HttpOnly gate cookie. Other frontend routes and assets also return `404` without that cookie, while Bitwarden-compatible API/login requests remain at their standard root endpoints. The gate reduces automated discovery; it does not replace account authentication, Cloudflare Access, or firewall rules. `HIDE_WEB_VAULT=1` takes precedence.

- Local ZIP exports can be protected with an independent backup password. New WebDAV/S3 destinations also default to AES-256 ZIP encryption before upload, so the storage provider only receives encrypted archive entries. Existing destinations remain in their prior mode until encryption is explicitly enabled, preserving restore compatibility. Keep the backup password outside the destination provider and test a restore after enabling it. Backup endpoints must use HTTPS.

- In this flow you hand code to Cloudflare to build and deploy. `wrangler.toml` or `wrangler.kv.toml` in the repo defines binding names; the Worker initializes the D1 schema on first request—no manual SQL upload.


> [!TIP] 
> Default R2 vs optional KV:
>   | Storage | Card required | Max single attachment / Send file | Free tier |
>   |---|---|---|---|
>   | R2 | Yes | 100 MB (soft limit, adjustable) | 10 GB |
>   | KV | No | 25 MiB (Cloudflare limit) | 1 GB |


## How to update

- Manual: open your fork on GitHub; when the sync banner appears, click **Sync fork** → **Update branch**




## CLI deploy

```powershell
git clone https://github.com/shuaiplus/NodeWarden.git
cd NodeWarden

npm install
npx wrangler login

# Default: R2 mode
npm run deploy

# Optional: KV mode
npm run deploy:kv

# Local development
npm run dev
npm run dev:kv
```

---


## License

LGPL-3.0 License

---

## Credits

- [Bitwarden](https://bitwarden.com/) - Original design and clients
- [Vaultwarden](https://github.com/dani-garcia/vaultwarden) - Server implementation reference
- [Cloudflare Workers](https://workers.cloudflare.com/) - Serverless platform

---
</a>
</a>
