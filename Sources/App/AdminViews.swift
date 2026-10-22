import Vapor

/// Server-rendered admin pages. Every interpolated value goes through `esc`.
enum AdminViews {
    static func locked() -> Response {
        page(title: "Admin locked", status: .serviceUnavailable, content: """
        <main class="center"><section class="panel narrow"><div class="mark">K</div>
        <h1>Admin access is locked</h1><p>Set <code>BUSINESS_TOKEN_SECRET</code> (and
        <code>ADMIN_PSK</code> for the super-admin sign-in), then restart the API.</p></section></main>
        """)
    }

    static func login(error: String? = nil, superAdminEnabled: Bool, totpRequired: Bool,
                      status: HTTPResponseStatus? = nil) -> Response {
        let notice = error.map { "<p class=\"error\">\(esc($0))</p>" } ?? ""
        let totp = totpRequired ? """
        <label>Authenticator code<input name="totp" inputmode="numeric" autocomplete="one-time-code"
        pattern="[0-9 ]{6,7}" required></label>
        """ : ""
        let superForm = superAdminEnabled ? """
        <form method="post" action="/admin/login"><label>Shared key
        <input type="password" name="psk" required autofocus autocomplete="current-password"></label>
        \(totp)<button type="submit">Sign in</button></form>
        """ : "<p class=\"muted\">Super-admin sign-in is disabled (no <code>ADMIN_PSK</code>).</p>"
        return page(title: "Admin sign in", status: status ?? (error == nil ? .unauthorized : .forbidden),
                    content: """
        <main class="center"><section class="panel narrow"><div class="mark">K</div>
        <p class="eyebrow">KENNI ADMIN</p><h1>Sign in</h1>\(notice)
        <h3 class="sub">KENNI administrator</h3>\(superForm)
        <h3 class="sub">Business administrator</h3>
        <form method="get" action="/admin/sso"><label>Organisation ID
        <input name="org" required pattern="[a-z0-9-]{2,40}" placeholder="acme"></label>
        <button class="quiet wide" type="submit">Continue with company sign-in</button></form>
        </section></main>
        """)
    }

    struct DeviceRow {
        let device: BusinessDevice
    }

    struct BusinessCard {
        let business: Business
        let hasLogo: Bool
        let devices: [BusinessDevice]
        let invitations: [BusinessDeviceInvitation]
    }

    static func dashboard(session: AdminSession, cards: [BusinessCard], audit: [AuditEvent],
                          error: String? = nil) -> Response {
        let csrf = esc(session.csrf)
        var directory = cards.map { card(session: session, $0) }.joined(separator: "\n")
        if directory.isEmpty { directory = "<div class=\"empty\">No approved businesses yet.</div>" }
        let notice = error.map { "<p class=\"error\">\(esc($0))</p>" } ?? ""
        let createPanel = session.isSuper ? """
        <section class="panel"><h2>Approve a business</h2>\(notice)
        <form method="post" action="/admin/businesses" enctype="multipart/form-data">
        <input type="hidden" name="csrf" value="\(csrf)">
        \(profileFields(name: "", address: "", website: ""))
        <button type="submit">Approve business</button></form></section>
        """ : "<section class=\"panel\"><h2>Your business</h2>\(notice)<p>You manage the devices of this business. Its public profile is maintained by KENNI.</p></section>"
        let sessionTools = session.isSuper ? """
        <form method="post" action="/admin/sessions/revoke-all"><input type="hidden" name="csrf" value="\(csrf)">
        <button class="quiet" type="submit">Sign out all other sessions</button></form>
        """ : ""
        return page(title: "Approved businesses", status: error == nil ? .ok : .badRequest, content: """
        <header><div><p class="eyebrow">KENNI ADMIN · \(esc(session.actor))</p><h1>\(session.isSuper ? "Approved businesses" : "Business devices")</h1></div>
        <div class="row">\(sessionTools)<form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="\(csrf)">
        <button class="quiet" type="submit">Sign out</button></form></div></header>
        <main class="layout"><div>\(createPanel)</div>
        <section><div class="section-title"><h2>Directory</h2><span>\(cards.count)</span></div>\(directory)
        <div class="section-title"><h2>Audit log</h2><span>\(audit.count)</span></div>\(auditTable(audit))</section></main>
        """)
    }

    private static func card(session: AdminSession, _ card: BusinessCard) -> String {
        let business = card.business
        let businessID = business.id?.uuidString ?? ""
        let csrf = esc(session.csrf)
        let logo = card.hasLogo
            ? "<img src=\"/v1/businesses/\(businessID)/logo\" alt=\"\(esc(business.name)) logo\">"
            : "<div class=\"logo-placeholder\">\(esc(String(business.name.prefix(1)).uppercased()))</div>"
        var deviceRows = card.devices.map { device -> String in
            let revoked = device.revokedAt != nil
            let action = revoked ? "" : """
            <form method="post" action="/admin/businesses/\(businessID)/devices/\(device.id?.uuidString ?? "")/revoke">
            <input type="hidden" name="csrf" value="\(csrf)"><button class="danger small" type="submit">Revoke</button></form>
            """
            let agent = device.agentName.map { " · \(esc($0))" } ?? ""
            return """
            <div class="device-row"><div><strong>\(esc(device.deviceLabel))</strong>
            <span class="status \(revoked ? "revoked" : "active")">\(revoked ? "Revoked" : "Active")</span>
            <small>\(device.lastSeenAt.map { "Last seen \(esc($0.formatted()))" } ?? "Not seen since enrollment")\(agent)</small></div>\(action)</div>
            """
        }.joined(separator: "\n")
        if deviceRows.isEmpty { deviceRows = "<p class=\"muted\">No enrolled devices.</p>" }
        let invitations = card.invitations.map { invitation in
            """
            <div class="device-row"><div><strong>\(esc(invitation.deviceLabel))</strong>
            <span class="status pending">Pending</span><small>Expires \(esc(invitation.expiresAt.formatted()))</small></div>
            <form method="post" action="/admin/businesses/\(businessID)/invitations/\(invitation.id?.uuidString ?? "")/cancel">
            <input type="hidden" name="csrf" value="\(csrf)"><button class="danger small" type="submit">Cancel</button></form></div>
            """
        }.joined(separator: "\n")
        let suspended = business.status == .suspended
        let superTools = session.isSuper ? """
        <div class="row"><a class="button-link quiet small" href="/admin/businesses/\(businessID)">Edit</a>
        <form method="post" action="/admin/businesses/\(businessID)/status"><input type="hidden" name="csrf" value="\(csrf)">
        <input type="hidden" name="status" value="\(suspended ? "active" : "suspended")">
        <button class="\(suspended ? "quiet" : "danger") small" type="submit">\(suspended ? "Reactivate" : "Suspend")</button></form></div>
        """ : ""
        let activeCount = card.devices.filter { $0.revokedAt == nil }.count
        return """
        <article class="business-card"><div class="business-head">\(logo)<div><h3>\(esc(business.name))
        \(suspended ? "<span class=\"status revoked\">Suspended</span>" : "")</h3>
        <p>\(esc(business.address).replacingOccurrences(of: "\n", with: "<br>"))</p>
        <span class="muted">\(activeCount) active · \(card.invitations.count) pending\(business.slug.map { " · org: \(esc($0))" } ?? "")</span></div>\(superTools)</div>
        <div class="devices">\(deviceRows)\(invitations)</div>
        \(suspended ? "" : """
        <form class="invite-form" method="post" action="/admin/businesses/\(businessID)/devices">
        <input type="hidden" name="csrf" value="\(csrf)"><label>New device label
        <input name="deviceLabel" maxlength="100" placeholder="Reception iPad" required></label>
        <button type="submit">Create enrollment QR</button></form>
        """)</article>
        """
    }

    static func profileFields(name: String, address: String, website: String) -> String {
        """
        <label>Business name<input name="name" maxlength="120" required value="\(esc(name))"></label>
        <label>Address<textarea name="address" maxlength="500" rows="4" required>\(esc(address))</textarea></label>
        <label>Website <span>optional, HTTPS</span><input type="url" name="websiteURL" maxlength="500" placeholder="https://…" value="\(esc(website))"></label>
        <label>Logo <span>PNG or JPEG, up to 512 KB</span><input type="file" name="logo" accept="image/png,image/jpeg"></label>
        <label>…or import logo from <span>HTTPS URL, downloaded once</span><input type="url" name="logoURL" maxlength="500" placeholder="https://…"></label>
        """
    }

    static func editBusiness(session: AdminSession, business: Business, hasLogo: Bool,
                             error: String? = nil) -> Response {
        let id = business.id?.uuidString ?? ""
        let csrf = esc(session.csrf)
        let notice = error.map { "<p class=\"error\">\(esc($0))</p>" } ?? ""
        let logo = hasLogo ? "<img class=\"preview\" src=\"/v1/businesses/\(id)/logo\" alt=\"Current logo\">" : ""
        return page(title: "Edit \(business.name)", status: error == nil ? .ok : .badRequest, content: """
        <header><div><p class="eyebrow">KENNI ADMIN</p><h1>\(esc(business.name))</h1></div>
        <a class="button-link quiet" href="/admin">Back</a></header>
        <main class="layout"><section class="panel"><h2>Public profile</h2>\(notice)\(logo)
        <form method="post" action="/admin/businesses/\(id)" enctype="multipart/form-data">
        <input type="hidden" name="csrf" value="\(csrf)">
        \(profileFields(name: business.name, address: business.address, website: business.websiteURL ?? ""))
        <button type="submit">Save profile</button></form></section>
        <section><section class="panel"><h2>Company sign-in (SSO)</h2>
        <p>Lets the business's own admins manage its devices with their OpenID Connect provider
        (Entra ID, Google Workspace, Okta…). Redirect URI: <code>&lt;PUBLIC_BASE_URL&gt;/admin/sso/callback</code></p>
        <form method="post" action="/admin/businesses/\(id)/sso"><input type="hidden" name="csrf" value="\(csrf)">
        <label>Organisation ID <span>lowercase, used at sign-in</span><input name="slug" pattern="[a-z0-9-]{2,40}" value="\(esc(business.slug ?? ""))"></label>
        <label>Issuer URL<input type="url" name="issuer" placeholder="https://login.microsoftonline.com/&lt;tenant&gt;/v2.0" value="\(esc(business.ssoIssuer ?? ""))"></label>
        <label>Client ID<input name="clientID" value="\(esc(business.ssoClientID ?? ""))"></label>
        <label>Client secret <span>\(business.ssoClientSecretSealed == nil ? "required" : "leave empty to keep")</span><input type="password" name="clientSecret" autocomplete="off"></label>
        <label>Allowed admins <span>comma-separated addresses or @domains</span><input name="allowedEmails" placeholder="it@acme.ch, @acme.ch" value="\(esc(business.ssoAllowedEmails ?? ""))"></label>
        <div class="row"><button type="submit" name="action" value="save">Save SSO</button>
        <button class="danger" type="submit" name="action" value="remove" formnovalidate>Turn off SSO</button></div></form></section>
        <section class="panel danger-zone"><h2>Delete business</h2>
        <p>Removes the business, its devices, invitations and logo. Customers can no longer verify it. This cannot be undone.</p>
        <form method="post" action="/admin/businesses/\(id)/delete"><input type="hidden" name="csrf" value="\(csrf)">
        <label>Type the business name to confirm<input name="confirmName" required autocomplete="off"></label>
        <button class="danger" type="submit">Delete permanently</button></form></section></section></main>
        """)
    }

    static func invitation(business: Business, label: String, enrollmentURL: String,
                           expiresAt: Date, qrSVG: String) -> Response {
        page(title: "Enroll \(label)", status: .created, content: """
        <main class="center"><section class="panel enrollment"><p class="eyebrow">ONE-TIME ENROLLMENT</p>
        <h1>\(esc(business.name))</h1><h2>\(esc(label))</h2>
        <p>Open KENNI on the business device and scan this QR during setup, or push the link
        through your MDM as the <code>kenniBusinessEnrollment</code> app setting. It expires
        \(esc(expiresAt.formatted())) and can be claimed once.</p>
        <div class="qr">\(qrSVG)</div><label>Enrollment link
        <textarea readonly rows="4">\(esc(enrollmentURL))</textarea></label>
        <p class="warning">This link is a one-time secret. Share it only with the intended device.</p>
        <a class="button-link" href="/admin">Back to businesses</a></section></main>
        """)
    }

    private static func auditTable(_ events: [AuditEvent]) -> String {
        guard !events.isEmpty else { return "<div class=\"empty\">Nothing recorded yet.</div>" }
        let rows = events.map { event in
            """
            <tr><td>\(esc(event.at.formatted(date: .abbreviated, time: .standard)))</td><td>\(esc(event.actor))</td>
            <td><code>\(esc(event.action))</code></td><td>\(esc(event.target ?? ""))\(event.detail.map { " · \(esc($0))" } ?? "")</td>
            <td class="muted">\(esc(event.ip ?? ""))</td></tr>
            """
        }.joined()
        return "<div class=\"panel table\"><table><thead><tr><th>When</th><th>Who</th><th>What</th><th>Details</th><th>IP</th></tr></thead><tbody>\(rows)</tbody></table></div>"
    }

    static func page(title: String, status: HTTPResponseStatus, content: String) -> Response {
        let document = """
        <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>\(esc(title)) · KENNI</title><style>
        :root{color-scheme:dark;--bg:#080b12;--panel:#111722;--line:#263145;--text:#f6f8fc;--muted:#9aa6b8;--blue:#6ba8ff;--cyan:#57e2d2;--danger:#ff7f87;--amber:#f4a72f}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0,#12233d 0,transparent 32rem),var(--bg);color:var(--text);font:15px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-height:100vh}header{max-width:1180px;margin:auto;padding:40px 24px 20px;display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.eyebrow{letter-spacing:.18em;color:var(--cyan);font-size:12px;font-weight:700;margin:0 0 6px}h1,h2,h3{margin:0}h3.sub{margin-top:26px;font-size:14px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}p{color:var(--muted);line-height:1.5}.layout{max-width:1180px;margin:auto;padding:20px 24px 64px;display:grid;grid-template-columns:minmax(280px,380px) 1fr;gap:32px;align-items:start}.panel,.business-card,.empty{background:color-mix(in srgb,var(--panel) 92%,transparent);border:1px solid var(--line);border-radius:20px;padding:24px;box-shadow:0 20px 60px #0005;margin-bottom:16px}.narrow{width:min(440px,calc(100vw - 32px))}.center{display:grid;place-items:center;min-height:100vh;padding:16px}.mark{width:48px;height:48px;border-radius:15px;background:linear-gradient(135deg,var(--blue),var(--cyan));display:grid;place-items:center;color:#08101c;font-size:24px;font-weight:900;margin-bottom:22px}label{display:grid;gap:8px;margin-top:18px;font-weight:600}label span,.muted,small{color:var(--muted);font-size:12px;font-weight:400}input,textarea{width:100%;background:#090e17;color:var(--text);border:1px solid var(--line);border-radius:12px;padding:12px 13px;font:inherit;resize:vertical}input[type=file]{padding:9px}input:focus,textarea:focus{outline:2px solid var(--blue);border-color:transparent}button,.button-link{border:0;border-radius:12px;background:var(--text);color:#0a1019;padding:12px 16px;font:inherit;font-weight:700;cursor:pointer;margin-top:20px;width:100%;text-align:center;text-decoration:none;display:block}.quiet{width:auto;margin:0;background:#ffffff10;color:var(--text);border:1px solid var(--line)}.quiet.wide{width:100%;margin-top:20px}.danger{width:auto;background:transparent;color:var(--danger);border:1px solid #ff7f8740}.small{width:auto;margin:0;padding:7px 10px;font-size:13px}.row button{margin-top:0}.error,.warning{padding:11px 13px;border-radius:10px;background:#ff7f8716;color:#ffabb0;border:1px solid #ff7f8730}.section-title{display:flex;align-items:center;gap:10px;margin:8px 0 14px}.section-title span{background:#ffffff12;color:var(--muted);border-radius:999px;padding:3px 9px}.business-card{padding:18px}.business-head{display:grid;grid-template-columns:56px 1fr auto;gap:16px;align-items:center}.business-head img,.logo-placeholder,.preview{width:56px;height:56px;object-fit:contain;border-radius:14px;background:#fff}.preview{width:96px;height:96px;margin-top:12px}.logo-placeholder{display:grid;place-items:center;color:#0a1019;font-size:24px;font-weight:800;background:linear-gradient(135deg,var(--blue),var(--cyan))}.business-head p{margin:4px 0;font-size:13px}.devices{margin-top:18px;border-top:1px solid var(--line)}.device-row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 0;border-bottom:1px solid var(--line)}.device-row strong,.device-row small{display:block}.status{display:inline-block;margin-left:8px;padding:2px 7px;border-radius:999px;font-size:11px;vertical-align:middle}.active{color:var(--cyan);background:#57e2d218}.revoked{color:var(--danger);background:#ff7f8718}.pending{color:var(--amber);background:#f4a72f18}.invite-form{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:end}.invite-form label{margin-top:16px}.invite-form button{width:auto;margin:0}.enrollment{width:min(560px,calc(100vw - 32px));text-align:center}.enrollment label{text-align:left}.qr{background:#fff;border-radius:18px;padding:16px;margin:24px auto;width:min(320px,100%)}.qr svg{display:block;width:100%;height:auto}.table{padding:0;overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}code{color:var(--cyan)}.danger-zone{border-color:#ff7f8740}@media(max-width:760px){.layout{grid-template-columns:1fr}.invite-form{grid-template-columns:1fr}.invite-form button{width:100%}.business-head{grid-template-columns:56px 1fr}}
        </style></head><body>\(content)</body></html>
        """
        var headers = HTTPHeaders()
        headers.replaceOrAdd(name: "Content-Type", value: "text/html; charset=utf-8")
        headers.replaceOrAdd(name: "Cache-Control", value: "no-store")
        return Response(status: status, headers: headers, body: .init(string: document))
    }

    static func esc(_ value: String) -> String {
        value.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }
}
