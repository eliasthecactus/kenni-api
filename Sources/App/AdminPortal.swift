import Fluent
import Vapor

private struct AdminLoginForm: Content {
    let psk: String
}

private struct CreateBusinessForm: Content {
    let name: String
    let pin: String
    let logoURL: String?
    let address: String
    let websiteURL: String?
    let csrf: String
}

private struct AdminActionForm: Content {
    let csrf: String
}

func registerAdminPortal(on app: Application, configuration: BusinessConfiguration) {
    app.get("admin") { req async throws -> Response in
        guard configuration.isAdminEnabled else {
            return adminLockedResponse()
        }
        guard let session = validAdminSession(req, configuration: configuration) else {
            return adminLoginResponse()
        }
        return try await adminDashboardResponse(req, configuration: configuration,
                                                session: session)
    }

    app.post("admin", "login") { req async throws -> Response in
        guard configuration.isAdminEnabled else {
            return adminLockedResponse()
        }
        let form = try req.content.decode(AdminLoginForm.self)
        guard configuration.matchesAdminPSK(form.psk) else {
            return adminLoginResponse(error: "The shared key is not valid.")
        }

        let session = makeAdminSession(configuration: configuration)
        let response = redirectToAdmin()
        response.headers.add(name: "Set-Cookie", value: adminCookie(
            value: session,
            maxAge: 28_800,
            secure: req.application.environment == .production))
        return response
    }

    app.post("admin", "logout") { req -> Response in
        let response = redirectToAdmin()
        response.headers.add(name: "Set-Cookie", value: adminCookie(
            value: "",
            maxAge: 0,
            secure: req.application.environment == .production))
        return response
    }

    app.post("admin", "businesses") { req async throws -> Response in
        guard configuration.isAdminEnabled else {
            return adminLockedResponse()
        }
        guard let session = validAdminSession(req, configuration: configuration) else {
            return adminLoginResponse()
        }
        let form = try req.content.decode(CreateBusinessForm.self)
        guard validCSRF(form.csrf, session: session, configuration: configuration) else {
            throw Abort(.forbidden)
        }

        let name = form.name.trimmingCharacters(in: .whitespacesAndNewlines)
        let address = form.address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= 120,
              !address.isEmpty, address.count <= 500,
              let pin = form.pin.normalizedBusinessPIN,
              let pinDigest = configuration.pinDigest(pin) else {
            return try await adminDashboardResponse(
                req, configuration: configuration, session: session,
                error: "Enter a name, address, and a six-digit PIN.")
        }

        let logoURL = normalizedHTTPSURL(form.logoURL)
        let websiteURL = normalizedHTTPSURL(form.websiteURL)
        if hasValue(form.logoURL), logoURL == nil {
            return try await adminDashboardResponse(
                req, configuration: configuration, session: session,
                error: "The logo URL must be a valid HTTPS URL.")
        }
        if hasValue(form.websiteURL), websiteURL == nil {
            return try await adminDashboardResponse(
                req, configuration: configuration, session: session,
                error: "The website URL must be a valid HTTPS URL.")
        }
        guard try await Business.query(on: req.db)
            .filter(\.$pinDigest == pinDigest)
            .first() == nil else {
            return try await adminDashboardResponse(
                req, configuration: configuration, session: session,
                error: "That PIN is already assigned to another business.")
        }

        try await Business(name: name, pinDigest: pinDigest, logoURL: logoURL,
                           address: address, websiteURL: websiteURL).create(on: req.db)
        return redirectToAdmin()
    }

    app.post("admin", "businesses", ":id", "delete") { req async throws -> Response in
        guard configuration.isAdminEnabled else {
            return adminLockedResponse()
        }
        guard let session = validAdminSession(req, configuration: configuration) else {
            return adminLoginResponse()
        }
        let form = try req.content.decode(AdminActionForm.self)
        guard validCSRF(form.csrf, session: session, configuration: configuration) else {
            throw Abort(.forbidden)
        }
        guard let id = req.parameters.get("id", as: UUID.self),
              let business = try await Business.find(id, on: req.db) else {
            throw Abort(.notFound)
        }
        try await business.delete(on: req.db)
        return redirectToAdmin()
    }
}

private func makeAdminSession(configuration: BusinessConfiguration) -> String {
    let expiration = Int(Date().addingTimeInterval(28_800).timeIntervalSince1970)
    let nonce = (0..<24).map { _ in String(format: "%02x", UInt8.random(in: .min ... .max)) }
        .joined()
    let payload = "\(expiration).\(nonce)"
    let signature = BusinessConfiguration.hmacHex(
        message: "kenni/admin-session/v1\n\(payload)",
        secret: configuration.adminPSK!)
    return "\(payload).\(signature)"
}

private func validAdminSession(_ req: Request,
                               configuration: BusinessConfiguration) -> String? {
    guard let secret = configuration.adminPSK,
          let session = requestCookie(named: "kenni_admin", from: req),
          session.count <= 200 else { return nil }
    let parts = session.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3,
          let expiration = TimeInterval(parts[0]),
          expiration > Date().timeIntervalSince1970 else { return nil }
    let payload = "\(parts[0]).\(parts[1])"
    let expected = BusinessConfiguration.hmacHex(
        message: "kenni/admin-session/v1\n\(payload)", secret: secret)
    guard timingSafeEqual(String(parts[2]), expected) else { return nil }
    return session
}

private func csrfToken(session: String, configuration: BusinessConfiguration) -> String {
    BusinessConfiguration.hmacHex(
        message: "kenni/admin-csrf/v1\n\(session)",
        secret: configuration.adminPSK!)
}

private func validCSRF(_ candidate: String, session: String,
                       configuration: BusinessConfiguration) -> Bool {
    timingSafeEqual(candidate, csrfToken(session: session, configuration: configuration))
}

private func timingSafeEqual(_ lhs: String, _ rhs: String) -> Bool {
    let left = Array(lhs.utf8)
    let right = Array(rhs.utf8)
    var difference = left.count ^ right.count
    for index in 0..<max(left.count, right.count) {
        difference |= Int(left.indices.contains(index) ? left[index] : 0)
            ^ Int(right.indices.contains(index) ? right[index] : 0)
    }
    return difference == 0
}

private func requestCookie(named name: String, from req: Request) -> String? {
    req.headers.first(name: "Cookie")?
        .split(separator: ";")
        .lazy
        .map { $0.trimmingCharacters(in: .whitespaces) }
        .first { $0.hasPrefix("\(name)=") }
        .map { String($0.dropFirst(name.count + 1)) }
}

private func adminCookie(value: String, maxAge: Int, secure: Bool) -> String {
    "kenni_admin=\(value); Path=/admin; Max-Age=\(maxAge); HttpOnly; SameSite=Strict"
        + (secure ? "; Secure" : "")
}

private func redirectToAdmin() -> Response {
    let response = Response(status: .seeOther)
    response.headers.replaceOrAdd(name: "Location", value: "/admin")
    return response
}

private func normalizedHTTPSURL(_ raw: String?) -> String? {
    guard let value = raw?.trimmingCharacters(in: .whitespacesAndNewlines),
          !value.isEmpty, value.count <= 500,
          let components = URLComponents(string: value),
          components.scheme?.lowercased() == "https",
          components.host != nil else { return nil }
    return components.url?.absoluteString
}

private func hasValue(_ raw: String?) -> Bool {
    !(raw?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
}

private func adminLockedResponse() -> Response {
    adminPage(
        title: "Admin locked",
        status: .serviceUnavailable,
        content: """
        <main class="center"><section class="panel narrow">
          <div class="mark">K</div>
          <h1>Admin access is locked</h1>
          <p>Set both <code>ADMIN_PSK</code> and <code>BUSINESS_PIN_SECRET</code>, then restart the API.</p>
        </section></main>
        """)
}

private func adminLoginResponse(error: String? = nil) -> Response {
    let notice = error.map { "<p class=\"error\">\(htmlEscape($0))</p>" } ?? ""
    return adminPage(
        title: "Admin sign in",
        status: error == nil ? .unauthorized : .forbidden,
        content: """
        <main class="center"><section class="panel narrow">
          <div class="mark">K</div>
          <p class="eyebrow">KENNI ADMIN</p>
          <h1>Approved businesses</h1>
          <p>Enter the shared key configured on the API.</p>
          \(notice)
          <form method="post" action="/admin/login">
            <label>Shared key<input type="password" name="psk" required autofocus autocomplete="current-password"></label>
            <button type="submit">Sign in</button>
          </form>
        </section></main>
        """)
}

private func adminDashboardResponse(_ req: Request, configuration: BusinessConfiguration,
                                    session: String, error: String? = nil) async throws -> Response {
    let businesses = try await Business.query(on: req.db).sort(\.$name).all()
    let csrf = csrfToken(session: session, configuration: configuration)
    let cards = businesses.isEmpty
        ? "<div class=\"empty\">No approved businesses yet.</div>"
        : try businesses.map { business in
            let id = try business.requireID().uuidString
            let logo = business.logoURL.map {
                "<img src=\"\(htmlEscape($0))\" alt=\"\(htmlEscape(business.name)) logo\">"
            } ?? "<div class=\"logo-placeholder\">\(htmlEscape(String(business.name.prefix(1)).uppercased()))</div>"
            let website = business.websiteURL.map {
                "<a href=\"\(htmlEscape($0))\" target=\"_blank\" rel=\"noreferrer\">Website</a>"
            } ?? ""
            return """
            <article class="business-card">
              \(logo)
              <div><h3>\(htmlEscape(business.name))</h3><p>\(htmlEscape(business.address).replacingOccurrences(of: "\n", with: "<br>"))</p>\(website)</div>
              <form method="post" action="/admin/businesses/\(id)/delete">
                <input type="hidden" name="csrf" value="\(csrf)">
                <button class="danger" type="submit">Remove</button>
              </form>
            </article>
            """
        }.joined(separator: "\n")
    let notice = error.map { "<p class=\"error\">\(htmlEscape($0))</p>" } ?? ""

    return adminPage(
        title: "Approved businesses",
        status: error == nil ? .ok : .badRequest,
        content: """
        <header><div><p class="eyebrow">KENNI ADMIN</p><h1>Approved businesses</h1></div>
          <form method="post" action="/admin/logout"><button class="quiet" type="submit">Sign out</button></form>
        </header>
        <main class="layout">
          <section class="panel"><h2>Add a business</h2><p>People can reveal this profile only with its six-digit PIN.</p>
            \(notice)
            <form method="post" action="/admin/businesses">
              <input type="hidden" name="csrf" value="\(csrf)">
              <label>Business name<input name="name" maxlength="120" required></label>
              <label>Six-digit PIN<input name="pin" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="off" required></label>
              <label>Logo URL <span>optional, HTTPS</span><input type="url" name="logoURL" maxlength="500" placeholder="https://…"></label>
              <label>Address<textarea name="address" maxlength="500" rows="4" required></textarea></label>
              <label>Website <span>optional, HTTPS</span><input type="url" name="websiteURL" maxlength="500" placeholder="https://…"></label>
              <button type="submit">Approve business</button>
            </form>
          </section>
          <section><div class="section-title"><h2>Directory</h2><span>\(businesses.count)</span></div>\(cards)</section>
        </main>
        """)
}

private func adminPage(title: String, status: HTTPResponseStatus, content: String) -> Response {
    let document = """
    <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>\(htmlEscape(title)) · KENNI</title><style>
    :root{color-scheme:dark;--bg:#080b12;--panel:#111722;--line:#263145;--text:#f6f8fc;--muted:#9aa6b8;--blue:#6ba8ff;--cyan:#57e2d2;--danger:#ff7f87}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0,#12233d 0,transparent 32rem),var(--bg);color:var(--text);font:15px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-height:100vh}header{max-width:1100px;margin:auto;padding:40px 24px 20px;display:flex;justify-content:space-between;align-items:center}.eyebrow{letter-spacing:.18em;color:var(--cyan);font-size:12px;font-weight:700;margin:0 0 6px}h1,h2,h3{margin:0}p{color:var(--muted);line-height:1.5}.layout{max-width:1100px;margin:auto;padding:20px 24px 64px;display:grid;grid-template-columns:minmax(280px,380px) 1fr;gap:32px;align-items:start}.panel,.business-card,.empty{background:color-mix(in srgb,var(--panel) 92%,transparent);border:1px solid var(--line);border-radius:20px;padding:24px;box-shadow:0 20px 60px #0005}.narrow{width:min(440px,calc(100vw - 32px))}.center{display:grid;place-items:center;min-height:100vh;padding:16px}.mark{width:48px;height:48px;border-radius:15px;background:linear-gradient(135deg,var(--blue),var(--cyan));display:grid;place-items:center;color:#08101c;font-size:24px;font-weight:900;margin-bottom:22px}label{display:grid;gap:8px;margin-top:18px;font-weight:600}label span{color:var(--muted);font-size:12px;font-weight:400}input,textarea{width:100%;background:#090e17;color:var(--text);border:1px solid var(--line);border-radius:12px;padding:12px 13px;font:inherit;resize:vertical}input:focus,textarea:focus{outline:2px solid var(--blue);border-color:transparent}button{border:0;border-radius:12px;background:var(--text);color:#0a1019;padding:12px 16px;font:inherit;font-weight:700;cursor:pointer;margin-top:20px;width:100%}.quiet{width:auto;margin:0;background:#ffffff10;color:var(--text);border:1px solid var(--line)}.danger{width:auto;margin:0;background:transparent;color:var(--danger);border:1px solid #ff7f8740}.error{padding:11px 13px;border-radius:10px;background:#ff7f8716;color:#ffabb0;border:1px solid #ff7f8730}.section-title{display:flex;align-items:center;gap:10px;margin-bottom:14px}.section-title span{background:#ffffff12;color:var(--muted);border-radius:999px;padding:3px 9px}.business-card{display:grid;grid-template-columns:56px 1fr auto;gap:16px;align-items:center;margin-bottom:12px;padding:16px}.business-card img,.logo-placeholder{width:56px;height:56px;object-fit:contain;border-radius:14px;background:#fff}.logo-placeholder{display:grid;place-items:center;color:#0a1019;font-size:24px;font-weight:800;background:linear-gradient(135deg,var(--blue),var(--cyan))}.business-card p{margin:4px 0;font-size:13px}.business-card a{color:var(--blue);text-decoration:none;font-size:13px}.empty{text-align:center;color:var(--muted)}code{background:#ffffff12;padding:2px 5px;border-radius:5px}@media(max-width:760px){header{padding-top:24px}.layout{grid-template-columns:1fr}.business-card{grid-template-columns:48px 1fr}.business-card img,.logo-placeholder{width:48px;height:48px}.business-card form{grid-column:1/-1}.danger{width:100%}}
    </style></head><body>\(content)</body></html>
    """
    var headers = HTTPHeaders()
    headers.replaceOrAdd(name: "Content-Type", value: "text/html; charset=utf-8")
    return Response(status: status, headers: headers, body: .init(string: document))
}

private func htmlEscape(_ value: String) -> String {
    value.replacingOccurrences(of: "&", with: "&amp;")
        .replacingOccurrences(of: "<", with: "&lt;")
        .replacingOccurrences(of: ">", with: "&gt;")
        .replacingOccurrences(of: "\"", with: "&quot;")
        .replacingOccurrences(of: "'", with: "&#39;")
}
