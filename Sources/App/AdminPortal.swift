import Fluent
import QRCodeGenerator
import Vapor

private struct AdminLoginForm: Content {
    let psk: String
    let totp: String?
}

private struct BusinessProfileForm: Content {
    let csrf: String
    let name: String
    let address: String
    let websiteURL: String?
    let logoURL: String?
    let logo: File?
}

private struct SSOForm: Content {
    let csrf: String
    let action: String?
    let slug: String?
    let issuer: String?
    let clientID: String?
    let clientSecret: String?
    let allowedEmails: String?
}

private struct InvitationForm: Content {
    let deviceLabel: String
    let csrf: String
}

private struct StatusForm: Content {
    let csrf: String
    let status: String
}

private struct DeleteForm: Content {
    let csrf: String
    let confirmName: String
}

private struct CSRFForm: Content { let csrf: String }

func registerAdminPortal(on app: Application, configuration: BusinessConfiguration) {
    let admin = app.grouped("admin")
    let uploads = admin.grouped(UploadLimit())

    /// Runs `body` for a signed-in admin with a valid CSRF token (on POSTs).
    @Sendable func authorized(_ req: Request, csrf: String? = nil,
                              _ body: (AdminSession) async throws -> Response) async throws -> Response {
        guard configuration.isAdminEnabled else { return AdminViews.locked() }
        guard let session = try await AdminSessions.current(req) else {
            return req.method == .GET ? loginPage() : redirect(to: "/admin")
        }
        if req.method != .GET {
            guard let csrf, timingSafeEqual(csrf, session.csrf) else { throw Abort(.forbidden) }
        }
        return try await body(session)
    }

    @Sendable func loginPage(error: String? = nil, status: HTTPResponseStatus? = nil) -> Response {
        AdminViews.login(error: error, superAdminEnabled: configuration.isSuperAdminEnabled,
                         totpRequired: configuration.adminTOTPSecret != nil, status: status)
    }

    @Sendable func manageableBusiness(_ req: Request, _ session: AdminSession) async throws -> Business {
        guard let id = req.parameters.get("id", as: UUID.self),
              session.canManage(id),
              let business = try await Business.find(id, on: req.db) else {
            throw Abort(.notFound)
        }
        return business
    }

    @Sendable func requireSuper(_ session: AdminSession) throws {
        guard session.isSuper else { throw Abort(.forbidden) }
    }

    @Sendable func dashboard(_ req: Request, _ session: AdminSession,
                             error: String? = nil) async throws -> Response {
        var query = Business.query(on: req.db).sort(\.$name)
        if !session.isSuper, let businessID = session.businessID {
            query = query.filter(\.$id == businessID)
        }
        var cards: [AdminViews.BusinessCard] = []
        for business in try await query.all() {
            let businessID = try business.requireID()
            cards.append(AdminViews.BusinessCard(
                business: business,
                hasLogo: try await BusinessLogo.find(businessID, on: req.db) != nil,
                devices: try await BusinessDevice.query(on: req.db)
                    .filter(\.$businessID == businessID).sort(\.$deviceLabel).all(),
                invitations: try await BusinessDeviceInvitation.query(on: req.db)
                    .filter(\.$businessID == businessID)
                    .filter(\.$claimedAt == nil)
                    .filter(\.$expiresAt > Date())
                    .sort(\.$createdAt).all()))
        }
        var audit = AuditEvent.query(on: req.db).sort(\.$at, .descending).limit(50)
        if !session.isSuper, let businessID = session.businessID {
            audit = audit.filter(\.$businessID == businessID)
        }
        return AdminViews.dashboard(session: session, cards: cards, audit: try await audit.all(),
                                    error: error)
    }

    // MARK: Sign-in

    admin.get { req async throws -> Response in
        try await authorized(req) { session in try await dashboard(req, session) }
    }

    admin.grouped(RateLimitMiddleware(store: app.rateLimits.adminLogin))
        .post("login") { req async throws -> Response in
            guard configuration.isSuperAdminEnabled else { return AdminViews.locked() }
            let form = try req.content.decode(AdminLoginForm.self)
            guard configuration.matchesAdminPSK(form.psk) else {
                await Audit.record(req, actor: "unknown", action: "admin.sign_in_failed")
                return loginPage(error: "The shared key or code is not valid.")
            }
            if let secret = configuration.adminTOTPSecret {
                let valid = (try? await TOTP.verify(form.totp ?? "", secretBase32: secret,
                                                     on: req.db)) ?? false
                guard valid else {
                    await Audit.record(req, actor: "admin", action: "admin.totp_failed")
                    return loginPage(error: "The shared key or code is not valid.")
                }
            }
            return try await AdminSessions.start(req, actor: "admin", role: .superAdmin,
                                                 businessID: nil)
        }

    admin.post("logout") { req async throws -> Response in
        try await AdminSessions.end(req)
    }

    admin.post("sessions", "revoke-all") { req async throws -> Response in
        let form = try req.content.decode(CSRFForm.self)
        return try await authorized(req, csrf: form.csrf) { session in
            try requireSuper(session)
            try await AdminSessions.revokeAll(except: session, on: req.db)
            await Audit.record(req, actor: session.actor, action: "admin.sessions_revoked")
            return redirect(to: "/admin")
        }
    }

    // MARK: Company sign-in (SSO)

    admin.get("sso") { req async throws -> Response in
        let org = (req.query[String.self, at: "org"] ?? "").lowercased()
            .trimmingCharacters(in: .whitespaces)
        guard org.range(of: "^[a-z0-9-]{2,40}$", options: .regularExpression) != nil else {
            return loginPage(error: "Enter your organisation ID.", status: .badRequest)
        }
        return redirect(to: "/admin/sso/\(org)")
    }

    admin.get("sso", "callback") { req async throws -> Response in
        guard configuration.isAdminEnabled else { return AdminViews.locked() }
        if req.query[String.self, at: "error"] != nil {
            return loginPage(error: "Company sign-in was cancelled.", status: .unauthorized)
        }
        do {
            let (business, email) = try await SSO.complete(req, configuration: configuration)
            return try await AdminSessions.start(req, actor: email, role: .business,
                                                 businessID: business.requireID())
        } catch let error as any AbortError {
            return loginPage(error: error.reason, status: error.status)
        }
    }

    admin.get("sso", ":slug") { req async throws -> Response in
        guard configuration.isAdminEnabled else { return AdminViews.locked() }
        let slug = try req.parameters.require("slug")
        guard let business = try await Business.query(on: req.db)
            .filter(\.$slug == slug).first(), business.isSSOConfigured,
              business.status == .active else {
            return loginPage(error: "Company sign-in isn't set up for this organisation.",
                             status: .notFound)
        }
        do {
            return try await SSO.begin(req, business: business, configuration: configuration)
        } catch let error as any AbortError {
            return loginPage(error: error.reason, status: error.status)
        }
    }

    // MARK: Businesses (super admin)

    uploads.post("businesses") { req async throws -> Response in
        let form = try req.content.decode(BusinessProfileForm.self)
        return try await authorized(req, csrf: form.csrf) { session in
            try requireSuper(session)
            let business = Business(name: "", address: "", websiteURL: nil)
            if let problem = try await apply(form, to: business, req: req) {
                return try await dashboard(req, session, error: problem)
            }
            await Audit.record(req, actor: session.actor, action: "business.approved",
                               businessID: business.id, target: business.name)
            return redirect(to: "/admin")
        }
    }

    admin.get("businesses", ":id") { req async throws -> Response in
        try await authorized(req) { session in
            try requireSuper(session)
            let business = try await manageableBusiness(req, session)
            return AdminViews.editBusiness(
                session: session, business: business,
                hasLogo: try await BusinessLogo.find(business.requireID(), on: req.db) != nil)
        }
    }

    uploads.post("businesses", ":id") { req async throws -> Response in
        let form = try req.content.decode(BusinessProfileForm.self)
        return try await authorized(req, csrf: form.csrf) { session in
            try requireSuper(session)
            let business = try await manageableBusiness(req, session)
            if let problem = try await apply(form, to: business, req: req) {
                return AdminViews.editBusiness(
                    session: session, business: business,
                    hasLogo: try await BusinessLogo.find(business.requireID(), on: req.db) != nil,
                    error: problem)
            }
            await Audit.record(req, actor: session.actor, action: "business.updated",
                               businessID: business.id, target: business.name)
            return redirect(to: "/admin")
        }
    }

    admin.post("businesses", ":id", "sso") { req async throws -> Response in
        let form = try req.content.decode(SSOForm.self)
        return try await authorized(req, csrf: form.csrf) { session in
            try requireSuper(session)
            let business = try await manageableBusiness(req, session)
            let hasLogo = try await BusinessLogo.find(business.requireID(), on: req.db) != nil
            func fail(_ message: String) -> Response {
                AdminViews.editBusiness(session: session, business: business, hasLogo: hasLogo,
                                        error: message)
            }
            if form.action == "remove" {
                business.ssoIssuer = nil
                business.ssoClientID = nil
                business.ssoClientSecretSealed = nil
                try await business.save(on: req.db)
                await Audit.record(req, actor: session.actor, action: "business.sso_removed",
                                   businessID: business.id, target: business.name)
                return redirect(to: "/admin/businesses/\(try business.requireID())")
            }
            let slug = (form.slug ?? "").lowercased().trimmingCharacters(in: .whitespaces)
            guard slug.range(of: "^[a-z0-9-]{2,40}$", options: .regularExpression) != nil else {
                return fail("The organisation ID must be 2–40 lowercase letters, digits or dashes.")
            }
            if let other = try await Business.query(on: req.db).filter(\.$slug == slug).first(),
               other.id != business.id {
                return fail("Another business already uses this organisation ID.")
            }
            guard let issuer = form.issuer?.trimmingCharacters(in: .whitespaces),
                  issuer.hasPrefix("https://"), URL(string: issuer)?.host != nil else {
                return fail("The issuer must be an HTTPS URL.")
            }
            guard let clientID = form.clientID?.trimmingCharacters(in: .whitespaces),
                  !clientID.isEmpty, clientID.count <= 200 else {
                return fail("Enter the client ID.")
            }
            let allowed = (form.allowedEmails ?? "").trimmingCharacters(in: .whitespaces)
            guard !allowed.isEmpty, allowed.contains("@") else {
                return fail("List at least one allowed address or @domain.")
            }
            guard configuration.publicBaseURL != nil else {
                return fail("Set PUBLIC_BASE_URL on the API first (needed for the redirect URI).")
            }
            if let secret = form.clientSecret, !secret.isEmpty {
                guard let sealed = configuration.seal(secret) else { throw Abort(.internalServerError) }
                business.ssoClientSecretSealed = sealed
            } else if business.ssoClientSecretSealed == nil {
                return fail("Enter the client secret.")
            }
            do {
                _ = try await SSO.discover(issuer: issuer, on: req)
            } catch {
                return fail("The issuer's OpenID configuration could not be loaded.")
            }
            business.slug = slug
            business.ssoIssuer = issuer
            business.ssoClientID = clientID
            business.ssoAllowedEmails = allowed
            try await business.save(on: req.db)
            await Audit.record(req, actor: session.actor, action: "business.sso_configured",
                               businessID: business.id, target: business.name, detail: allowed)
            return redirect(to: "/admin")
        }
    }

    admin.post("businesses", ":id", "status") { req async throws -> Response in
        let form = try req.content.decode(StatusForm.self)
        return try await authorized(req, csrf: form.csrf) { session in
            try requireSuper(session)
            let business = try await manageableBusiness(req, session)
            guard let status = Business.Status(rawValue: form.status) else {
                throw Abort(.badRequest)
            }
            business.status = status
            try await business.save(on: req.db)
            await Audit.record(req, actor: session.actor,
                               action: status == .active ? "business.reactivated" : "business.suspended",
                               businessID: business.id, target: business.name)
            return redirect(to: "/admin")
        }
    }

    admin.post("businesses", ":id", "delete") { req async throws -> Response in
        let form = try req.content.decode(DeleteForm.self)
        return try await authorized(req, csrf: form.csrf) { session in
            try requireSuper(session)
            let business = try await manageableBusiness(req, session)
            guard form.confirmName.trimmingCharacters(in: .whitespaces) == business.name else {
                return AdminViews.editBusiness(
                    session: session, business: business,
                    hasLogo: try await BusinessLogo.find(business.requireID(), on: req.db) != nil,
                    error: "The name didn't match — nothing was deleted.")
            }
            let businessID = try business.requireID()
            try await req.db.transaction { db in
                // Children first: SQLite doesn't enforce the cascades.
                let devices = try await BusinessDevice.query(on: db)
                    .filter(\.$businessID == businessID).all()
                for device in devices {
                    let deviceID = try device.requireID()
                    try await BusinessConfirmation.query(on: db)
                        .filter(\.$businessDeviceID == deviceID).delete()
                    try await OutboundVerification.query(on: db)
                        .filter(\.$businessDeviceID == deviceID).delete()
                    try await device.delete(on: db)
                }
                try await BusinessDeviceInvitation.query(on: db)
                    .filter(\.$businessID == businessID).delete()
                try await BusinessLogo.query(on: db).filter(\.$id == businessID).delete()
                try await AdminSession.query(on: db).filter(\.$businessID == businessID).delete()
                try await OIDCLoginState.query(on: db).filter(\.$businessID == businessID).delete()
                try await business.delete(on: db)
            }
            await Audit.record(req, actor: session.actor, action: "business.deleted",
                               businessID: businessID, target: business.name)
            return redirect(to: "/admin")
        }
    }

    // MARK: Devices (super admin, or the business's own admins)

    admin.post("businesses", ":id", "devices") { req async throws -> Response in
        let form = try req.content.decode(InvitationForm.self)
        return try await authorized(req, csrf: form.csrf) { session in
            let business = try await manageableBusiness(req, session)
            guard business.status == .active else {
                return try await dashboard(req, session, error: "Reactivate the business first.")
            }
            let label = form.deviceLabel.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !label.isEmpty, label.count <= 100 else {
                return try await dashboard(req, session, error: "Enter a device label.")
            }
            let invitationID = UUID()
            let token = "\(invitationID.uuidString).\(randomBusinessToken())"
            guard let digest = configuration.digest(context: "business-invitation", value: token) else {
                throw Abort(.serviceUnavailable)
            }
            let expiresAt = Date().addingTimeInterval(7 * 86_400)
            try await BusinessDeviceInvitation(
                id: invitationID, businessID: business.requireID(), deviceLabel: label,
                tokenDigest: digest, expiresAt: expiresAt).create(on: req.db)
            await Audit.record(req, actor: session.actor, action: "device.invited",
                               businessID: business.id, target: label)
            let enrollmentURL = "kenni://business/enroll?token=\(token)"
            let svg = try QRCode.encode(text: enrollmentURL, ecl: .medium).toSVGString(border: 4)
            return AdminViews.invitation(business: business, label: label,
                                         enrollmentURL: enrollmentURL, expiresAt: expiresAt,
                                         qrSVG: svg)
        }
    }

    admin.post("businesses", ":id", "devices", ":deviceID", "revoke") { req async throws -> Response in
        let form = try req.content.decode(CSRFForm.self)
        return try await authorized(req, csrf: form.csrf) { session in
            let business = try await manageableBusiness(req, session)
            guard let deviceID = req.parameters.get("deviceID", as: UUID.self),
                  let device = try await BusinessDevice.find(deviceID, on: req.db),
                  device.businessID == (try business.requireID()) else { throw Abort(.notFound) }
            if device.revokedAt == nil {
                device.revokedAt = .now
                try await device.save(on: req.db)
                await Audit.record(req, actor: session.actor, action: "device.revoked",
                                   businessID: business.id, target: device.deviceLabel)
                await PushService.sendBusinessRevocation(to: device, on: req)
            }
            return redirect(to: "/admin")
        }
    }

    admin.post("businesses", ":id", "invitations", ":invitationID", "cancel") { req async throws -> Response in
        let form = try req.content.decode(CSRFForm.self)
        return try await authorized(req, csrf: form.csrf) { session in
            let business = try await manageableBusiness(req, session)
            guard let invitationID = req.parameters.get("invitationID", as: UUID.self),
                  let invitation = try await BusinessDeviceInvitation.find(invitationID, on: req.db),
                  invitation.businessID == (try business.requireID()),
                  invitation.claimedAt == nil else { throw Abort(.notFound) }
            try await invitation.delete(on: req.db)
            await Audit.record(req, actor: session.actor, action: "device.invitation_cancelled",
                               businessID: business.id, target: invitation.deviceLabel)
            return redirect(to: "/admin")
        }
    }
}

/// Validates and stores a profile form. Returns a message for the admin, or nil.
private func apply(_ form: BusinessProfileForm, to business: Business,
                   req: Request) async throws -> String? {
    let name = form.name.trimmingCharacters(in: .whitespacesAndNewlines)
    let address = form.address.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !name.isEmpty, name.count <= 120, !address.isEmpty, address.count <= 500 else {
        return "Enter a business name and address."
    }
    let websiteURL = normalizedHTTPSURL(form.websiteURL)
    if hasValue(form.websiteURL), websiteURL == nil {
        return "The website URL must be a valid HTTPS URL."
    }

    var logo: (data: Data, contentType: String)?
    if let file = form.logo, file.data.readableBytes > 0 {
        guard let image = Logos.validate(Data(buffer: file.data)) else {
            return "The logo must be a PNG or JPEG of at most 512 KB."
        }
        logo = image
    } else if hasValue(form.logoURL) {
        guard let url = normalizedHTTPSURL(form.logoURL) else {
            return "The logo URL must be a valid HTTPS URL."
        }
        guard let image = await Logos.download(url, on: req.client) else {
            return "The logo couldn't be downloaded (PNG or JPEG, at most 512 KB)."
        }
        logo = image
    }

    business.name = name
    business.address = address
    business.websiteURL = websiteURL
    try await business.save(on: req.db)
    if let logo {
        let businessID = try business.requireID()
        try await BusinessLogo.query(on: req.db).filter(\.$id == businessID).delete()
        try await BusinessLogo(businessID: businessID, contentType: logo.contentType,
                               data: logo.data).create(on: req.db)
        business.logoURL = nil
        try await business.save(on: req.db)
    }
    return nil
}

private func normalizedHTTPSURL(_ raw: String?) -> String? {
    guard let value = raw?.trimmingCharacters(in: .whitespacesAndNewlines),
          !value.isEmpty, value.count <= 500,
          let components = URLComponents(string: value),
          components.scheme?.lowercased() == "https", components.host != nil else { return nil }
    return components.url?.absoluteString
}

private func hasValue(_ raw: String?) -> Bool {
    !(raw?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
}

/// Lets logo uploads through the 2 MB global cap but no further.
private struct UploadLimit: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        if let length = request.headers.first(name: .contentLength).flatMap(Int.init),
           length > 1_048_576 {
            throw Abort(.payloadTooLarge)
        }
        return try await next.respond(to: request)
    }
}

enum Logos {
    static let maxBytes = 512 * 1024

    /// PNG or JPEG by magic number, within the size cap.
    static func validate(_ data: Data) -> (data: Data, contentType: String)? {
        guard !data.isEmpty, data.count <= maxBytes else { return nil }
        if data.starts(with: [0x89, 0x50, 0x4E, 0x47]) { return (data, "image/png") }
        if data.starts(with: [0xFF, 0xD8, 0xFF]) { return (data, "image/jpeg") }
        return nil
    }

    static func download(_ url: String, on client: any Client) async -> (data: Data, contentType: String)? {
        guard url.hasPrefix("https://"),
              let response = try? await client.get(URI(string: url)),
              response.status == .ok, let body = response.body,
              body.readableBytes <= maxBytes else { return nil }
        return validate(Data(buffer: body))
    }

    /// Copies hot-linked logos from before hosted logos existed, once.
    static func importLegacy(app: Application) async {
        guard let businesses = try? await Business.query(on: app.db)
            .filter(\.$logoURL != nil).all() else { return }
        for business in businesses {
            guard let id = business.id, let url = business.logoURL else { continue }
            if let image = await download(url, on: app.client) {
                try? await BusinessLogo.query(on: app.db).filter(\.$id == id).delete()
                try? await BusinessLogo(businessID: id, contentType: image.contentType,
                                        data: image.data).create(on: app.db)
                business.logoURL = nil
                try? await business.save(on: app.db)
                app.logger.info("imported legacy logo for \(business.name)")
            } else {
                app.logger.warning("could not import legacy logo for \(business.name)")
            }
        }
    }
}
