import Fluent
import Vapor

func routes(_ app: Application, businessConfiguration: BusinessConfiguration) throws {
    registerOperationalRoutes(on: app)
    registerAdminPortal(on: app, configuration: businessConfiguration)

    let v1 = app.grouped("v1")
    registerPersonalRoutes(on: v1)
    registerFamilyAlertRoutes(on: v1)
    registerBusinessRoutes(on: v1, app: app, businessConfiguration: businessConfiguration)
}
