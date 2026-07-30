// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "kenni-api",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.99.0"),
        .package(url: "https://github.com/vapor/fluent.git", from: "4.9.0"),
        .package(url: "https://github.com/vapor/fluent-kit.git", from: "1.52.2"),
        .package(url: "https://github.com/vapor/fluent-postgres-driver.git", from: "2.8.0"),
        .package(url: "https://github.com/vapor/fluent-sqlite-driver.git", from: "4.6.0"),
        .package(url: "https://github.com/vapor/apns.git", from: "4.0.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/fwcd/swift-qrcode-generator.git", from: "1.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "App",
            dependencies: [
                .product(name: "Vapor", package: "vapor"),
                .product(name: "Fluent", package: "fluent"),
                .product(name: "FluentSQL", package: "fluent-kit"),
                .product(name: "FluentPostgresDriver", package: "fluent-postgres-driver"),
                .product(name: "FluentSQLiteDriver", package: "fluent-sqlite-driver"),
                .product(name: "VaporAPNS", package: "apns"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "QRCodeGenerator", package: "swift-qrcode-generator"),
            ],
            path: "Sources/App",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "AppTests",
            dependencies: [
                .target(name: "App"),
                .product(name: "XCTVapor", package: "vapor"),
            ],
            path: "Tests/AppTests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
