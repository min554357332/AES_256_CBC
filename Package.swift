// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "AES_256_CBC",
    platforms: [
            .iOS(.v13),
            .macOS(.v10_15),
        ],
    products: [
        .library(
            name: "AES_256_CBC",
            targets: ["AES_256_CBC"]),
    ],
    targets: [
        .target(
            name: "AES_256_CBC"),

    ]
)
