// swift-tools-version:5.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "blades",
    platforms: [
        .macOS(.v10_14),
    ],
    products: [
        .executable(
            name: "blades",
            targets: [ "blades" ]
        ),
    ],
    targets: [
        .target(
            name: "libCapstone",
            path: "WBBlades/Capstone"
        ),
        .target(
            name: "blades",
            dependencies: [ "libCapstone" ],
            path: "WBBlades",
            exclude: [ "Capstone" ],
            cSettings: [
                .headerSearchPath("."),
                .headerSearchPath("Tools"),
                .headerSearchPath("Model"),
                .headerSearchPath("Link"),
                .headerSearchPath("Scan")
            ]
        )
    ],
    cLanguageStandard: .gnu11,
    cxxLanguageStandard: .gnucxx14
)
