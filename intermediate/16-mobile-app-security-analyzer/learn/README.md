# Learn — mobile manifest risk indicators

## Manifests as an attack surface map

An app manifest declares what the app is allowed to do and what other apps can reach. Reviewing it statically is a quick way to find over-privilege and accidental exposure before shipping.

## Excessive permissions

Permissions such as SMS access, fine location, contacts, and audio recording are high value. A manifest that requests them without a clear feature justification should be questioned, especially when the data leaves the device.

## Cleartext traffic

Unencrypted HTTP permits eavesdropping and tampering. Android exposes this through `usesCleartextTraffic` and network security configuration; iOS has App Transport Security exceptions. Treat a permissive setting as a high-severity finding.

## Exported components

An exported activity, service, receiver, or provider can be invoked by other apps on the device. If it performs privileged work without its own permission check, it becomes a bridge around the app's UI controls.

## Secure flags

`allowBackup`, `debuggable`, and cleartext permissions should be explicitly set to safe values. Missing keys are suspicious because platform defaults are not always the hardened choice.

## Scope

This analyzer works on a simplified JSON projection of a manifest. Real reviews also need code analysis, dependency checks, and runtime testing.
