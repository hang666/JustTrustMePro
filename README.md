# JustTrustMePro

JustTrustMePro is an Xposed module that allows Android applications to bypass SSL certificate validation. This tool is particularly useful for security researchers, developers performing app analysis, and for debugging encrypted traffic in development environments.

## Features

- Bypasses SSL certificate pinning mechanisms in Android applications
- Works with various HTTP libraries including OkHttp, Apache HTTP, and Android's native implementations
- Hooks into WebView and other secure connection methods
- Compatible with modern Android versions
- Minimal impact on application performance

## Installation

### Prerequisites

- A rooted Android device
- Xposed Framework (or alternatives like LSPosed/EdXposed) installed and working

### Installation Steps

1. Download the latest APK from the [Releases](https://github.com/hang666/JustTrustMePro/releases) section
2. Install the APK on your device
3. Enable the module in Xposed Installer (or equivalent)
4. Reboot your device
5. Select target apps in the module settings (if available)

## Building from Source

### Building Steps

1. Clone the repository: ```git clone https://github.com/hang666/JustTrustMePro.git```
2. Open the project in Android Studio
3. Sync the Gradle files
4. Build using: ```./gradlew assembleDebug```
5. Find the compiled APK in `app/build/outputs/apk/debug/`

## Usage

After installation and configuration:

1. Start the target application
2. The module will automatically hook into the SSL validation process
3. Certificate validation will be bypassed, allowing you to inspect encrypted traffic using tools like mitmproxy

## Disclaimer

JustTrustMePro is intended solely for security research, application development, and debugging purposes. Users are responsible for ensuring they comply with all applicable laws and regulations when using this tool.

The developers assume no liability for any misuse of this software. Use at your own risk and only on applications you own or have permission to test.

## Credits

- [Xposed Framework](https://github.com/rovo89/Xposed)
- [JustTrustMe](https://github.com/Fuzion24/JustTrustMe)
- [JustTrustMePP](https://github.com/JunGe-Y/JustTrustMePP)
