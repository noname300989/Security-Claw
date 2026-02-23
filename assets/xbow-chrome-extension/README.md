# XBOW Autonomous Pentesting Chrome Extension

A lightweight, standalone Chrome extension that allows you to instantly trigger an XBOW autonomous security assessment against the website you are currently viewing.

## Setup

1. Open Chrome and navigate to `chrome://extensions`
2. Toggle **Developer mode** in the top right corner.
3. Click **Load unpacked** and select the `/Users/gayatrirachakonda/Security Claw/assets/xbow-chrome-extension` directory.
4. Pin the extension to your toolbar.

## Usage

1. Navigate to the website you want to test (ensure you have authorization).
2. Click the XBOW extension icon.
3. Enter your `XBOW_API_KEY` (this is saved locally in your browser for future use).
4. Click **Launch Autonomous Scan**.
5. Watch the swarm analyze the attack surface and retrieve verified exploits!

> **Note:** The extension communicates directly with the XBOW public API (`api.xbow.com`). It does not require the OpenClaw gateway to be running.
