# Battle.net TOTP Generator

## Overview

This script was created to simplify the process of generating a Time-based One-Time Password (TOTP) URL for Battle.net. It facilitates the two-factor authentication (2FA) setup for your Blizzard account, enabling secure access through an authenticator app by converting your device secret into a usable format.

## Purpose

Battle.net provides an option to enable two-factor authentication (2FA) using an authenticator app. This script helps generate the necessary TOTP URL, streamlining the process of setting up 2FA. By providing the TOTP URL, you can configure your authenticator app to generate valid one-time passwords (OTP) for your Battle.net account.

## Features

- **Generates TOTP URL** for Battle.net.
- **Converts device secrets** into Base32 format, required by authenticator apps.
- **Step-by-step guidance** to help users through the process.

## How to Use

### Prerequisites

Before running the script, make sure you have the following:

1. **Python 3.x** installed on your system.
2. The **`requests`** Python package (the script will prompt to install this if it's missing).

### Installation

1. Clone or download the repository:
    ```bash
    git clone [https://github.com/ShinobiCat/bliz_totp.git]
    ```

2. Navigate to the script folder:
    ```bash
    cd <script-folder>
    ```

3. Install any missing modules:
    If any required modules are missing (e.g., `requests`), the script will automatically prompt you to install them.

### Running the Script

1. Run the script in your terminal or command prompt:
    ```bash
    python bliz_totp.py
    ```

2. The script will guide you step by step:
    - You will be asked to choose your region (EU or US).
    - You will need to enter an **ST token** after logging into Battle.net.
    - The script will generate a TOTP URL and guide you to set up your authenticator.

### Example Flow:

- **Step 1:** Choose your region (EU or US).
- **Step 2:** Log in to your Battle.net account and retrieve the ST token from your browser's address bar.
- **Step 3:** Enter the ST token into the script.
- **Step 4:** The script will generate a TOTP URL which you can scan with your authenticator app.

## Troubleshooting

- **Missing modules:** If you see an error about missing modules, the script will ask if you want to install them automatically.
- **Invalid ST token:** Ensure that the ST token is entered correctly. It must follow the format: `<region>-<30-alphanumeric-characters>-<9-numeric-characters>`.

## License

This script is provided under the MIT License. Feel free to modify and adapt it as needed for your personal use.
