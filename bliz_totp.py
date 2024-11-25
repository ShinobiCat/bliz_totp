# bliz_totp.py
import subprocess
import sys

# List of required modules
required_modules = ['atexit', 'base64', 'gc', 'logging', 'os', 're', 'requests', 'time']

def check_and_install_modules(modules):
    """Check if required modules are installed and install if missing."""
    for module in modules:
        try:
            __import__(module)
        except ImportError:
            print(f"Module '{module}' not found. Installing...")
            install_module(module)

def install_module(module):
    """Install a specific module using pip."""
    subprocess.check_call([sys.executable, "-m", "pip", "install", module])

# Check and install missing modules
check_and_install_modules(required_modules)

# import modules after ensuring they are installed
import atexit
import base64
import gc
import logging
import os
import re
import requests
import time

# Configure logging to avoid saving logs
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Clear existing handlers to prevent duplication
if logger.hasHandlers():
    logger.handlers.clear()

# Add a StreamHandler for console-only output
stream_handler = logging.StreamHandler()
formatter = logging.Formatter('%(message)s')
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

# Constants
EU_URL = "https://eu.account.battle.net/login/en/?ref=localhost"
US_URL = "https://us.account.battle.net/login/en/?ref=localhost"
OAUTH_URL = "https://oauth.battle.net/oauth/sso"
AUTHENTICATOR_URL = "https://authenticator-rest-api.bnet-identity.blizzard.net/v1/authenticator"
CLIENT_ID = "baedda12fe054e4abdfc3ad7bdea970a"

def main():
    """Main function to drive the script."""
    clear_screen()
    print(f"I am an element found at the core of technology (SiO₂)")
    print()
    time.sleep(1)
    print(f"Like a synapse, I connect two worlds.")
    print()
    time.sleep(2)
    print(f"33.6053, 117.7114")
    print()
    time.sleep(3)
    clear_screen()
    logger.info("Welcome! This script generates a TOTP URL for Battle.net.")
    print()

    try:
        region = get_region()
        url = EU_URL if region == 'eu' else US_URL

        logger.info(f"Visit the following URL to log in: {url}")
        print()
        logger.info("After logging in, copy the code starting with 'ST=' from your address bar.")
        print()

        st_token = input("Enter the ST code: ").strip()
        if not validate_st_token(st_token, region):
            logger.error("Invalid ST code format. Exiting.")
            print()
            sys.exit(1)
        logger.info(f"ST code provided: {st_token}")
        print()

        # Generate access token
        access_token = generate_bearer(st_token)
        if not access_token:
            logger.error("Failed to retrieve access token. Exiting.")
            print()
            sys.exit(1) 
            
        devicesecret = generate_dev_secret(access_token)
        if not devicesecret:
            logger.error("Failed to retrieve device secret. Exiting.")
            print()
        sys.exit(1)    
            
        base32_string = generate_base32(devicesecret)
        if not base32_string:
            logger.error("Failed to convert device secret to Base32. Exiting.")
            print()
        sys.exit(1)    

        generate_totp(base32_string)

        # Clear sensitive data
        del st_token, access_token, devicesecret, base32_string
        gc.collect()
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        print()

def get_region():
    """Prompt the user to choose a region."""
    while True:
        region = input("Choose a region (eu or us): ").strip().lower()
        if region in ['eu', 'us']:
            return region
        logger.warning("Invalid input. Please choose 'eu' or 'us'.")
        print()

def validate_st_token(st_token, region):
    """
    Validate the ST token format.

    Format example: EU-00x0xx0x000000x000000x0xd0xx0x-123456789
    - Starts with the region (e.g., EU- or US-).
    - Followed by 30 alphanumeric characters.
    - Ends with a hyphen and 9 numeric characters.
    """
    pattern = rf"^{region.upper()}-[a-fA-F0-9]{{30}}-\d{{9}}$"
    if re.match(pattern, st_token):
        return True
    return False

def generate_bearer(st_token):
    """
    Generate a bearer token using the provided ST token.
    :param st_token: The session token (ST code) from the login URL.
    :return: Bearer access token if successful, otherwise None.
    """
    headers = {
        "content-type": "application/x-www-form-urlencoded; charset=utf-8"
    }
    data = {
        "client_id": CLIENT_ID,
        "grant_type": "client_sso",
        "scope": "auth.authenticator",
        "token": st_token
    }

    try:
        response = requests.post(OAUTH_URL, headers=headers, data=data)
        response.raise_for_status()
        response_data = response.json()
        if response_data.get("token_type") == "bearer":
            access_token = response_data.get("access_token")
            logger.info("Access token retrieved successfully.")
            print()
            logger.info(f"Bearer token: {access_token}")
            print()
            return access_token
        else:
            logger.error("Unexpected token type: Not a bearer token.")
            print()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch bearer token: {e}")
        print()
    return None

def generate_dev_secret(access_token):
    """
    Generate a device secret using the access token.
    :param access_token: Bearer access token.
    :return: Device secret if successful, otherwise None.
    """
    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {access_token}"
    }

    try:
        response = requests.post(AUTHENTICATOR_URL, headers=headers)
        response.raise_for_status()
        response_data = response.json()
        devicesecret = response_data.get("deviceSecret")
        if devicesecret:
            logger.info("Device secret retrieved successfully.")
            print()
            logger.info(f"Device secret: {devicesecret}")
            print()
            return devicesecret
        else:
            logger.error("Device secret not found in the response.")
            print()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch device secret: {e}")
        print()
    return None

def generate_base32(device_secret):
    """
    Convert the device secret (hex) to a Base32 string.
    :param device_secret: Hexadecimal device secret.
    :return: Base32 encoded string.
    """
    try:
        hex_bytes = bytes.fromhex(device_secret)
        base32_string = base64.b32encode(hex_bytes).decode()
        logger.info("Device secret successfully converted to Base32.")
        print()
        return base32_string
    except ValueError as e:
        logger.error(f"Failed to convert device secret to Base32: {e}")
        print()
    return None

def generate_totp(base32_string):
    """
    Generate and log the TOTP URL.
    :param base32_string: Base32 encoded device secret.
    """
    totp_url = f"otpauth://totp/Battle.net?secret={base32_string}&digits=8"
    logger.info(f"TOTP URL generated: {totp_url}")
    print()

def clear_memory():
    """Securely clear cache and sensitive data on exit."""
    logger.info("Clearing sensitive data and cache.")
    print()
    gc.collect()

def countdown_and_clear_screen():
    """Countdown timer before clearing the screen."""
    countdown = 30  # Countdown time in seconds
    logger.info(f"Screen will be cleared in {countdown} seconds.")
    print()
    
    while countdown > 0:
        logger.info(f"{countdown} seconds remaining before screen is cleared...")
        time.sleep(1)  # Wait for 1 second
        countdown -= 1
    
    # Clear the screen after countdown
    clear_screen()

def clear_screen():
    """Clear the terminal screen."""
    if sys.platform == 'win32':
        os.system('cls')  # For Windows
    else:
        os.system('clear')  # For Unix-like systems (macOS, Linux)

# Register cleanup function to be called at exit
atexit.register(clear_memory)

if __name__ == "__main__":
    main()