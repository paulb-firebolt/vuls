#!/usr/bin/env python3
"""
Test script to debug authentication issues with the hosts API
"""

import requests
import json
import sys

def test_login_and_hosts_api():
    """Test login and then try to access the hosts API"""
    base_url = "http://localhost:8000"

    print("=== Authentication Debug Test ===")

    # Step 1: Try to login
    print("\n1. Testing login...")
    login_data = {
        "username": "admin",
        "password": "admin123"
    }

    try:
        # Try form-based login
        login_response = requests.post(
            f"{base_url}/api/auth/login-form",
            data=login_data,
            allow_redirects=False
        )
        print(f"Login response status: {login_response.status_code}")
        print(f"Login response headers: {dict(login_response.headers)}")

        # Get cookies from login
        cookies = login_response.cookies
        print(f"Cookies received: {dict(cookies)}")

        # Step 2: Try to access hosts API with cookies
        print("\n2. Testing hosts API with cookies...")
        hosts_response = requests.get(
            f"{base_url}/api/hosts/detailed",
            cookies=cookies
        )
        print(f"Hosts API response status: {hosts_response.status_code}")
        print(f"Hosts API response headers: {dict(hosts_response.headers)}")

        if hosts_response.status_code == 200:
            print("SUCCESS: Hosts API worked with cookies!")
            data = hosts_response.json()
            print(f"Response data keys: {list(data.keys())}")
        else:
            print(f"FAILED: Hosts API returned {hosts_response.status_code}")
            print(f"Response text: {hosts_response.text}")

    except Exception as e:
        print(f"Error during login test: {e}")

    # Step 3: Try JWT token login
    print("\n3. Testing JWT token login...")
    try:
        token_response = requests.post(
            f"{base_url}/api/auth/login",
            data={"username": "admin", "password": "admin123"}
        )
        print(f"Token login status: {token_response.status_code}")

        if token_response.status_code == 200:
            token_data = token_response.json()
            access_token = token_data.get("access_token")
            print(f"Access token received: {access_token[:20]}..." if access_token else "No token")

            # Try hosts API with Bearer token
            print("\n4. Testing hosts API with Bearer token...")
            headers = {"Authorization": f"Bearer {access_token}"}
            hosts_response = requests.get(
                f"{base_url}/api/hosts/detailed",
                headers=headers
            )
            print(f"Hosts API with token status: {hosts_response.status_code}")

            if hosts_response.status_code == 200:
                print("SUCCESS: Hosts API worked with Bearer token!")
                data = hosts_response.json()
                print(f"Response data keys: {list(data.keys())}")
            else:
                print(f"FAILED: Hosts API returned {hosts_response.status_code}")
                print(f"Response text: {hosts_response.text}")
        else:
            print(f"Token login failed: {token_response.text}")

    except Exception as e:
        print(f"Error during token test: {e}")

    # Step 5: Test without authentication
    print("\n5. Testing hosts API without authentication...")
    try:
        no_auth_response = requests.get(f"{base_url}/api/hosts/detailed")
        print(f"No auth response status: {no_auth_response.status_code}")
        print(f"No auth response text: {no_auth_response.text}")
    except Exception as e:
        print(f"Error during no-auth test: {e}")

if __name__ == "__main__":
    test_login_and_hosts_api()
