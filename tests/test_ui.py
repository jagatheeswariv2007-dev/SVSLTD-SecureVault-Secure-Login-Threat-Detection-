"""
Optional browser-level smoke tests using Playwright.
First install Chromium: python -m playwright install chromium
Start the app in a separate terminal: python app.py
Then run: python -m pytest tests/test_ui.py -q
"""
import os
import pytest
from playwright.sync_api import sync_playwright

BASE_URL = os.environ.get("SECUREVAULT_BASE_URL", "http://127.0.0.1:5000")


def test_home_page_and_navigation():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        response = page.goto(BASE_URL, wait_until="domcontentloaded")
        assert response is not None and response.status == 200
        assert page.get_by_role("heading", name="Protect accounts. Notice suspicious activity.").is_visible()
        page.get_by_role("link", name="Create demo account").click()
        assert page.get_by_role("heading", name="Create a demo account").is_visible()
        browser.close()


def test_registration_form_validation_message():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(BASE_URL)
        page.get_by_role("link", name="Register").click()
        page.get_by_label("Username").fill("ui_test_user")
        page.get_by_label("Password").fill("weakpass12")
        page.get_by_role("button", name="Register securely").click()
        assert page.get_by_text("Use at least 10 characters", exact=False).is_visible()
        browser.close()
