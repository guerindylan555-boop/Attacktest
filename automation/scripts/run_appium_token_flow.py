#!/usr/bin/env python3
"""Automated unlock/lock flow driven with Appium."""

import os
import sys
from datetime import datetime

from appium import webdriver
from appium.webdriver.common.appiumby import AppiumBy
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

DEFAULT_SERVER = os.getenv("MAYNDRIVE_APPIUM_SERVER", "http://127.0.0.1:4723/wd/hub")
APP_PACKAGE = os.getenv("MAYNDRIVE_APP_PACKAGE", "fr.mayndrive.app")
APP_ACTIVITY = os.getenv(
    "MAYNDRIVE_APP_ACTIVITY", "city.knot.knotapp.ui.MainActivity"
)

SELECTORS = {
    "email": os.getenv("MAYNDRIVE_SELECTOR_EMAIL", "fr.mayndrive.app:id/email"),
    "password": os.getenv("MAYNDRIVE_SELECTOR_PASSWORD", "fr.mayndrive.app:id/password"),
    "login": os.getenv("MAYNDRIVE_SELECTOR_LOGIN", "fr.mayndrive.app:id/login"),
    "unlock": os.getenv("MAYNDRIVE_SELECTOR_UNLOCK", "fr.mayndrive.app:id/unlock"),
    "lock": os.getenv("MAYNDRIVE_SELECTOR_LOCK", "fr.mayndrive.app:id/lock"),
}

CREDENTIALS = {
    "email": os.getenv("MAYNDRIVE_TEST_EMAIL", ""),
    "password": os.getenv("MAYNDRIVE_TEST_PASSWORD", ""),
}

TIMEOUT_S = int(os.getenv("MAYNDRIVE_APPIUM_TIMEOUT", "30"))


def log(message: str) -> None:
    timestamp = datetime.utcnow().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")
    sys.stdout.flush()


def ensure_selector(name: str) -> str:
    locator = SELECTORS.get(name)
    if not locator:
        raise ValueError(
            f"Selector for '{name}' is missing. Set MAYNDRIVE_SELECTOR_{name.upper()}"
        )
    return locator


def build_driver() -> webdriver.Remote:
    desired_caps = {
        "platformName": "Android",
        "automationName": os.getenv("MAYNDRIVE_AUTOMATION_NAME", "UiAutomator2"),
        "deviceName": os.getenv("MAYNDRIVE_DEVICE_NAME", "Android Emulator"),
        "appPackage": APP_PACKAGE,
        "appActivity": APP_ACTIVITY,
        "noReset": os.getenv("MAYNDRIVE_NO_RESET", "true").lower() == "true",
        "newCommandTimeout": int(os.getenv("MAYNDRIVE_NEW_COMMAND_TIMEOUT", "180")),
    }

    log(f"Connecting to Appium server at {DEFAULT_SERVER}")
    driver = webdriver.Remote(DEFAULT_SERVER, desired_caps)
    driver.implicitly_wait(5)
    return driver


def wait_for(driver: webdriver.Remote, strategy: str, locator: str, action: str):
    try:
        return WebDriverWait(driver, TIMEOUT_S).until(
            EC.presence_of_element_located((strategy, locator))
        )
    except TimeoutException as exc:
        raise TimeoutException(f"Timed out waiting for {action} using {locator}") from exc


def send_keys(el, value: str, label: str) -> None:
    el.clear()
    el.send_keys(value)
    log(f"Filled {label}")


def tap(el, label: str) -> None:
    el.click()
    log(f"Tapped {label}")


def must_have_credentials() -> None:
    missing = [key for key, value in CREDENTIALS.items() if not value]
    if missing:
        raise RuntimeError(
            "Missing credentials: "
            + ", ".join(missing)
            + ". Set MAYNDRIVE_TEST_EMAIL / MAYNDRIVE_TEST_PASSWORD."
        )


def run():
    must_have_credentials()
    driver = build_driver()
    try:
        log("Waiting for login form")
        email_field = wait_for(
            driver,
            AppiumBy.ID,
            ensure_selector("email"),
            "email field",
        )
        password_field = wait_for(
            driver,
            AppiumBy.ID,
            ensure_selector("password"),
            "password field",
        )
        send_keys(email_field, CREDENTIALS["email"], "email")
        send_keys(password_field, CREDENTIALS["password"], "password")

        login_button = wait_for(
            driver,
            AppiumBy.ID,
            ensure_selector("login"),
            "login button",
        )
        tap(login_button, "login")

        unlock_locator = SELECTORS.get("unlock")
        if unlock_locator:
            unlock_button = wait_for(
                driver,
                AppiumBy.ID,
                unlock_locator,
                "unlock button",
            )
            tap(unlock_button, "unlock")
        else:
            log("No unlock selector provided; skipping unlock click")

        lock_locator = SELECTORS.get("lock")
        if lock_locator:
            lock_button = wait_for(
                driver,
                AppiumBy.ID,
                lock_locator,
                "lock button",
            )
            tap(lock_button, "lock")
        else:
            log("No lock selector provided; skipping lock click")

        log("Appium flow complete")
    except (TimeoutException, NoSuchElementException, ValueError, RuntimeError) as exc:
        log(f"[ERROR] {exc}")
        raise
    finally:
        driver.quit()
        log("Appium session closed")


if __name__ == "__main__":
    run()
