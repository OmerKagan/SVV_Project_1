from selenium import webdriver
from selenium.webdriver.common.by import By
import time

# Initialize the WebDriver
driver = webdriver.Chrome()

# Open the login page
driver.get("http://127.0.0.1:5000/login")

# Find the "Login with Google" button
google_login_button = driver.find_element(By.XPATH, "//button[contains(text(), 'Login with Google')]")

# Click on the "Login with Google" button
google_login_button.click()

# Wait for Google authentication page to load
time.sleep(2)

# Check if redirection to Google authentication page is successful
if "accounts.google.com" in driver.current_url:
    print("Google Authentication Page opened successfully. Assuming user is prompted to log in.")
else:
    print("Google Authentication Page not opened. Verification failed.")

# Close the browser
driver.quit()
