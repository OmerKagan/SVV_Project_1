from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

# Initialize the WebDriver
driver = webdriver.Chrome()

# Open the login page
driver.get("http://127.0.0.1:5000/login")

# Find the email and password input fields and the login button
email_input = driver.find_element(By.NAME, "email")
password_input = driver.find_element(By.NAME, "password")
login_button = driver.find_element(By.XPATH, "//button[contains(text(), 'Login')]")

# Input invalid email and password
email_input.send_keys("invalid_user@login.com")
password_input.send_keys("invalid_password")

# Click on the login button
login_button.click()

# Wait for the error message to be displayed
error_message = WebDriverWait(driver, 10).until(
    EC.visibility_of_element_located((By.ID, "alertContainer"))
)

# Check if error message is displayed
if "Invalid email or password!" in error_message.text:
    print("Invalid Credentials Login test passed: Error message displayed for invalid credentials.")
else:
    print("Invalid Credentials Login test failed: Error message not displayed for invalid credentials.")

# Close the browser
driver.quit()
