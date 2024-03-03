from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

# Initialize the WebDriver (assuming Chrome WebDriver is used)
driver = webdriver.Chrome()

# Open the login page
driver.get("http://127.0.0.1:5000/login")  # Adjust the URL if needed

# Wait for the email input field to be visible
email_input = WebDriverWait(driver, 10).until(
    EC.visibility_of_element_located((By.NAME, "email"))
)

# Find the password input field
password_input = driver.find_element(By.NAME, "password")

# Find the login button
login_button = driver.find_element(By.XPATH, "//button[contains(text(), 'Login')]")

# Input valid email and password
email_input.send_keys("user1@login.com")
password_input.send_keys("password1")

# Click on the login button
login_button.click()

# Wait for the login process to complete
time.sleep(2)

# Check if redirection to the entry page is successful
if driver.current_url == "http://127.0.0.1:5000/entry-page":
    print("Valid Credentials Login test passed: User successfully logged in.")
else:
    print("Valid Credentials Login test failed: User login unsuccessful.")

# Close the browser
driver.quit()
