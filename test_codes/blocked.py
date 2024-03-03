from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

driver = webdriver.Chrome()

# Open the login page
driver.get("http://127.0.0.1:5000/login")

def find_element(by, value):
    return WebDriverWait(driver, 10).until(EC.visibility_of_element_located((by, value)))

# Find the email input field
email_input = find_element(By.NAME, "email")

# Find the password input field
password_input = find_element(By.NAME, "password")

# Find the login button
login_button = find_element(By.XPATH, "//button[contains(text(), 'Login')]")

# Attempt login with wrong password 5 times
for _ in range(5):
    # Find the email input field before interacting with it
    email_input = find_element(By.ID, "email")
    email_input.clear()  # Clear email input
    email_input.send_keys("user1@login.com")

    # Find the password input field
    password_input = find_element(By.ID, "password")
    password_input.clear()  # Clear password input
    password_input.send_keys("wrong_password")

    # Find and click the login button
    login_button = find_element(By.XPATH, "//button[contains(text(), 'Login')]")
    login_button.click()

    time.sleep(1)  # Wait for the result

# Attempt to login with a valid password during the blocked time
email_input = find_element(By.ID, "email")
email_input.clear()
email_input.send_keys("user1@login.com")

password_input = find_element(By.ID, "password")
password_input.clear()
password_input.send_keys("password1")

login_button = find_element(By.XPATH, "//button[contains(text(), 'Login')]")
login_button.click()

time.sleep(2)  # Wait for the result

# Check if redirection to the entry page is successful
if driver.current_url == "http://127.0.0.1:5000/entry-page":  # Adjust the URL if needed
    print("Test failed: User successfully logged in during the blocked time.")
else:
    print("Test passed: User login unsuccessful during the blocked time.")

# Wait for 60 seconds for the block to expire
print("Waiting for 60 seconds for the block to expire...")
time.sleep(60)

# Attempt to login again after the block expiration
email_input = find_element(By.ID, "email")
email_input.clear()
email_input.send_keys("user1@login.com")

password_input = find_element(By.ID, "password")
password_input.clear()
password_input.send_keys("password1")

login_button = find_element(By.XPATH, "//button[contains(text(), 'Login')]")
login_button.click()

time.sleep(2)  # Wait for the result

# Check if redirection to the entry page is successful
if driver.current_url == "http://127.0.0.1:5000/entry-page":  # Adjust the URL if needed
    print("Test passed: User successfully logged in after the block expiration.")
else:
    print("Test failed: User login unsuccessful even after the block expiration.")

# Close the browser
driver.quit()
