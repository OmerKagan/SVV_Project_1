from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

# Initialize the WebDriver (assuming Chrome WebDriver is used)
driver = webdriver.Chrome()

# Open the login page
driver.get("http://127.0.0.1:5000/login")  # Adjust the URL if needed

# Empty Input Login Test
def empty_input_login():
    # Find the email and password input fields and the login button
    email_input = driver.find_element(By.NAME, "email")
    password_input = driver.find_element(By.NAME, "password")
    login_button = driver.find_element(By.XPATH, "//button[contains(text(), 'Login')]")

    # Click on the login button without entering any credentials
    login_button.click()

    # Wait for the error message to be displayed
    error_message = WebDriverWait(driver, 10).until(
        EC.visibility_of_element_located((By.ID, "alertContainer"))
    )

    # Check if error message is displayed
    if "Empty email or password!" in error_message.text:
        print("Empty Input Login test passed: Error message displayed for empty input.")
    else:
        print("Empty Input Login test failed: Error message not displayed for empty input.")

# Perform the Empty Input Login test
empty_input_login()

# Close the browser
driver.quit()
