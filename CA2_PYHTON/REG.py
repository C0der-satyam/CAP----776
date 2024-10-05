import csv
import os
import bcrypt
import re
import yfinance as yf
import getpass
import time
from datetime import datetime

def create_regno_file():
    file_name = 'regno.csv'
    if not os.path.exists(file_name):
        with open(file_name, mode='w', newline='') as file:
            writer = csv.writer(file)
            headers = ['Email', 'Hashed_Password', 'Security_Question', 'Hashed_Answer']
            writer.writerow(headers)
    else:
        print(f"{file_name} already exists!")


def create_log_file():
    file_name = 'log.csv'
    if not os.path.exists(file_name):
        with open(file_name, mode='w', newline='') as file:
            writer = csv.writer(file)
            headers = ['Email', 'Login_Time', 'Logout_Time', 'Ticker_Symbols']
            writer.writerow(headers)
    else:
        print(f"{file_name} already exists!")

def log_user_activity(email, login_time, logout_time=None, ticker_symbols=None):
    ticker_string = ", ".join(ticker_symbols) if ticker_symbols else None
    with open('log.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([email, login_time, logout_time, ticker_string])

def hash(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def check(hashed, user):
    return bcrypt.checkpw(user.encode(), hashed)


def emailed(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email)

def validPass(password):
    return (len(password) >= 8 and
            re.search(r'[A-Z]', password) and
            re.search(r'[a-z]', password) and
            re.search(r'[0-9]', password) and
            re.search(r'[\W]', password))

def get(email):
    with open('regno.csv', mode='r') as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            if row[0] == email:
                return row
    return None

def register():
    email = input("Enter your email: ")
    if not emailed(email):
        print("Invalid email format")
        return
    if get(email):
        print("This email is already registered. Please login!")
        return
    password = getpass.getpass("Enter your password: ")
    password_conf = input("Enter the confirmed password: ")
    if password != password_conf:
        print("Password mismatch")
        return
    if not validPass(password):
        print("Password must contain at least 8 characters, include one uppercase, one lowercase, one number, and one symbol.")
        return
    hash_password = hash(password)

    security = input("Enter a security question (e.g., What is your pet's name?): ")
    security_ans = getpass.getpass("Enter the answer: ")
    hash_answer = hash(security_ans)

    with open('regno.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([email, hash_password.decode(), security, hash_answer.decode()])
    print("Registration successful!")

def update(email, new_pass):
    rows = []
    with open('regno.csv', mode='r') as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            if row[0] == email:
                row[1] = new_pass
            rows.append(row)
    with open('regno.csv', mode='w', newline='') as file:
        csv_writer = csv.writer(file)
        csv_writer.writerows(rows)

def login():
    email = input("Enter your email: ")
    if not emailed(email):
        print("Invalid email format.")
        return False
    user = get(email)
    if not user:
        print("Email not found")
        return False
    attempts = 0
    lock = 1 * 60
    start = None

    while True:
        if start:
            elapsed = time.time() - start
            if elapsed < lock:
                remain = lock - elapsed
                print(f"Too many attempts. Please wait {int(remain)} seconds before trying again.")
                while remain > 0:
                    print(f"Time remaining: {int(remain)} seconds", end='\r')
                    time.sleep(1)
                    remain -= 1
                start = None
                attempts = 0
                continue

        if attempts >= 5:
            print("Too many failed attempts. You are locked for 1 minute.")
            start = time.time()
            continue
        password = getpass.getpass("Enter your password: ")
        if check(user[1].encode(), password): 
            print("Login successful!")
            return email  
        else:
            attempts += 1
            print(f"Invalid password. Attempts remaining: {5 - attempts}")

def forgot():
    email = input("Enter your registered email: ")
    user = get(email)
    if not user:
        print("Email not found.")
        return
    security = user[2]
    security_ans = user[3]

    ans = getpass.getpass(f"{security}: ")
    if check(security_ans.encode(), ans):
        print("Security question answered correctly.")
        new_pass = getpass.getpass("Enter your new password: ")
        if validPass(new_pass):
            hashed = hash(new_pass)
            update(email, hashed.decode())
            print("Password reset successful.")
        else:
            print("Password does not meet criteria.")
    else:
        print("Incorrect answer to the security question.")

def fetch(ticker):
    try:
        stock = yf.Ticker(ticker)
        stock_info = stock.info

        print(f"\nStock Data for {stock_info['longName']} ({ticker}):")
        print(f"Current Price: {stock_info['currentPrice']}")
        print(f"Open Price: {stock_info['open']}")
        print(f"High Price: {stock_info['dayHigh']}")
        print(f"Low Price: {stock_info['dayLow']}")
        print(f"Previous Close: {stock_info['regularMarketPreviousClose']}")
        print(f"Volume: {stock_info['volume']}")
    except KeyError:
        print("Error: Stock data not available.")
    except Exception as e:
        print(f"Error fetching stock data: {e}")
    return

def main():
    create_regno_file()  
    create_log_file()   

    print("Welcome to the Stock Market App")

    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Forgot Password")
        print("4. Exit")
        choice = input("Select an option: ")
        if choice == '1':
            register()
        elif choice == '2':
            email = login() 
            if email:
                login_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ticker_symbols = []  
                while True:
                    print("\n--- Logged In Menu ---")
                    print("1. Fetch Stock Data")
                    print("2. Logout") 
                    inner_choice = input("Select an option: ")

                    if inner_choice == '1':
                        ticker_symbol = input("Enter company ticker symbol (e.g., AAPL, MSFT): ")
                        ticker_symbols.append(ticker_symbol) 
                        fetch(ticker_symbol)
                    elif inner_choice == '2':  
                        logout_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        log_user_activity(email, login_time, logout_time, ticker_symbols)  
                        print(f"Logged out {email}")
                        break
                    else:
                        print("Invalid option. Please try again.")
        elif choice == '3':
            forgot()
        elif choice == '4':
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
