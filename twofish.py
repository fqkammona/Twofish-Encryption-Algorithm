#TwoFish
#Class: CS 4980 Cryptography 
#Name: Fatima Kammona

def input_from_user(prompt, length):
    while True:
        user_input = input(prompt)
        if all((letter in "01") for letter in user_input) and len(user_input) == length:
            return user_input
        print(f"Error: Please enter a {length}-bit binary number.")

def print_summary(key, plaintext):
    print(f"Key: {key}")
    print(f"PT: {plaintext}")

if __name__ == "__main__":
    key = input_from_user("Enter 32-bit Key: ", 32)
    plaintext = input_from_user("Enter 32-bit Plantext: ", 32)
    