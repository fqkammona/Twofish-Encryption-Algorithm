#TwoFish
#Class: CS 4980 Cryptography 
#Name: Fatima Kammona

def input_from_user_key(prompt):
    while True:
        user_input = input(prompt).replace(" ", "").lower()  # Remove spaces and convert to lowercase
        hex_length = len(user_input)
    
        # Check if the length of the string is 32 (128-bit), 48 (192-bit), or 64 (256-bit) characters
        if hex_length in (32, 48, 64) and all(c in '0123456789abcdef' for c in user_input):
            return user_input
        else:
            print("Error: Please enter a valid hex string of 128, 192, or 256 bits in length.")

def key_schedule_s(key):
    RS_matrix = [
    [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
    [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
    [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
    [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03]
    ]

    # Break up the key by twos and convert to integers
    key_array = [key[i:i+2] for i in range(0, len(key), 2)]
    key_length = int(len(key_array) / 2) 

    key_first_half = key_array[:key_length]
    key_second_half = key_array[key_length:]

def key_schedule(key):
    key_schedule_s(key)

if __name__ == "__main__":
    key = input_from_user_key("Enter a hex string of 128, 192, or 256 bits in length: ")
    print(f"key {key}")
    key_schedule(key)
    