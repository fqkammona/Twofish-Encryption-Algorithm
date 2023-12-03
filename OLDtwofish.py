#TwoFish
#Class: CS 4980 Cryptography 
#Name: Fatima Kammona

import numpy as np

import galois


def input_from_user_key(prompt):
    while True:
        user_input = input(prompt).replace(" ", "").lower()  # Remove spaces and convert to lowercase
        hex_length = len(user_input)
    
        # Check if the length of the string is 32 (128-bit), 48 (192-bit), or 64 (256-bit) characters
        if hex_length in (32, 48, 64) and all(c in '0123456789abcdef' for c in user_input):
            return user_input
        else:
            print("Error: Please enter a valid hex string of 128, 192, or 256 bits in length.")

# This function creates the s0 and s1 boxes
# Calls create_s0_s1
# takes the user input key 
def key_schedule_s(key):
    # Break up the key by twos and convert to integers
    key_array = [key[i:i+2] for i in range(0, len(key), 2)]
    half_length = int(len(key_array)/ 2) 

    key_first_half = key_array[:half_length]
    key_second_half = key_array[half_length:]

    size = int(half_length / 4)
    s0_matrix = create_s0_s1(key_first_half, size)
    s1_matrix = create_s0_s1(key_second_half, size)
    
    print(s0_matrix)
    print(s1_matrix)

    
# Takes a part of the key that is being multiplied 
# Takes the size needed to reshape 
#  Size is either 2,3,4
def create_s0_s1(key_section, size):
    RS_matrix = np.array([
        [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
        [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
        [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
        [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03]
    ])

    second_matrix = np.array([int(value, 16) for value in key_section]).reshape(4, size) 
    # reshape(4, 3) method in NumPy is used to change the shape of an array. 
    # When you apply reshape(4, 3) to an array, 
    # you are transforming the array into a new shape with 4 rows and 3 columns
    # hexadecimal(base16) 
    expanded_second_matrix = np.repeat(second_matrix, len(key_section), axis=1)
    
    # Perform element-wise multiplication in GF(2^8)
    gf_result_matrix = np.zeros_like(RS_matrix)

    for i in range(RS_matrix.shape[0]):
        for j in range(RS_matrix.shape[1]):
            # Performing GF(2^8) multiplication with the corresponding element in the expanded second matrix
            gf_result_matrix[i, j] = galois_multiply(RS_matrix[i, j], expanded_second_matrix[i, j % 2])

    return gf_result_matrix

# Multiply two numbers in the GF(2^8) field. 
def galois_multiply(a, b):
    p = 0
    for counter in range(8):
        if b & 1:
            p ^= a
        carry = a & 0x80
        a <<= 1
        if carry:
            a ^= 0xAD # irreducible polynomial (x^8 + x^6 + x^3 + x^2 + 1)
        b >>= 1
    return p % 256

def key_schedule(key):
    key_schedule_s(key)

if __name__ == "__main__":
    key = input_from_user_key("Enter a hex string of 128, 192, or 256 bits in length: ")
    print(f"key {key}")
    key_schedule(key)
    def test_rs_matrix_multiply():
    test_key = "0123456789ABCDEF"  # A simple 128-bit test key
    expected_s_boxes = [0x12345678, 0x9ABCDEF0, 0x11223344, 0x55667788]  # Placeholder values

    # Convert the test key to bytes
    key_bytes = [int(test_key[i:i+2], 16) for i in range(0, len(test_key), 2)]

    # Get the S-boxes using RS matrix multiplication
    s_boxes = rs_matrix_multiply(key_bytes)

    # Compare each S-box with the expected value
    for i, s_box in enumerate(s_boxes):
        assert s_box == expected_s_boxes[i], f"RS Matrix multiplication failed for S{i}. Expected: {expected_s_boxes[i]:08X}, got: {s_box:08X}"

    print("RS Matrix multiplication test passed.")

    def test_galois_multiply():
    # Test cases as (a, b, expected_result)
    test_cases = [
        (0x57, 0x83, 0xc1),  # Example values from GF(2^8)
        (0x01, 0x01, 0x01),  # Testing with identity
        (0x00, 0x83, 0x00),  # Testing with zero
        # Add more test cases here
    ]

    for a, b, expected in test_cases:
        result = galois_multiply(a, b)
        assert result == expected, f"Failed for galois_multiply({a}, {b}): expected {expected}, got {result}"

def test_split_key():
    test_key = "0123456789ABCDEFFEDCBA98765432100011223344556677"
    
    # Expected output (in little-endian format)
    expected_even = [0x67452301, 0x98BADCFE, 0x33221100]  # Reversed order
    expected_odd = [0xEFCDAB89, 0x10325476, 0x77665544]   # Reversed order

    # Split the key using your function
    even, odd = split_key(test_key)

    # Compare the results
    assert even == expected_even, f"Even words do not match. Expected {expected_even}, got {even}"
    assert odd == expected_odd, f"Odd words do not match. Expected {expected_odd}, got {odd}"

    print("Test passed: split_key function works correctly.")