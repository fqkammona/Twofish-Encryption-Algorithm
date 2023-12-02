#TwoFish
#Class: CS 4980 Cryptography 
#Name: Fatima Kammona

import numpy as np

'''Initialize the RS and MDS matrices. They are used for the key schedule and the h function.'''
RS_matrix = np.array([
        [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
        [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
        [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
        [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03]
    ])

MDS_matrix = np.array([
        [0x01, 0xEF, 0x5B, 0x5B],
        [0x5B, 0xEF, 0xEF, 0x01],
        [0xEF, 0x5B, 0x01, 0xEF],
        [0xEF, 0x01, 0xEF, 0x5B]
    ])

'''This function initializes the g_q array, which is use in the 'h' function. 
The array is created using the provided permutation tables (t). '''
def twofish_init():
    t = [
        [
            [0x8, 0x1, 0x7, 0xd, 0x6, 0xf, 0x3, 0x2, 0x0, 0xb, 0x5, 0x9, 0xe, 0xc, 0xa, 0x4],
            [0xe, 0xc, 0xb, 0x8, 0x1, 0x2, 0x3, 0x5, 0xf, 0x4, 0xa, 0x6, 0x7, 0x0, 0x9, 0xd],
            [0xb, 0xa, 0x5, 0xe, 0x6, 0xd, 0x9, 0x0, 0xc, 0x8, 0xf, 0x3, 0x2, 0x4, 0x7, 0x1],
            [0xd, 0x7, 0xf, 0x4, 0x1, 0x2, 0x6, 0xe, 0x9, 0xb, 0x3, 0x0, 0x8, 0x5, 0xc, 0xa]
        ],
        [
            [0x2, 0x8, 0xb, 0xd, 0xf, 0x7, 0x6, 0xe, 0x3, 0x1, 0x9, 0x4, 0x0, 0xa, 0xc, 0x5],
            [0x1, 0xe, 0x2, 0xb, 0x4, 0xc, 0x3, 0x7, 0x6, 0xd, 0xa, 0x5, 0xf, 0x9, 0x0, 0x8],
            [0x4, 0xc, 0x7, 0x5, 0x1, 0x6, 0x9, 0xa, 0x0, 0xe, 0xd, 0x8, 0x2, 0xb, 0x3, 0xf],
            [0xb, 0x9, 0x5, 0x1, 0xc, 0x3, 0xd, 0xe, 0x6, 0x4, 0x7, 0xf, 0x2, 0x0, 0x8, 0xa]
        ]
    ]
    
    g_q = [[0] * 256 for _ in range(2)]
    for i in range(256):
        x = i
        a = [0] * 5
        b = [0] * 5

        a[0] = x // 16
        b[0] = x % 16
        a[1] = a[0] ^ b[0]
        b[1] = (a[0] ^ ((b[0] >> 1) | ((b[0] & 1) << 3)) ^ (8 * a[0])) % 16

        for j in range(2):
            a[2] = t[j][0][a[1]]
            b[2] = t[j][1][b[1]]
            a[3] = a[2] ^ b[2]
            b[3] = (a[2] ^ ((b[2] >> 1) | ((b[2] & 1) << 3)) ^ (8 * a[2])) % 16
            a[4] = t[j][2][a[3]]
            b[4] = t[j][3][b[3]]
            g_q[j][x] = (b[4] << 4) + a[4]

    return g_q

'''THis function prompts the user and verifiyes the input key
 is either 128, 192 or 256 bits in length. '''
def input_from_user_key(prompt):
    while True:
        user_input = input(prompt).replace(" ", "").lower()  # Remove spaces and convert to lowercase
        hex_length = len(user_input)
    
        # Check if the length of the string is 32 (128-bit), 48 (192-bit), or 64 (256-bit) characters
        if hex_length in (32, 48, 64) and all(c in '0123456789abcdef' for c in user_input):
            return user_input
        else:
            print("Error: Please enter a valid hex string of 128, 192, or 256 bits in length.")

'''Splits the key into even and odd 32-bit words.'''
def split_key(key):
    key_bytes = bytes.fromhex(key)
    m_even = [int.from_bytes(key_bytes[i:i+4], 'little') for i in range(0, len(key_bytes), 8)]
    m_odd = [int.from_bytes(key_bytes[i:i+4], 'little') for i in range(4, len(key_bytes), 8)]
    return m_even, m_odd


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

def rs_matrix_multiply(key_bytes):
    if isinstance(key_bytes, str):
        key_bytes = [int(key_bytes[i:i+2], 16) for i in range(0, len(key_bytes), 2)]

    # Initialize the S-boxes
    s_boxes = [0] * 4  # Four 32-bit S-boxes

    # Perform RS matrix multiplication
    for i in range(4):  # 4 rows in RS matrix
        for j in range(len(key_bytes)):  # Adjust to the length of key_bytes
            result = galois_multiply(RS_matrix[i][j % 8], key_bytes[j])  # Use modulo for key_bytes longer than 8
            s_boxes[i] ^= result

    return s_boxes


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



'''Multiply two numbers in the GF(2^8) field. '''
def galois_multiply(a, b):
    p = 0
    for counter in range(8):
        if b & 1:
            p ^= a

        high_bit_set = a & 0x80
        a <<= 1
        if high_bit_set:
            a ^= 0x014D  # Reduction polynomial for RS matrix
        a &= 0xFF  # Ensure a remains an 8-bit number

        b >>= 1

    return p


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


def h_function(input_value, key_portion, key_length, q_table, MDS_matrix):
    # Split input_value into 4 bytes
    input_bytes = [(input_value >> (8 * i)) & 0xFF for i in range(4)]

    # Apply the q-tables and key bytes based on the key length
    if key_length >= 4:
        input_bytes = [
            q_table[0 if i == 0 or i == 3 else 1][input_bytes[i]] ^ (key_portion[12 + i] if len(key_portion) > 12 + i else 0)
            for i in range(4)
        ]

    if key_length >= 3:
        input_bytes = [
            q_table[0 if i == 0 or i == 1 else 1][input_bytes[i]] ^ (key_portion[8 + i] if len(key_portion) > 8 + i else 0)
            for i in range(4)
        ]

    input_bytes = [
        q_table[1 if i % 2 == 0 else 0][q_table[1 if i < 2 else 0][input_bytes[i]] ^ (key_portion[4 + i] if len(key_portion) > 4 + i else 0)]
        ^ (key_portion[i] if len(key_portion) > i else 0) for i in range(4)
    ]

    # Perform the MDS matrix multiplication
    mds_output = [0] * 4
    for i in range(4):
        for j in range(4):
            mds_output[i] ^= galois_multiply(MDS_matrix[i][j], input_bytes[j])

    # Combine mds_output into a 32-bit word
    return sum(mds_output[i] << (8 * i) for i in range(4))


def key_schedule(key, g_q, MDS_matrix):
    key_length = len(key) // 8  # Determine key length in words (32-bit words)
    m_even, m_odd = split_key(key)
    s_boxes = rs_matrix_multiply(key)

    print_key_schedule(m_even, m_odd, s_boxes)
    # Key-dependent S-boxes
    for i in range(min(4, len(m_even))):
        s_boxes[i] = h_function(m_even[i], s_boxes, key_length, g_q, MDS_matrix)

    return s_boxes


def print_key_schedule(m_even, m_odd, s_boxes):
    print("Input key\t\t\t\tS-Box Key")
    print("Odd\t\tEven")
    for i in range(len(s_boxes)):
        odd_hex = f"{m_odd[i]:08X}" if i < len(m_odd) else "--------"
        even_hex = f"{m_even[i]:08X}" if i < len(m_even) else "--------"
        s_box_hex = f"{s_boxes[i]:08X}" if i < len(s_boxes) else "--------"
        print(f"{odd_hex}\t{even_hex} -> {s_box_hex}")

if __name__ == "__main__":
    key = input_from_user_key("Enter a hex string of 128, 192, or 256 bits in length: ")
    g_q = twofish_init()
    m_even, m_odd = split_key(key)  # Assuming this gives you the split key parts
    s_boxes = key_schedule(key, g_q, MDS_matrix)
    print_key_schedule(m_even, m_odd, s_boxes)
    # Run the test

    # Run the test
    test_split_key()
  
