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

def rotl(x, r):
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

def rotr(x, r):
    return ((x >> r) | (x << (32 - r))) & 0xFFFFFFFF

def rotr4(x, r):
    return ((x >> r) | ((x & (1 << (r - 1))) << (4 - r))) & 0xF


'''Splits the key into even and odd 32-bit words.'''
def split_key(key):
    key_bytes = bytes.fromhex(key)
    m_even = [int.from_bytes(key_bytes[i:i+4], 'little') for i in range(0, len(key_bytes), 8)]
    m_odd = [int.from_bytes(key_bytes[i:i+4], 'little') for i in range(4, len(key_bytes), 8)]
    return m_even, m_odd


def rs_matrix_multiply(key_bytes):
    # Make sure the key bytes are in the correct format (list of integers)
    if isinstance(key_bytes, str):
        key_bytes = [int(key_bytes[i:i+2], 16) for i in range(0, len(key_bytes), 2)]

    # Initialize the S-boxes as a 4x8 matrix
    s_boxes = [[0 for _ in range(8)] for _ in range(4)]  # 4 rows, 8 columns

    # Perform RS matrix multiplication
    for i in range(4):  # 4 rows in RS matrix
        for j in range(8):  # 8 columns (key bytes)
            #print(RS_matrix[i][j])
            #print(key_bytes[j])
            result = galois_multiply(RS_matrix[i][j], key_bytes[j])
            #print(f"Here: {result}")
            s_boxes[i][j] = result

        # After each row is filled, print the row
        print("Row", i, ":", s_boxes[i])

    return s_boxes

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

def h_function(input_value, key_portion, key_length, q_table, MDS_matrix):
    # Split input_value into 4 bytes
    input_bytes = [(input_value >> (8 * i)) & 0xFF for i in range(4)]

    # Intermediate transformations with rotr4 and q-tables
    transformed_bytes = [0] * 4
    for i in range(4):
        a0 = input_bytes[i] // 16
        b0 = input_bytes[i] % 16
        a1 = a0 ^ b0
        b1 = rotr4(b0, 1) ^ (8 * a0) % 16

        a2 = q_table[0][a1]
        b2 = q_table[1][b1]
        a3 = a2 ^ b2
        b3 = rotr4(b2, 1) ^ (8 * a2) % 16

        transformed_bytes[i] = 16 * q_table[1][b3] + q_table[0][a3]

    # Apply the key portion based on the key length
    if key_length >= 4:
        transformed_bytes = [transformed_bytes[i] ^ key_portion[i + 12] for i in range(4)]

    if key_length >= 3:
        transformed_bytes = [transformed_bytes[i] ^ key_portion[i + 8] for i in range(4)]

    # Further transformations
    input_bytes = [
        q_table[1 if i % 2 == 0 else 0][q_table[1 if i < 2 else 0][transformed_bytes[i]] ^ key_portion[i + 4]]
        ^ key_portion[i] for i in range(4)
    ]

    # Print input_bytes before MDS matrix multiplication
    print("input_bytes before MDS matrix multiplication:", input_bytes)

    # Perform the MDS matrix multiplication
    mds_output = [0] * 4
    for i in range(4):
        for j in range(4):
            mds_output[i] ^= galois_multiply(MDS_matrix[i][j], input_bytes[j])

    # Combine mds_output into a 32-bit word
    return sum(mds_output[i] << (8 * i) for i in range(4))


'''This function is responsible for generating the round keys.'''
def key_schedule(key, g_q, MDS_matrix):
    key_length = len(key) // 8  # Determine key length in words (32-bit words)
    m_even, m_odd = split_key(key)
    print("Length of m_even:", len(m_even))
    print("Length of m_odd:", len(m_odd))
    s_boxes = rs_matrix_multiply(key)
    subkeys = [0] * 48  # Extend to 48 subkeys for whitening

    for i in range(40):
        print(f"Round {i}: Length of m_even = {len(m_even)}, Length of m_odd = {len(m_odd)}")
    # rest of the loop code...

    # Key-dependent S-boxes
    for i in range(min(4, len(m_even))):
        s_box_row = h_function(m_even[i], s_boxes[i], key_length, g_q, MDS_matrix)
        print(f"s_box_row before update (row {i}): {s_box_row:08X}")

        # Ensure that only the lower 32 bits are used to update the s_boxes
        s_box_row &= 0xFFFFFFFF  # Mask to ensure it's a 32-bit value


def print_inputKey_Sboxes(m_even, m_odd, s_boxes):
    print("Input key\t\t\t\tS-Box Key")
    print("Odd\t\tEven")
    for i in range(len(m_even)):  # Assuming m_even and m_odd are of the same length
        odd_hex = f"{m_odd[i]:08X}"
        even_hex = f"{m_even[i]:08X}"
        s_box_hex = " ".join([f"{byte:02X}" for byte in s_boxes[i][:4]])
        print(f"{odd_hex}\t{even_hex} -> {s_box_hex}")

def print_key_schedule(subkeys):
    print("\nRound subkeys:")
    for i in range(0, 40, 2):
        print(f"K{i}: {subkeys[i]:08X}, K{i+1}: {subkeys[i+1]:08X}")


if __name__ == "__main__":
    key = input_from_user_key("Enter a hex string of 128, 192, or 256 bits in length: ")
    g_q = twofish_init()
    m_even, m_odd = split_key(key)  # Assuming this gives you the split key parts
    s_boxes, subkeys = key_schedule(key, g_q, MDS_matrix)
    print_inputKey_Sboxes(m_even, m_odd, s_boxes)
    print_key_schedule(subkeys)
 
  
