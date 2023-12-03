#TwoFish
#Class: CS 4980 Cryptography 
#Name: Fatima Kammona

import numpy as np

'''Matrix Initialization Section '''

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


def twofish_init():
    '''This function initializes the g_q array, which is use in the 'h' function. The array is created using the provided permutation tables (t). '''
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

'''End of Matrix Initialization Section '''

''' Key Preparation Section '''

def input_from_user_key(prompt):
    '''THis function prompts the user and verifiyes the input key
    is either 128, 192 or 256 bits in length. '''
    
    while True:
        user_input = input(prompt).replace(" ", "").lower()  # Remove spaces and convert to lowercase
        hex_length = len(user_input)
    
        # Check if the length of the string is 32 (128-bit), 48 (192-bit), or 64 (256-bit) characters
        if hex_length in (32, 48, 64) and all(c in '0123456789abcdef' for c in user_input):
            return user_input
        else:
            print("Error: Please enter a valid hex string of 128, 192, or 256 bits in length.")


def split_key(key):
    '''This function splits a hexadecimal key into even and odd 32-bit words'''
    key_bytes = bytes.fromhex(key) # Convert the hexadecimal key string into a byte array

    # Even starts from index 0 and Odd starts from index 4
    # Start form index and skip every 8 bytes to get the next 32-bit word
    m_even = [int.from_bytes(key_bytes[i:i+4], 'little') for i in range(0, len(key_bytes), 8)]
    m_odd = [int.from_bytes(key_bytes[i:i+4], 'little') for i in range(4, len(key_bytes), 8)]
    return m_even, m_odd

'''End of key preparation Section'''

'''Rotation Section '''

def rotl(x, r):
    '''This function that performs a left rotation (circular shift) on a 32-bit integer 'x' by 'r' bits'''
    # The OR operation combines these two values and The result is masked with 0xFFFFFFFF to make sure the value within 32 bits.
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

def rotr(x, r):
    '''This function that performs a right rotation (circular shift) on a 32-bit integer 'x' by 'r' bits'''
    # The OR operation combines these two values and The result is masked with 0xFFFFFFFF to make sure the value within 32 bits.
    return ((x >> r) | (x << (32 - r))) & 0xFFFFFFFF

def rotr4(x, r):
    '''This function to perform a right rotation on a 4-bit integer 'x' by 'r' bits'''
    # Shift 'x' right by 'r' bits and create a mask to rotate the leftmost 'r-1' bits.
    # The OR operation combines these two values anf The result is masked with 0xF to make sure the value within 4 bits.
    return ((x >> r) | ((x & (1 << (r - 1))) << (4 - r))) & 0xF


'''End Rotation Section '''

'''S-Box Generation Section '''

def rs_matrix_multiply(key_bytes):
    '''This function performs matrix multiplication using the RS matrix and the given key'''
    # Make sure the key bytes are in the correct format (list of integers) if not then 
    # Converts the key from a hex string to a list of integers
    if isinstance(key_bytes, str):
        key_bytes = [int(key_bytes[i:i+2], 16) for i in range(0, len(key_bytes), 2)]

    # Initialize the S-boxes as a 4x8 matrix
    s_boxes = [[0 for _ in range(8)] for _ in range(4)]  # 4 rows, 8 columns

    #  RS matrix multiplication
    for i in range(4):  # 4 rows in RS matrix
        for j in range(8):  # 8 columns (key bytes)
            # Multiply each element of the RS matrix with the correct key byte using GF 
            result = galois_multiply(RS_matrix[i][j], key_bytes[j])
            s_boxes[i][j] = result # Store the result in the S-boxes matrix

        # After each row is filled, print the row
        print("Row", i, ":", s_boxes[i])

    return s_boxes


def galois_multiply(a, b):
    '''Multiply two numbers in the GF(2^8) field. ''' 
    '''w(x) = x^8 + x^6 + x^3 + x^2 + 1'''
    p = 0
    # Loop over each bit (8 bits for GF(2^8))
    for counter in range(8):
        if b & 1: # If the least significant bit of 'b' is set, XOR 'p' with 'a'
            p ^= a

        high_bit_set = a & 0x80 # Check if the high bit of 'a' is set
        a <<= 1 # Left shift 'a' by 1 bit
        if high_bit_set: # If the high bit of 'a' was set then do  modulo reduction
            a ^= 0x014D   # XOR with the reduced polynomial for RS matrix
        a &= 0xFF  # make sure 'a' remains an 8-bit value

        b >>= 1  # Right shift 'b' by 1 bit so that we can process the next bit in the next loop iteration

    return p

'''End of S-Box Generation Section '''

def h_function(input_value, key_portion, key_length, q_table):
    # Split input_value into 4 bytes
    input_bytes = [(input_value >> (8 * i)) & 0xFF for i in range(4)]

    # Initialize transformed_bytes
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
        transformed_bytes = [transformed_bytes[i] ^ (key_portion[i + 12] if i + 12 < len(key_portion) else 0) for i in range(4)]

    if key_length >= 3:
        transformed_bytes = [transformed_bytes[i] ^ (key_portion[i + 8] if i + 8 < len(key_portion) else 0) for i in range(4)]
    
    # Final transformation with checks
    final_bytes = []
    for i in range(4):
        key_index = i + 4
        if key_index < len(key_portion):
            intermediate_val = transformed_bytes[i] ^ key_portion[key_index]
            q_table_index = intermediate_val & 0xFF
            temp = q_table[1 if i % 2 == 0 else 0][q_table[1 if i < 2 else 0][q_table_index]]
        else:
            q_table_index = transformed_bytes[i] & 0xFF
            temp = q_table[1 if i % 2 == 0 else 0][q_table[1 if i < 2 else 0][q_table_index]]
        temp ^= key_portion[i] if i < len(key_portion) else 0
        final_bytes.append(temp)

    return final_bytes

def mds_matrix_multiply(transformed_bytes, MDS_matrix):
    mds_output = [0] * 4
    for i in range(4):
        for j in range(4):
            mds_output[i] ^= galois_multiply(MDS_matrix[i][j], transformed_bytes[j])

    return sum(mds_output[i] << (8 * i) for i in range(4))

def key_schedule_setup(key, g_q, MDS_matrix):
    key_length = len(key) // 8  # Key length in words (32-bit words)
    m_even, m_odd = split_key(key)  # Split the key into even and odd parts
    s_boxes = rs_matrix_multiply(key)  # Generate S-boxes
    return key_length, m_even, m_odd, s_boxes

def create_round_keys(m_even, m_odd, key_length, g_q, MDS_matrix):
    round_keys = [0] * 40  # Initialize round keys
    for i in range(20):
        round_constant_even = 2 * i * 0x01010101
        round_constant_odd = (2 * i + 1) * 0x01010101

        if i < len(m_even):
            transformed_bytes = h_function(round_constant_even, m_even, key_length, g_q)
            round_keys[2 * i] = mds_matrix_multiply(transformed_bytes, MDS_matrix)

        if i < len(m_odd):
            transformed_bytes = h_function(round_constant_odd, m_odd, key_length, g_q)
            round_keys[2 * i + 1] = mds_matrix_multiply(transformed_bytes, MDS_matrix)
            round_keys[2 * i + 1] = rotl(round_keys[2 * i + 1], 8)

    return round_keys

def create_whitening_keys(m_even, m_odd):
    whitening_keys = [0] * 8  # Initialize whitening keys
    for i in range(8):
        if i % 2 == 0 and i < len(m_even):
            whitening_keys[i] = m_even[i // 2]
        elif i % 2 != 0 and i < len(m_odd):
            whitening_keys[i] = m_odd[i // 2]
    return whitening_keys

def key_schedule(key, g_q, MDS_matrix):
    key_length, m_even, m_odd, s_boxes = key_schedule_setup(key, g_q, MDS_matrix)
    round_keys = create_round_keys(m_even, m_odd, key_length, g_q, MDS_matrix)
    whitening_keys = create_whitening_keys(m_even, m_odd)

    # Combine round keys and whitening keys into one array
    subkeys = round_keys + whitening_keys
    return s_boxes, subkeys


def print_inputKey_Sboxes(m_even, m_odd, s_boxes):
    print("Input key\t\t\t\tS-Box Key")
    print("Odd\t\tEven")
    for i in range(len(m_even)):  
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
    m_even, m_odd = split_key(key)  
    s_boxes, subkeys = key_schedule(key, g_q, MDS_matrix)
    print_inputKey_Sboxes(m_even, m_odd, s_boxes)
    print_key_schedule(subkeys)
   