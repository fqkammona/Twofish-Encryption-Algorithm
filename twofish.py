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

MDS_POLY =	0b01101001
RS_POLY	 =	0b01001101  # w(x) = x^8 + x^6 + x^3 + x^2 + 1

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
        b[1] = (a[0] ^ ((b[0] >> 1) | ((b[0] & 1) << 3)) ^ (a[0] << 3)) & 0xf

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


def split_key(key_bytes):
    '''This function splits a hexadecimal key into even and odd 32-bit words'''
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
    key_len = len(key_bytes) // 8

    # Initialize the S-boxes as a 4x8 matrix
    S = [[0 for _ in range(4)] for _ in range(key_len)]

    for k in range(key_len):
        #  RS matrix multiplication
        for i in range(4):  # 4 rows in RS matrix
            for j in range(8):  # 8 columns (key bytes)
                S[k][3 - i] ^= galois_multiply(RS_matrix[i][j], key_bytes[8*k + j], RS_POLY)

    return S


def galois_multiply(a, b, poly):
    '''Multiply two numbers in the GF(2^8) field, mod <poly> ''' 
    p = 0
    # Loop over each bit (8 bits for GF(2^8))
    for counter in range(8):
        if b & 1: # If the least significant bit of 'b' is set, XOR 'p' with 'a'
            p ^= a

        high_bit_set = a & 0x80 # Check if the high bit of 'a' is set
        a <<= 1 # Left shift 'a' by 1 bit
        if high_bit_set: # If the high bit of 'a' was set then do  modulo reduction
            a ^= poly   # XOR with the reduced polynomial for RS matrix
        a &= 0xFF  # make sure 'a' remains an 8-bit value

        b >>= 1  # Right shift 'b' by 1 bit so that we can process the next bit in the next loop iteration

    return p

'''End of S-Box Generation Section '''


'''Everything with H_function Section'''

def h_function(x, L, q):
    # Split x into 4 bytes
    y = [(x >> (8 * i)) & 0xFF for i in range(4)]
    l = [[(l >> (8 * i)) & 0xFF for i in range(4)] for l in L]


    if len(L) == 4:
        y = [
            q[1][y[0]] ^ l[3][0],
            q[0][y[1]] ^ l[3][1],
            q[0][y[2]] ^ l[3][2],
            q[1][y[3]] ^ l[3][3],
        ]

    if len(L) >= 3:
        y = [
            q[1][y[0]] ^ l[2][0],
            q[1][y[1]] ^ l[2][1],
            q[0][y[2]] ^ l[2][2],
            q[0][y[3]] ^ l[2][3],
        ]

    y = [
        q[1][ q[0][ q[0][y[0]] ^ l[1][0] ] ^ l[0][0] ],
        q[0][ q[0][ q[1][y[1]] ^ l[1][1] ] ^ l[0][1] ],
        q[1][ q[1][ q[0][y[2]] ^ l[1][2] ] ^ l[0][2] ],
        q[0][ q[1][ q[1][y[3]] ^ l[1][3] ] ^ l[0][3] ],
    ]

    return mds_matrix_multiply(y)

def mds_matrix_multiply(transformed_bytes):
    mds_output = [0] * 4
    for i in range(4):
        for j in range(4):
            mds_output[i] ^= galois_multiply(MDS_matrix[i][j], transformed_bytes[j], MDS_POLY)

    return sum(mds_output[i] << (8 * i) for i in range(4))

'''End of Everything with H_function Section'''

def key_schedule_setup(key):
    key_bytes = bytes.fromhex(key)

    m_even, m_odd = split_key(key_bytes)  # Split the key into even and odd parts
    s_boxes = rs_matrix_multiply(key_bytes)  # Generate S-boxes
    return m_even, m_odd, s_boxes

def create_round_keys(m_even, m_odd, g_q):
    round_keys = [0] * 40  # Initialize round keys
    for i in range(20): # Go over 20 times to generate 40 keys (2 keys per iteration)
        # Calculate round constants for even and odd values
        round_constant_even = 2 * i * 0x01010101
        round_constant_odd = (2 * i + 1) * 0x01010101

        Ai = h_function(round_constant_even, m_even, g_q)
        Bi = rotl(h_function(round_constant_odd, m_odd, g_q), 8)

        round_keys[2 * i] = (Ai + Bi) & 0xffffffff
        round_keys[2 * i + 1] = rotl((Ai + 2*Bi) & 0xffffffff, 9)

    return round_keys

def key_schedule(key, g_q):
    m_even, m_odd, s_boxes = key_schedule_setup(key)
    round_keys = create_round_keys(m_even, m_odd, g_q)

    return m_even, m_odd, s_boxes, round_keys

''' Printing Section '''

def print_inputKey_Sboxes(m_even, m_odd, s_boxes):
    print("Input key\t\t\t\tS-Box Key")
    for i in range(len(m_even)):  
        odd_hex = f"{m_odd[i]:08X}"
        even_hex = f"{m_even[i]:08X}"
        s_box_hex = " ".join([f"{byte:02X}" for byte in s_boxes[i][:4]])
        print(f"{odd_hex}\t{even_hex} -> {s_box_hex}")

def print_key_schedule(subkeys):
    print("\nRound subkeys:")
    for i in range(0, 40, 2):
        print(f"K{i}: {subkeys[i]:08X}, K{i+1}: {subkeys[i+1]:08X}")

'''End Of Printing Section '''

if __name__ == "__main__":
    key = input_from_user_key("Enter a hex string of 128, 192, or 256 bits in length: ")
    g_q = twofish_init()
    m_even, m_odd, s_boxes, subkeys = key_schedule(key, g_q)
    print_inputKey_Sboxes(m_even, m_odd, s_boxes)
    print_key_schedule(subkeys)
