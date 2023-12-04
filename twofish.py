#TwoFish
#Class: CS 4980 Cryptography 
#Name: Fatima Kammona

# import numpy as np

'''Matrix Initialization Section '''

RS_matrix = [
        [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
        [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
        [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
        [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03]
    ]

MDS_matrix = [
        [0x01, 0xEF, 0x5B, 0x5B],
        [0x5B, 0xEF, 0xEF, 0x01],
        [0xEF, 0x5B, 0x01, 0xEF],
        [0xEF, 0x01, 0xEF, 0x5B]
    ]

MDS_POLY =	0b01101001
RS_POLY	 =	0b01001101  # w(x) = x^8 + x^6 + x^3 + x^2 + 1

gq = []

def twofish_init():
    '''This function initializes the g_q array, which is use in the 'h' function. 
    The array is created using the provided permutation tables (t). '''
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

        a[0] = x // 16 # ⌊x/16⌋
        b[0] = x % 16 # x mod 16
        a[1] = a[0] ^ b[0]  # a0 XOR b0
        b[1] = (a[0] ^ ((b[0] >> 1) | ((b[0] & 1) << 3)) ^ (a[0] << 3)) & 0xf # a0 XOR ROR4(b0,1) XOR 8a0mod16

        for j in range(2):
            a[2] = t[j][0][a[1]] # t0[a1]
            b[2] = t[j][1][b[1]] # t1[b1]
            a[3] = a[2] ^ b[2]  # a2 XOR b2
            b[3] = (a[2] ^ ((b[2] >> 1) | ((b[2] & 1) << 3)) ^ (8 * a[2])) % 16 # a2 XOR ROR4(b2,1) XOR 8a2mod16
            a[4] = t[j][2][a[3]] # t2[a3]
            b[4] = t[j][3][b[3]] # t3[b3]
            g_q[j][x] = (b[4] << 4) + a[4]  # 16b4 + a4

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

def input_from_user_pt(prompt):
    '''THis function prompts the user and verifiyes the input key
    is either 128, 192 or 256 bits in length. '''
    
    while True:
        user_input = input(prompt).replace(" ", "").lower()  # Remove spaces and convert to lowercase
        hex_length = len(user_input)
    
        # Check if the length of the string is 32 (128-bit), 48 (192-bit), or 64 (256-bit) characters
        if hex_length == 32 and all(c in '0123456789abcdef' for c in user_input):
            return user_input
        else:
            print("Error: Please enter a valid hex string of 128 in length.")      

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
                S[key_len - 1 - k][i] ^= galois_multiply(RS_matrix[i][j], key_bytes[8*k + j], RS_POLY)

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
            a ^= poly   # XOR with the reduced polynomial 
        a &= 0xFF  # make sure 'a' remains an 8-bit value

        b >>= 1  # Right shift 'b' by 1 bit so that we can process the next bit in the next loop iteration

    return p

'''End of S-Box Generation Section '''

'''Everything with H_function Section'''

def h_function(x, L):
    # Split x into 4 bytes
    # l = key portion so either m_even or m_odd
    # x = round constant 
    y = [(x >> (8 * i)) & 0xFF for i in range(4)]
    l = [[(l >> (8 * i)) & 0xFF for i in range(4)] for l in L]

    #  k = 4 we have
    if len(L) == 4:
        y = [
            g_q[1][y[0]] ^ l[3][0],
            g_q[0][y[1]] ^ l[3][1],
            g_q[0][y[2]] ^ l[3][2],
            g_q[1][y[3]] ^ l[3][3],
        ]

    # k ≥ 3 we have 
    if len(L) >= 3:
        y = [
            g_q[1][y[0]] ^ l[2][0],
            g_q[1][y[1]] ^ l[2][1],
            g_q[0][y[2]] ^ l[2][2],
            g_q[0][y[3]] ^ l[2][3],
        ]

    # In all cases we have
    y = [
        g_q[1][ g_q[0][ g_q[0][y[0]] ^ l[1][0] ] ^ l[0][0] ],
        g_q[0][ g_q[0][ g_q[1][y[1]] ^ l[1][1] ] ^ l[0][1] ],
        g_q[1][ g_q[1][ g_q[0][y[2]] ^ l[1][2] ] ^ l[0][2] ],
        g_q[0][ g_q[1][ g_q[1][y[3]] ^ l[1][3] ] ^ l[0][3] ],
    ]

    return mds_matrix_multiply(y)

def mds_matrix_multiply(transformed_bytes):
    '''This function performs matrix multiplication using a predefined MDS matrix (maximum distance separable)
    and a set of bytes that have been transformed. '''
    mds_output = [0] * 4  # hold the MDS matrix multiplication result
    for i in range(4):
        for j in range(4):
            mds_output[i] ^= galois_multiply(MDS_matrix[i][j], transformed_bytes[j], MDS_POLY)

    return sum(mds_output[i] << (8 * i) for i in range(4))

'''End of Everything with H_function Section'''

'''Key_scheduling and Round Key Section'''

def key_schedule_setup(key):
    key_bytes = bytes.fromhex(key)

    m_even, m_odd = split_key(key_bytes)  # Split the key into even and odd parts
    s_boxes = rs_matrix_multiply(key_bytes)  # Generate S-boxes
    return m_even, m_odd, s_boxes

def create_round_keys(m_even, m_odd):
    round_keys = [0] * 40  # Initialize round keys
    for i in range(20): # Go over 20 times to generate 40 keys (2 keys per iteration)
        # Calculate round constants for even and odd values
        round_constant_even = 2 * i * 0x01010101
        round_constant_odd = (2 * i + 1) * 0x01010101

        Ai = h_function(round_constant_even, m_even)
        Bi = rotl(h_function(round_constant_odd, m_odd), 8)

        round_keys[2 * i] = (Ai + Bi) & 0xffffffff
        round_keys[2 * i + 1] = rotl((Ai + 2*Bi) & 0xffffffff, 9)

    return round_keys

def key_schedule(key):
    m_even, m_odd, s_boxes = key_schedule_setup(key)
    round_keys = create_round_keys(m_even, m_odd)

    return m_even, m_odd, s_boxes, round_keys

'''End of Key_scheduling and Round Key Section'''

'''Encrption/Decryption Functions  Section'''

def g_function(X, S):
    '''This function processes a part of the block that is being encrypted or decrypted.
    It takes an input value X and a set of substitution boxes S, 
    and then transforms S into a form that h_function can use, and then does h_function to X'''
    s = [sum(l[i] << (8 * i) for i in range(4)) for l in S]  # Transform each 4-byte list in S to a 32-bit integer
    return h_function(X, s) # returns h_function the input value X and the transformed S

def f_function(r0, r1, r, S, K):
    '''This function is the Fiestel network section that is combining
      the results of the g_function and round keys to produce two 32-bit outputs.'''
    t0 = g_function(r0, S) # Apply g_function to r0 with the S-boxes S
    t1 = g_function(rotl(r1, 8), S) # Apply g_function to r1 after rotating it left by 8 bits, using the S-boxes S
    f0 = (t0 + t1 + K[2*r + 8]) & 0xffffffff  # calcs f0 using the results from above, + the key value from K, make sures 32-bit size
    f1 = (t0 + 2*t1 + K[2*r + 9]) & 0xffffffff  # calcs f1 using the results from above, with t1 being doubled before adding
    return f0, f1

def do_encrypt(plain, S, K):
    '''This is the encryption function that 
    1. input whiting of pt
    2. 16 rounds of f_function 
    3. output whiting '''

    # Convert pt into 32-bit words using little-endian format
    P = [int.from_bytes(plain[i:i+4], 'little') for i in range(0, len(plain), 4)]
    # Initialize lists for storing the function outputs and round values
    F = []
    R = []
    
    R.append([P[i] ^ K[i] for i in range(4)]) # input whitening -  XOR each 32-bit block of pt with a subkey

    # does 16 rounds of the encryption algorithm
    for r in range(16):
        f0, f1 = f_function(R[r][0], R[r][1], r, S, K)  # Compute the round functions f0 and f1
        R.append([  # Update the new state to R w/ transformations applied to each word
            rotr(R[r][2] ^ f0, 1),   # Rotate 3rd word right by 1 bit and XOR with f0
            rotl(R[r][3], 1) ^ f1,   # Rotate 4th word left by 1 bit and XOR with f1
            R[r][0],                 # Pass 1st word to the next round
            R[r][1],                 # Pass 2nd word to the next round
        ])
    
    R.append([R[-1][(i + 2) % 4] ^ K[i+4] for i in range(4)]) # Output whitening - XOR the last round's output with additional subkeys

    # print the intermediate round values
    print(f'R[-1]: x= {P[0]:08x}  {P[1]:08x}  {P[2]:08x}  {P[3]:08x}')
    for i in range(18):
        print(f'R[{i:02}]: x= {R[i][0]:08x}  {R[i][1]:08x}  {R[i][2]:08x}  {R[i][3]:08x}')

    # Combine the final round into ct using little-endian format
    ct = b''.join([R[-1][i].to_bytes(4, 'little') for i in range(4)])
    print(f'CT={ct.hex()}') # print CT in hex 

    do_decrypt(ct, S, K)

def do_decrypt(cipher, S, K):
    '''This is the decryption function that 
    1. output dewhiting of ct
    2. 16 rounds in reverse order
    3. input de whiting '''

    # Convert ct into 32-bit words using little-endian format
    C = [int.from_bytes(cipher[i:i+4], 'little') for i in range(0, len(cipher), 4)]
    
    # Initialize the round list with the ct
    R = [C]

    R.append([C[i] ^ K[i + 4] for i in range(4)]) # Output de whitening - XOR each 32-bit block of ct with a subkey

    # does 16 rounds in reverse order
    for r in range(16)[::-1]:
        f0, f1 = f_function(R[-1][0], R[-1][1], r, S, K) # Compute the round functions f0 and f1
        R.append([ 
            rotl(R[-1][2], 1) ^ f0,  # Rotate 3rd  word left by 1 bit and XOR with f0
            rotr(R[-1][3] ^ f1, 1),  # Rotate 4th word right by 1 bit and XOR with f1
            R[-1][0],                # Pass 1st word to the next round
            R[-1][1],                # Pass 2nd word to the next round
        ])
 
    R.append([R[-1][(i + 2) % 4] ^ K[i] for i in range(4)]) # input dewhitening - XOR the last round's output with the initial subkeys

    # print the intermediate round values in reverse order
    for i, r in enumerate(R):
        print(f'R[{len(R)-2-i:02}]: x= {r[0]:08x}  {r[1]:08x}  {r[2]:08x}  {r[3]:08x}')

    # Combine the final round values into pt using little-endian format
    pt = b''.join([R[-1][i].to_bytes(4, 'little') for i in range(4)])
   
    print(f'PT={pt.hex()}') # print pt in hex 

'''End of Encrption/Decryption Functions  Section'''

''' Printing Key Section '''

def print_inputKey_Sboxes(m_even, m_odd, s_boxes):
    print("Input key\t\t    S-Box Key")
    for i in range(len(m_even)):  
        odd_hex = f"{m_odd[i]:08X}"
        even_hex = f"{m_even[i]:08X}"
        s_box_hex = " ".join([f"{byte:02X}" for byte in s_boxes[i][:4]])
        print(f"{odd_hex}\t{even_hex} -> {s_box_hex}")

def print_key_schedule(subkeys):
    print("\nRound subkeys:")
    for i in range(0, 40, 2):
        print(f"K{i}: {subkeys[i]:08X}, K{i+1}: {subkeys[i+1]:08X}")

''' End of Printing Key Section'''

if __name__ == "__main__":
    key = input_from_user_key("Enter a hex string of 128, 192, or 256 bits in length: ")
    pt = input_from_user_pt("Enter a hex string of 128: ")
    g_q = twofish_init()
    m_even, m_odd, s_boxes, round_keys = key_schedule(key)
    print_inputKey_Sboxes(m_even, m_odd, s_boxes)
    print_key_schedule(round_keys)

    do_encrypt(bytes.fromhex(pt), s_boxes, round_keys)

