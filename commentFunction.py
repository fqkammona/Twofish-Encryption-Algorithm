




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



'''Multiply two numbers in the GF(2^8) field. ''' 
'''w(x) = x^8 + x^6 + x^3 + x^2 + 1'''
def galois_multiply(a, b):
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

'''This function performs matrix multiplication using the RS matrix and the given key'''
def rs_matrix_multiply(key_bytes):
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

    return s_boxes

def permutation_q(input_byte, q_table):
    '''This function is the Permutations q0 and q1'''
    # Split the input byte into two 4-bit parts
    a0, b0 = input_byte // 16, input_byte % 16 # ⌊x/16⌋, x mod 16

    a1 = a0 ^ b0 # a0 XOR b0
    b1 = rotr4(b0, 1) ^ (8 * a0) % 16 # a0 XOR ROR4(b0,1) XOR 8a0mod16

    # Use the q_table with the results of the first operations to get new values
    a2, b2 = q_table[0][a1], q_table[1][b1]

    a3 = a2 ^ b2 # a2 XOR b2
    b3 = rotr4(b2, 1) ^ (8 * a2) % 16 # a2 XOR ROR4(b2,1) XOR 8a2mod16

    # Combine the final values to get the transformed byte
    transformed_byte = 16 * q_table[1][b3] + q_table[0][a3]

    return transformed_byte


def create_whitening_keys(m_even, m_odd):
    '''This function s creating an array of whitening keys using the even and odd key parts. 
    It then alternates between these two arrays to fill the whitening keys. '''
    # Reasons for whiting is to increase the security of a cipher by adding additional randomness to the 
    # encryption and decryption processes. 

    whitening_keys = [0] * 8  # Initialize whitening keys
    for i in range(8):  # Iterate over the indices for the whitening keys
        if i % 2 == 0 and i < len(m_even):  # Check if 'i' is even and is not greater then the length of m_odd 
            whitening_keys[i] = m_even[i // 2]  # Assign the value from m_even to the whitening key
       
        elif i % 2 != 0 and i < len(m_odd):  # Check if 'i' is odd and is not greater then the length of m_odd 
            whitening_keys[i] = m_odd[i // 2]  # Assign the value from m_odd to the whitening key
    return whitening_keys 