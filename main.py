import struct

# Constants
K = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774DF4DF3D11, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
]

# Initial hash values
H = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
]


def sha512(message):
    # Padding step
    padded_message = pad_message(message)

    # Initialize the hash values
    a, b, c, d, e, f, g, h = H

    # Process message in 1024-bit blocks
    for block in divide_into_blocks(padded_message, 128):
        W = message_schedule(block)
        a, b, c, d, e, f, g, h = process_block(W, a, b, c, d, e, f, g, h)

    # Final hash value
    hash_result = b''.join(struct.pack('>Q', h) for h in [a, b, c, d, e, f, g, h])
    return hash_result



def pad_message(message):
    # Padding step
    message_length = len(message)
    message += b'\x80'
    while (len(message) + 16) % 128 != 0:
        message += b'\x00'
    message += struct.pack('>Q', message_length * 8)
    return message


def divide_into_blocks(message, block_size):
    return [message[i:i + block_size] for i in range(0, len(message), block_size)]


def message_schedule(block):
    W = [0] * 80  # Initialize W with 80 elements
    for t in range(16):
        W[t] = int.from_bytes(block[t * 8:t * 8 + 8], byteorder='big')

    for t in range(16, 80):
        W[t] = process_word(W, t)

    return W


def process_block(W, a, b, c, d, e, f, g, h):
    for t in range(80):
        a, b, c, d, e, f, g, h = sha512_round(W, a, b, c, d, e, f, g, h, t)
    return a, b, c, d, e, f, g, h


def sha512_round(W, a, b, c, d, e, f, g, h, t):
    # Part 1: Compute temporary values
    s1 = (e >> 14 | e << 50) ^ (e >> 18 | e << 46) ^ (e >> 41 | e << 23)
    ch = (e & f) ^ (~e & g)
    # if t < 0 or t >= 80:
    #     print("Error: t is out of range:", t)
    temp1 = h + s1 + ch + K[t] + W[t]

    s0 = (a >> 28 | a << 36) ^ (a >> 34 | a << 30) ^ (a >> 39 | a << 25)
    maj = (a & b) ^ (a & c) ^ (b & c)
    temp2 = s0 + maj

    # Part 2: Update working variables
    h = g
    g = f
    f = e
    e = (d + temp1) & 0xFFFFFFFFFFFFFFFF
    d = c
    c = b
    b = a
    a = (temp1 + temp2) & 0xFFFFFFFFFFFFFFFF

    return a, b, c, d, e, f, g, h  # Return the updated values



def process_word(W, t):
    s0 = (W[t - 15] >> 1 | W[t - 15] << 63) ^ (W[t - 15] >> 8 | W[t - 15] << 56) ^ (W[t - 15] >> 7)
    s1 = (W[t - 2] >> 19 | W[t - 2] << 45) ^ (W[t - 2] >> 61 | W[t - 2] << 3) ^ (W[t - 2] >> 6)

    Wt = (W[t - 16] + s0 + W[t - 7] + s1) & 0xFFFFFFFFFFFFFFFF

    return Wt


# Test the SHA-512 function
message = b'Hello, SHA-512!'
digest = sha512(message)
print("SHA-512 Digest:", digest.hex())
