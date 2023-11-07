import struct

# Constants
K = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
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
        print("Size of constant `k`: ",len(K))
        a, b, c, d, e, f, g, h = sha512_round(W, a, b, c, d, e, f, g, h)

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
    for t in range(80):
        if t >= 15:
            W[t] = int.from_bytes(block[t * 8:t * 8 + 8], byteorder='big')

        else:
            W[t] = process_word(W, t)

    return W


# def process_block(W, a, b, c, d, e, f, g, h):
#     for t in range(80):
#         a, b, c, d, e, f, g, h = sha512_round(W, a, b, c, d, e, f, g, h, t)
#     return a, b, c, d, e, f, g, h


def sha512_round(W, a, b, c, d, e, f, g, h):
    # Part 1: Compute temporary values
    for t in range(80):
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
