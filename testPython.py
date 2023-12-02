import galois

if __name__ == "__main__":
    irreducible_poly = galois.irreducible_poly(2, 8)

# Create the Galois field GF(2^8) using the found irreducible polynomial
    GF = galois.GF(2**8, irreducible_poly=irreducible_poly)
    print(GF.properties)