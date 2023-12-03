#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

void printBN(char *msg, BIGNUM *tmp) {
    char *number_str = BN_bn2hex(tmp); // Convert BIGNUM to hex
    printf("%s%s\n", msg, number_str); // Print hex
    OPENSSL_free(number_str); // Free memory
}

int main(int argc, char *argv[]) {
    BN_CTX *ctx = BN_CTX_new();

    // Initialize all needed BIGNUM variables
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *Phi_n = BN_new();
    BIGNUM *C = BN_new(); // Encrypted Message variable
    BIGNUM *D = BN_new(); // Decrypted Ciphertext variable

    // Assign values to e, n, Phi_n, and d using BN_hex2bn()
    BN_hex2bn(&e, "010001"); // Public Key (e)
    BN_hex2bn(&n, "E103ABD94892E3E74AFD724BF28E78366D9676BCCC70118BD0AA1968DBB143D1"); // Modulus (n)
    BN_hex2bn(&Phi_n, "E103ABD94892E3E74AFD724BF28E78348D52298BD687C44DEB3A81065A7981A4"); // Phi(n)
    // Calculate d (Private Key)
    BN_mod_inverse(d, e, Phi_n, ctx);

    // Read the Encrypted Message from the user
    printf("Enter your Encrypted Message:\n");
    char CC[500];
    fgets(CC, sizeof(CC), stdin); // Assuming the encrypted message input is taken as a string
    BN_hex2bn(&C, CC); // Assign the input value in variable (CC) to Encrypted Message variable

    // Decrypt ciphertext using D = C^d mod(n)
    BN_mod_exp(D, C, d, n, ctx); // Compute D = C^d mod n

    // Convert Hex string to ASCII letters using Python
    printf("\nOriginal Message:\n");
    char str1[1000] = "print(\"";
    char *str2 = BN_bn2hex(D);
    char str3[] = "\".decode(\"hex\"))";
    strcat(str1, str2);
    strcat(str1, str3);

    // Execute Python command to print the decrypted message
    char *args[] = {"python2", "-c", str1, NULL};
    execvp("python2", args);

    // Free allocated memory
    BN_CTX_free(ctx);
    BN_free(e);
    BN_free(d);
    BN_free(n);
    BN_free(Phi_n);
    BN_free(C);
    BN_free(D);

    return EXIT_SUCCESS;
} 
