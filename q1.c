#include <stdio.h>

int main() {
    char letters[] = "abcdefghijklmnopqrstuvwxyz";
    int count = 0;

    for (int i = 0; i < 26; i++) {
        for (int j = 0; j < 26; j++) {
            if (j == i) continue;
            for (int k = 0; k < 26; k++) {
                if (k == i || k == j) continue;
                for (int l = 0; l < 26; l++) {
                    if (l == i || l == j || l == k) continue;
                    printf("%c%c%c%c\n", letters[i], letters[j], letters[k], letters[l]);
                    count++;
                }
            }
        }
    }

    printf("Total combinations: %d\n", count);

    return 0;
}
