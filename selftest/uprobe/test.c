//+build ignore
#include <unistd.h>

__attribute__((optnone))
void testFunction() {}

int main() {
    int i;

    while (1) {
        usleep(100 * 1000);
        testFunction();
    }
}
