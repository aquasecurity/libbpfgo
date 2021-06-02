//+build ignore

__attribute__((optnone))
void testFunction() {}

int main() {
    int i;

    while(1) {
        testFunction();
    }
}