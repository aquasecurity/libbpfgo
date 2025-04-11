//+build ignore
#include <unistd.h>

__attribute__((optnone)) void fooFunction() {}
__attribute__((optnone)) void barFunction() {}
__attribute__((optnone)) void bazFunction() {}

int main()
{
    int i;

    while (1) {
        usleep(100 * 1000);
        fooFunction();
        usleep(100 * 1000);
        barFunction();
        usleep(100 * 1000);
        bazFunction();
    }
}
