#include <sys/sdt.h>
#include <unistd.h>

int main()
{
    while (1) {
        usleep(100 * 1000);
        DTRACE_PROBE1(test, test_marker, 1234);
    }
    return 0;
}
