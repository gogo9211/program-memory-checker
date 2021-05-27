#include <Windows.h>
#include <iostream>
#include <thread>
#include "pmc/mc.hpp"

__declspec(noinline) void test_function()
{
    std::printf("im hashed!\n");
}

int main()
{
    test_function();

    memory_checker pmc = memory_checker();

    pmc.hash();
    pmc.start();

    std::cin.get();
    return 1;
}
