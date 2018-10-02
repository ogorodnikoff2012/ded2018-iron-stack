#include "iron_stack.h"
#include <iostream>
#include <cassert>

int main() {
    IronStack<int> stack;
    for (int i = 0; i < 100; ++i) {
        stack.Push(i);
    }

    for (int i = 99; i >= 0; --i) {
        assert(stack.Top() == i);
        stack.Pop();
    }
    return 0;
}