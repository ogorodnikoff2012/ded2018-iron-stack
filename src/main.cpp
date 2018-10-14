#include "iron_stack.h"
#include <iostream>
#include <cassert>

int main() {
    using iron_stack::IronStack;

    IronStack<int> stack;
    for (int i = 0; i < 100; ++i) {
        stack.Push(i);
    }

    *(int*)(&stack) = 0;

    for (int i = 99; i >= 0; --i) {
        assert(stack.Top() == i);
        stack.Pop();
    }
    return 0;
}
