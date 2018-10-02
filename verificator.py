#!/usr/bin/env python3

import sys

variables = dict()
actions = dict()

def get_action(variables, args):
    if len(args) < 2:
        return
    if args[0] == 'size':
        print(len(variables.get(args[1], [[]])[-1]))
    elif args[0] == 'at':
        if len(args) < 3:
            return
        try:
            idx = int(args[1])
            arr = variables.get(args[2], [[]])[-1]
            if idx >= 0 and idx < len(arr):
                print(arr[idx])
            else:
                print(0)
        except ValueError:
            pass

def set_action(variables, args):
    if len(args) < 3:
        return
    if args[0] == 'size':
        try:
            size = int(args[2])
            stack = variables.get(args[1], [[]])
            arr = stack.pop()
            arr = arr[:size] + [0] * (size - len(arr))
            stack.append(arr)
            variables[args[1]] = stack
        except ValueError:
            pass
    elif args[0] == 'at':
        try:
            idx = int(args[1])
            stack = variables.get(args[2], [[]])
            arr = stack.pop()
            if idx >= 0 and idx < len(arr):
                arr[idx] = args[3]
            stack.append(arr)
            variables[args[2]] = stack
        except ValueError:
            pass

def dup_action(variables, args):
    if len(args) < 1:
        return
    stack = variables.get(args[0], [[]])
    stack.append(stack[-1][:])
    variables[args[0]] = stack

def pop_action(variables, args):
    if len(args) < 1:
        return
    stack = variables.get(args[0], [[]])
    if len(stack) > 1:
        stack.pop()
    variables[args[0]] = stack

def exit_action(variables, args):
    sys.exit(0)

actions['get'] = get_action
actions['set'] = set_action
actions['dup'] = dup_action
actions['pop'] = pop_action
actions['exit'] = exit_action

print('ready')
if input() != 'ready':
    sys.exit(0)

try:
    while True:
        cmd = input().split()
        if len(cmd) == 0:
            continue
        actions[cmd[0]](variables, cmd[1:])
except EOFError:
    pass
