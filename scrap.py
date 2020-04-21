#!/usr/bin/python3
# Works on x86-based systems
import subprocess

MAX_GADGET_SIZE  = 7                # Max number of instructions for a sequence to be considered a gadget.
GADGET_THRESHOLD = 4                # Alarm rings when this number of gadgets run continuously.
TARGET_NAME      = 'echo'	    # Enter the name of the program you want analyze here.
TARGET_ARGS      = 'Hello world!'   # Enter the command-line arguments for the program.
OUTPUT_FILE      = 'out.txt'	    # File to print stdout of analyzed program.
START_FROM_MAIN  = False            # Set to true to start debugging from main. Only works with symbols.

_64 = True # Set to false if on a 32-bit system
PC = ''

if _64:
    PC = '$rip'
else:
    PC = '$eip'

def categorizeInstruction(instructionName, instructionArgs):
    if 'jmp' in instructionName and '*' in instructionArgs:
    	# Indirect jump
        return 'w'
    elif 'call' in instructionName:
        if '*' in instructionArgs:
            # Indirect call
            return 'x'
        else:
            # Direct call
            return 'y'
    elif 'ret' in instructionName:
    	# Return
        return 'z'
    else:
    	# Other
        return 'a'

# State machine & shadow stack functions
counter = 0        # Count how long a gadget candidate is.
state = 0          # Count how many gadgets have run in sequence.
shadowStack = []   # Stores old states.
stateLastInst = [] # Not a part of SCRAP, just stores last indirect jumps/calls for each state.

for i in range(GADGET_THRESHOLD + 1):
    stateLastInst.append('')

def incrementCounter():
    global counter
    counter += 1

def resetCounter():
    global counter
    counter = 0

def incrementState():
    global line
    global state
    global stateLastInst
    global steps
    
    state += 1
    resetCounter()
    stateLastInst[state] = '(' + str(steps) + ')' + line

def resetState():
    global line
    global state
    global stateLastInst
    global steps

    state = 0
    stateLastInst[0] = '(' + str(steps) + ')' + line
    resetCounter()

def pushState():
    global counter
    global shadowStack
    global state

    shadowStack.append([state, counter])

def popState():
    global counter
    global line
    global shadowStack
    global state

    # For some reason an empty shadow stack can be popped.
    # This seems to be an effect of the debugged program, however.
    if len(shadowStack) != 0:
        state, counter = shadowStack.pop()
    else:
    	print('(' + str(steps) + ') Tried to pop from empty stack!')
    	print(stateLastInst[state], end='')
    	print('(' + str(steps) + ')', line, end='')

def caseW():
    global counter

    if counter < MAX_GADGET_SIZE:
        incrementState()
    else:
        resetState()
    resetCounter()

def caseX():
    caseW()
    pushState()

typeSwitch = {
    'a': incrementCounter,
    'w': caseW,
    'x': caseX,
    'y': pushState,
    'z': popState
}

arguments = [ 'gdb', '-q', TARGET_NAME ]

proc = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, bufsize=1)
running = True

# Consume first few lines.
# Add as many of these statements as you need, you might need 1 or 2. It depends on your setup.
print(proc.stdout.readline(),end='')

# Begin debugging
if START_FROM_MAIN:
    proc.stdin.write('start ' + TARGET_ARGS + ' > ' + OUTPUT_FILE + '\n')
else:
    proc.stdin.write('starti ' + TARGET_ARGS + ' > ' + OUTPUT_FILE + '\n')

# Must use readline() instead of readlines() here, since readlines will only read at least 1 line.
# You can modify this group of statements so that "Starting program" is shown.
# It depends on your setup.
proc.stdout.readline()
print(proc.stdout.readline(), end='')

steps = 0
line = ''

while running:
    steps += 1

    proc.stdin.write('x/i ' + PC + '\n')

    # Skip lines we don't care about
    while True:
        line = proc.stdout.readline()
#        print(steps, line, end='')
        if '=> 0x' in line or 'exited' in line or 'terminated' in line or 'signal' in line:
            break
    
    if 'exited' in line:
        print('(' + str(steps) + ') Target exited.')
        break

    if '=> 0x' in line:
        instruction = line.split('\t')[1].split()

        if len(instruction) == 0:
            # The next line has the instruction.
            line = proc.stdout.readline()
#            print(steps, line, end='')
            instruction = line.split()
        
        if len(instruction) < 2:
            instruction.append('')

        catChar = categorizeInstruction(instruction[0], instruction[1])
        typeSwitch[catChar]()

    # For some systems you need this set of if statements.
    #elif 'exited' in line:
    #    print('(' + str(steps) + ') Target exited.')
    #    break
    #elif 'terminated' in line:
    #    print('(' + str(steps) + ') Target terminated.')
    #    break
    #elif 'signal' in line:
    #    print('(' + str(steps) + ')', line)
    #    break

    if state >= GADGET_THRESHOLD:
        print('(' + str(steps) + ') ALERT: Code-reuse attack detected!')
        running = False
        for i in range(len(stateLastInst)):
            print('(' + str(i) + ')', stateLastInst[i], end='')
        break
        
    if steps % 10000 == 0:
    	print(steps, 'instructions processed.')

    proc.stdin.write('stepi\n')

    # For other systems you need this set of if statements. I can't tell why.
    l = proc.stdout.readline()
    if 'exited' in l:
        print('(' + str(steps) + ') Target exited.')
        break
    elif 'terminated' in l:
        print('(' + str(steps) + ') Target terminated.')
        break
    elif 'signal' in l:
        print('(' + str(steps) + ')', l)
        break

proc.stdin.write('q\ny\n')
print('Finished.')
