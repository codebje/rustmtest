test: Memory Address decode

setup:
    r0 = 0b10111011101

call: memaddr

check:
    r0 = 0b10111001
    r1 = 0
