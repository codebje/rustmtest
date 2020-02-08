test: Memory Address decode

setup:
    r0 = 0b10111011101

call: memaddr

check:
    r0 = 0x200000b9
    r1 = 0
