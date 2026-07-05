"""
80-bit Fibonacci LFSR
Used as deterministic pseudo-random generator for cipher layers
"""

class LFSR:

    TAPS = [0, 13, 23, 38, 51]
    MASK = (1 << 80) - 1

    def __init__(self, seed: int):

        if seed == 0:
            raise ValueError("Seed cannot be zero")

        self.state = seed & self.MASK

        # warm-up to remove startup bias
        for _ in range(160):
            self.step()

    # --------------------------------

    def step(self):

        feedback = 0

        for t in self.TAPS:
            feedback ^= (self.state >> t) & 1

        out = self.state & 1

        self.state = (self.state >> 1) | (feedback << 79)

        return out

    # --------------------------------

    def byte(self):

        value = 0

        for _ in range(8):
            value = (value << 1) | self.step()

        return value

    # --------------------------------

    def randint(self, max_value):

        if max_value <= 0:
            raise ValueError("max_value must be positive")

        return self.byte() % max_value

    # --------------------------------

    def get_state(self):

        return self.state

    # --------------------------------

    def set_state(self, state):

        self.state = state & self.MASK