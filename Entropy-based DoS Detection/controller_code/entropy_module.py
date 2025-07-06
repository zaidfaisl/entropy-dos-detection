from collections import Counter
import math

class EntropyModule:
    def __init__(self, window_size=100, max_windows=10):
        self.window_size = window_size
        self.max_windows = max_windows
        self.buffer = []
        self.entropy_history = []
        self.threshold = None

    def add_and_check(self, dst_ip):
        self.buffer.append(dst_ip)

        if len(self.buffer) == self.window_size:
            entropy = self.calculate_entropy(self.buffer)
            self.entropy_history.append(entropy)

            if len(self.entropy_history) == self.max_windows and self.threshold is None:
                self.threshold = sum(self.entropy_history) / self.max_windows

            self.buffer = []
            return entropy
        return None

    def calculate_entropy(self, window):
        freq = Counter(window)
        total = len(window)
        return -sum((count / total) * math.log2(count / total) for count in freq.values())

