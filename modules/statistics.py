class Statistics:
    def __init__(self):
        self.received_bytes = 0
        self.sent_bytes = 0

    def update(self, recv=0, sent=0):
        self.received_bytes += recv
        self.sent_bytes += sent
