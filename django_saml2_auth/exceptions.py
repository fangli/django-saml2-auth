class SAMLAuthError(Exception):
    extra = None

    def __init__(self, msg, extra=None):
        self.message = msg
        self.extra = extra
