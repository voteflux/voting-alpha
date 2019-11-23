

class LambdaError(Exception):
    def __init__(self, code=500, msg="Error", client_response=None):
        self.code = code
        self.msg = msg
        self.client_response = client_response
        super().__init__(f"LambdaError ({code}, {msg})")

