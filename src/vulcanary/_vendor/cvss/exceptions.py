"""Exceptions required by the vendored CVSS v4 reference implementation."""

class CVSSError(ValueError):
    pass

class CVSS4MalformedError(CVSSError):
    pass

class CVSS4MandatoryError(CVSSError):
    pass

class CVSS4RHMalformedError(CVSSError):
    pass

class CVSS4RHScoreDoesNotMatch(CVSSError):
    pass

