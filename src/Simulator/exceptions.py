class SimulationError(Exception):
    # Errors that are part of the simulation, not the code
    pass

class SimTimeoutError(SimulationError):
    # Error raised when a timeout occurs
    pass

class SimCorruptResponseError(SimulationError):
    # Error raised when a response is corrupted
    pass

class SimVerificationFailedError(SimulationError):
    # Error raised when a verification fails
    pass