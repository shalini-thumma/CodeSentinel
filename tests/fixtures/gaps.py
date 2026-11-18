from abc import ABC, abstractmethod


class Port(ABC):
    @abstractmethod
    def load(self):
        pass


def unfinished():
    """The implementation still needs to be written."""
    pass


def pending_validation(value):
    # TODO: validate external input
    return value


def deferred_behavior():
    raise NotImplementedError("finish this behavior")