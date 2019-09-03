from random import randint

class Randomizer(object):
    def __call__(self, **kwargs):
        return randint(0, 65536)
