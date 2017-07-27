from argparse import Action


class KeyValueAction(Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is None:
            setattr(namespace, self.dest, {})

        if '=' in values:
            getattr(namespace, self.dest, {}).update([values.split('=', 1)])
        else:
            getattr(namespace, self.dest, {}).pop(values, None)


class ValueFormatStoreTrueAction(Action):
    """Same as 'store_true', but also set 'formatter' field to 'value'"""
    def __init__(self, option_strings, dest, nargs=0, **kwargs):
        super(ValueFormatStoreTrueAction, self).__init__(
              option_strings, dest, nargs=nargs, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, True)
        setattr(namespace, "formatter", "value")
