# Event Agent Filters

## Available filters:
(TBD)

## Adding filters:
Adding a new filter entails the following:

- Writing a module in oio.event.filters, refer to the already defined filters
for a template.
- Adding the filter to the [setup.cfg](../../../setup.cfg) file.
- Modify the event agent configuration template in 
[oio-bootstrap.py](../../../tools/oio-bootstrap.py) to include an entry for
the filter at the bottom _(a `[filter:my_new_filter]` entry)_and to place the 
filter in the pipelines of needed handlers. _(cascading filters is possible and 
working)_
 