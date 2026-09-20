# A one-off helper someone ran by hand years ago. It is not built, not
# shipped and not part of the service — but a scanner walking the tree
# still reports what it imports.
from jinja2 import Template

print(Template('{{ name }}').render(name='report'))
