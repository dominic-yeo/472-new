import django, re
from django.urls import get_resolver
from django.urls.resolvers import URLPattern, URLResolver

def describe(view):
    cls = getattr(view, 'view_class', None)
    if cls is not None:
        methods = [m.upper() for m in getattr(cls, 'http_method_names', []) if m not in ('options','head','trace')]
        return f"{cls.__module__}.{cls.__name__}", methods
    name = getattr(view, '__name__', repr(view))
    mod = getattr(view, '__module__', '')
    return f"{mod}.{name}", []

rows=[]
def walk(patterns, prefix=''):
    for p in patterns:
        if isinstance(p, URLResolver):
            walk(p.url_patterns, prefix + str(p.pattern))
        elif isinstance(p, URLPattern):
            pat = prefix + str(p.pattern)
            v, methods = describe(p.callback)
            rows.append((pat, v, ','.join(methods), p.name or ''))

walk(get_resolver().url_patterns)
for r in sorted(set(rows)):
    print('\t'.join(r))
print('TOTAL', len(set(rows)))
