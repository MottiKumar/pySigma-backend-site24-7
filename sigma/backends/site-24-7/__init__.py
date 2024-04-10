from .site-24-7 import site-24-7-Backend
# TODO: add all backend classes that should be exposed to the user of your backend in the import statement above.

backends = {        # Mapping between backend identifiers and classes. This is used by the pySigma plugin system to recognize backends and expose them with the identifier.
    "site-24-7": site-24-7-Backend,
}