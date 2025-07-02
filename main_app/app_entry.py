from importlib import import_module

try:
    module = import_module('main_app.main')
except ModuleNotFoundError:
    try:
        module = import_module('main')
    except ModuleNotFoundError as e:
        raise RuntimeError('Cannot import FastAPI app') from e

app = getattr(module, 'app', None)
if app is None:
    raise RuntimeError('App instance not found') 