from importlib import import_module

try:
    module = import_module('main_app.app_entry')
    app = module.app
except ModuleNotFoundError:
    try:
        module = import_module('main_app.main')
    except ModuleNotFoundError:
        module = import_module('main')
    app = getattr(module, 'app', None)

if app is None:
    raise RuntimeError('Could not locate FastAPI app instance') 