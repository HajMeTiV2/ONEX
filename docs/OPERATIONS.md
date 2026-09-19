# ONEX Operations

Recommended checks before deployment:

```bash
python scripts/verify_project.py
python -m compileall -q main.py onex tests
python tests/smoke_native.py
```

Railway can continue using the existing root `main.py` entrypoint, so the directory refactor does not require changing the deployment command.
