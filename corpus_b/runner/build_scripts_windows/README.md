# Windows Build Commands for Coverity

This folder stores Windows-native build commands used by `run_coverity_windows.py`.

## File

- `build_commands_windows.json`: project -> command mapping.

## Format

```json
{
  "raylib": {
    "default": "cmake -S . -B build -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Debug && cmake --build build --config Debug"
  }
}
```

## Notes

- Commands are executed from repo root via `cmd /c`.
- Use `default` for both `V` and `S`, or define version-specific commands:

```json
{
  "raylib": {
    "V": "...",
    "S": "...",
    "default": "..."
  }
}
```

- Set `"__NOT_CONFIGURED__"` to explicitly skip unsupported projects.
