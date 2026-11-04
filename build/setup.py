from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from setuptools import Extension, setup

ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parent
CONFIG_PATH = ROOT / "build_config.json"

try:
    CONFIG: dict[str, Any] = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
except FileNotFoundError as exc:
    raise SystemExit(f"Build configuration not found: {CONFIG_PATH}") from exc
except json.JSONDecodeError as exc:
    raise SystemExit(f"Invalid JSON in {CONFIG_PATH}: {exc}") from exc


def select_module() -> tuple[str, dict[str, Any]]:
    """Read --module and leave the remaining arguments for setuptools."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--module", required=True)
    args, setuptools_args = parser.parse_known_args()
    sys.argv = [sys.argv[0], *setuptools_args]

    if not isinstance(CONFIG, dict) or not CONFIG:
        raise ValueError(
            "build_config.json must be a non-empty object whose top-level keys are module names"
        )

    module_config = CONFIG.get(args.module)
    if not isinstance(module_config, dict):
        available = ", ".join(str(name) for name in CONFIG)
        raise ValueError(
            f"Unknown module {args.module!r}. Configured modules: {available or '(none)'}"
        )
    return args.module, module_config


def setup_distribution(module_key: str, module_config: dict[str, Any], extensions: list[Extension]) -> None:
    """Run setuptools for a module, including a successful no-op when skipped."""
    setup(
        name=str(module_config.get("distribution_name", module_key)),
        version=str(module_config.get("version", "0.2.0")),
        description=str(module_config.get("description", f"{module_key} native extension")),
        ext_modules=extensions,
        zip_safe=False,
        python_requires=str(module_config.get("python_requires", ">=3.10")),
    )


def resolve_repository_paths(values: object, setting_name: str) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise ValueError(f"{setting_name} must be an array of path strings")

    resolved: list[str] = []
    for value in values:
        path = Path(value)
        resolved.append(
            str(path if path.is_absolute() else (REPOSITORY_ROOT / path).resolve())
        )
    return resolved


def compiler_arguments(value: object, compiler: str) -> list[str]:
    """Read compiler flags from either a compiler-keyed object or a list."""
    if value is None:
        return []
    if isinstance(value, dict):
        result = value.get(compiler, [])
    else:
        result = value
    if not isinstance(result, list):
        raise ValueError("compiler_args must be an array or a compiler-keyed object")
    if any(not isinstance(argument, str) for argument in result):
        raise ValueError("compiler_args entries must be strings")
    return list(result)


MODULE_KEY, MODULE_CONFIG = select_module()
CURRENT_PLATFORM = "windows" if os.name == "nt" else "linux"
SUPPORTED_PLATFORMS = {"linux", "windows"}
MODULE_PLATFORMS = MODULE_CONFIG.get("platforms", ["linux", "windows"])
if (
    not isinstance(MODULE_PLATFORMS, list)
    or not MODULE_PLATFORMS
    or any(
        not isinstance(platform, str) or platform not in SUPPORTED_PLATFORMS
        for platform in MODULE_PLATFORMS
    )
):
    raise ValueError(
        f"{MODULE_KEY}.platforms must be a non-empty array containing only 'linux' and/or 'windows'"
    )

if CURRENT_PLATFORM not in MODULE_PLATFORMS:
    print(
        f"Skipping module {MODULE_KEY!r}: current platform is {CURRENT_PLATFORM}, "
        f"but configured platforms are {', '.join(MODULE_PLATFORMS)}. No compilation will run.",
        flush=True,
    )
    # setuptools accepts an empty extension list and returns successfully from
    # `build_ext`; this makes a platform mismatch a successful no-op, not a
    # failed matrix build. The workflow should still avoid expecting an output
    # binary for this module on the unsupported platform.
    setup_distribution(MODULE_KEY, MODULE_CONFIG, extensions=[])
    raise SystemExit(0)

# Import pybind11 only after the platform check so skipped modules do not need
# their extension build requirements merely to complete the no-op setup call.
import pybind11  # noqa: E402

MODULE_NAME = MODULE_CONFIG.get("module_name", MODULE_KEY)
if not isinstance(MODULE_NAME, str) or not MODULE_NAME.strip():
    raise ValueError(f"Module {MODULE_KEY!r} has an invalid module_name")

IS_WINDOWS = os.name == "nt"
COMPILER = "msvc" if IS_WINDOWS else "unix"
CXX_STANDARD = int(MODULE_CONFIG.get("cxx_standard", 17))
if CXX_STANDARD < 17:
    raise ValueError("Native extensions require C++17 or newer")

sources = MODULE_CONFIG.get("sources")
if not isinstance(sources, list) or not sources:
    raise ValueError(f"Module {MODULE_KEY!r} must define a non-empty sources array")
source_paths = resolve_repository_paths(sources, f"{MODULE_KEY}.sources")
for source in source_paths:
    if not Path(source).is_file():
        raise FileNotFoundError(
            f"Source file for module {MODULE_KEY!r} does not exist: {source}"
        )

extra_compile_args = compiler_arguments(MODULE_CONFIG.get("compiler_args"), COMPILER)
if IS_WINDOWS:
    extra_compile_args.append(f"/std:c++{CXX_STANDARD}")
else:
    extra_compile_args.append(f"-std=c++{CXX_STANDARD}")

libraries_key = "windows_libraries" if IS_WINDOWS else "unix_libraries"
libraries = MODULE_CONFIG.get(libraries_key, [])
if not isinstance(libraries, list) or any(not isinstance(item, str) for item in libraries):
    raise ValueError(f"{MODULE_KEY}.{libraries_key} must be an array of strings")

include_dirs = [pybind11.get_include()]
include_dirs.extend(
    resolve_repository_paths(MODULE_CONFIG.get("include_dirs", []), f"{MODULE_KEY}.include_dirs")
)

extension = Extension(
    name=MODULE_NAME,
    sources=source_paths,
    include_dirs=include_dirs,
    libraries=list(libraries),
    language="c++",
    extra_compile_args=extra_compile_args,
)

setup_distribution(MODULE_KEY, MODULE_CONFIG, extensions=[extension])