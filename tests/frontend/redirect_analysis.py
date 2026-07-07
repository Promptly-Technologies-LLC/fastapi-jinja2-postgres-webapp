"""Static analysis of RedirectResponse targets in application source."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RedirectSite:
    source_file: str
    line: int
    function_name: str | None
    url_kind: str  # url_path_for | literal | dynamic
    endpoint_name: str | None = None
    literal_path: str | None = None


_PATH_PARAM_RE = re.compile(r"\{[^}]+\}")


def _get_call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Attribute):
        parts: list[str] = []
        current: ast.expr = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    if isinstance(node.func, ast.Name):
        return node.func.id
    return None


class _RedirectVisitor(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.sites: list[RedirectSite] = []
        self._current_function: str | None = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        previous = self._current_function
        self._current_function = node.name
        self.generic_visit(node)
        self._current_function = previous

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        previous = self._current_function
        self._current_function = node.name
        self.generic_visit(node)
        self._current_function = previous

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _get_call_name(node) or ""
        if call_name.endswith("RedirectResponse") or call_name == "RedirectResponse":
            self._record_redirect(node)
        self.generic_visit(node)

    def _record_redirect(self, node: ast.Call) -> None:
        url_expr = None
        status_is_redirect = False
        for keyword in node.keywords:
            if keyword.arg == "url":
                url_expr = keyword.value
            if keyword.arg == "status_code":
                if isinstance(keyword.value, ast.Constant) and keyword.value.value in (
                    301,
                    302,
                    303,
                    307,
                    308,
                ):
                    status_is_redirect = True
        if url_expr is None and node.args:
            url_expr = node.args[0]

        if url_expr is None:
            return

        site = self._classify_url(url_expr, line=node.lineno)
        if site is not None:
            self.sites.append(site)
        elif status_is_redirect:
            self.sites.append(
                RedirectSite(
                    source_file=self.filename,
                    line=node.lineno,
                    function_name=self._current_function,
                    url_kind="dynamic",
                )
            )

    def _classify_url(self, node: ast.expr, *, line: int) -> RedirectSite | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return RedirectSite(
                source_file=self.filename,
                line=line,
                function_name=self._current_function,
                url_kind="literal",
                literal_path=node.value.split("?", 1)[0],
            )

        if isinstance(node, ast.JoinedStr):
            return RedirectSite(
                source_file=self.filename,
                line=line,
                function_name=self._current_function,
                url_kind="dynamic",
            )

        call_name = _get_call_name(node) if isinstance(node, ast.Call) else None
        if call_name and call_name.endswith("url_path_for") and node.args:
            if isinstance(node.args[0], ast.Constant) and isinstance(
                node.args[0].value, str
            ):
                return RedirectSite(
                    source_file=self.filename,
                    line=line,
                    function_name=self._current_function,
                    url_kind="url_path_for",
                    endpoint_name=node.args[0].value,
                )
            return RedirectSite(
                source_file=self.filename,
                line=line,
                function_name=self._current_function,
                url_kind="dynamic",
            )

        if isinstance(node, ast.Call):
            return RedirectSite(
                source_file=self.filename,
                line=line,
                function_name=self._current_function,
                url_kind="dynamic",
            )

        return None


def extract_redirect_sites(
    python_dir: Path,
    *,
    patterns: tuple[str, ...] = ("main.py", "routers/**/*.py"),
) -> list[RedirectSite]:
    sites: list[RedirectSite] = []
    root = python_dir.resolve()
    files: set[Path] = set()
    for pattern in patterns:
        files.update(root.glob(pattern))

    for path in sorted(files):
        if path.suffix != ".py" or not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        tree = ast.parse(path.read_text(), filename=rel)
        visitor = _RedirectVisitor(rel)
        visitor.visit(tree)
        sites.extend(visitor.sites)
    return sites


def iter_route_paths(app) -> set[str]:
    """Return registered HTTP route path patterns from the FastAPI app."""
    return set(app.openapi()["paths"].keys())


def _literal_path_matches_route(literal_path: str, route_paths: set[str]) -> bool:
    for route_path in route_paths:
        if route_path == literal_path:
            return True
        pattern = "^" + _PATH_PARAM_RE.sub(r"[^/]+", route_path) + "$"
        if re.match(pattern, literal_path):
            return True
    return False


def validate_redirect_sites(app, sites: list[RedirectSite]) -> list[str]:
    """Return human-readable errors for static redirect analysis."""
    from pytest_jinja_check.endpoint_validation import get_registered_endpoints

    endpoint_names = get_registered_endpoints(app)
    route_paths = iter_route_paths(app)
    errors: list[str] = []

    for site in sites:
        if site.url_kind == "url_path_for" and site.endpoint_name:
            if site.endpoint_name not in endpoint_names:
                errors.append(
                    f"{site.source_file}:{site.line} in {site.function_name}: "
                    f"url_path_for({site.endpoint_name!r}) references unknown endpoint"
                )
        elif site.url_kind == "literal" and site.literal_path:
            if site.literal_path.startswith(("http://", "https://")):
                continue
            if not _literal_path_matches_route(site.literal_path, route_paths):
                errors.append(
                    f"{site.source_file}:{site.line} in {site.function_name}: "
                    f"redirect literal path {site.literal_path!r} does not match any route"
                )
    return errors
