"""
scanner.py – Core scanning logic for Project Doctor.
"""

import ast
import hashlib
import importlib.util
import re
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Set, Optional
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    WARNING = "warning"
    INFO = "info"
    PASSED = "passed"


class Category(Enum):
    CODE = "code"
    SECURITY = "security"
    DEPENDENCIES = "dependencies"
    STRUCTURE = "structure"
    STORAGE = "storage"


@dataclass
class ScanResult:
    """Represents a single issue found during scanning."""
    severity: Severity
    category: Category
    title: str
    description: str
    file_path: Optional[Path] = None
    line_number: Optional[int] = None
    details: Dict = field(default_factory=dict)


DEFAULT_IGNORED_DIRS = [
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    "env", "dist", "build", "target", ".cache"
]


def list_files(root: Path, ignored_dirs: List[str]) -> List[Path]:
    """Recursively list all files under root, skipping ignored directories."""
    files = []
    for entry in root.rglob("*"):
        if any(part in ignored_dirs for part in entry.parts):
            continue
        if entry.is_file():
            files.append(entry)
    return files


def get_file_hash(file_path: Path, chunk_size: int = 8192) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return ""


def is_binary(file_path: Path) -> bool:
    """Heuristic to detect binary files."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            return b"\0" in chunk
    except Exception:
        return True


def mask_secret(value: str, visible_chars: int = 4) -> str:
    """Mask a secret string, keeping first and last few characters."""
    if len(value) <= visible_chars * 2:
        return "*" * len(value)
    return value[:visible_chars] + "*" * (len(value) - visible_chars * 2) + value[-visible_chars:]


class ProjectScanner:
    """Main scanner that runs all checks and returns results + stats."""

    def __init__(self, ignored_dirs: List[str] = DEFAULT_IGNORED_DIRS,
                 large_warning_mb: int = 100, large_serious_mb: int = 500):
        self.ignored_dirs = ignored_dirs
        self.large_warning_mb = large_warning_mb
        self.large_serious_mb = large_serious_mb
        self.results: List[ScanResult] = []
        self.stats = {
            "file_count": 0,
            "folder_count": 0,
            "total_size_mb": 0.0,
            "largest_files": [],
        }

    def scan(self, project_path: Path) -> Tuple[List[ScanResult], Dict]:
        """Run all scans and return (results, stats)."""
        self.results = []
        self.stats = {
            "file_count": 0,
            "folder_count": 0,
            "total_size_mb": 0.0,
            "largest_files": [],
        }

        # Gather files
        files = list_files(project_path, self.ignored_dirs)
        self.stats["file_count"] = len(files)
        self.stats["folder_count"] = sum(
            1 for d in project_path.rglob("*")
            if d.is_dir() and not any(part in self.ignored_dirs for part in d.parts)
        )

        total_size = 0
        for file in files:
            try:
                size = file.stat().st_size
                total_size += size
                size_mb = size / (1024 * 1024)
                if len(self.stats["largest_files"]) < 10:
                    self.stats["largest_files"].append({"path": str(file), "size_mb": round(size_mb, 2)})
                elif size_mb > self.stats["largest_files"][-1]["size_mb"]:
                    self.stats["largest_files"][-1] = {"path": str(file), "size_mb": round(size_mb, 2)}
                self.stats["largest_files"].sort(key=lambda x: x["size_mb"], reverse=True)
            except Exception:
                continue
        self.stats["total_size_mb"] = round(total_size / (1024 * 1024), 2)

        # Run scans
        self._scan_python_files(project_path)
        self._scan_dependencies(project_path)
        self._scan_security(project_path)
        self._scan_structure(project_path)
        self._scan_duplicates(project_path, files)

        return self.results, self.stats

    # ------------------------------------------------------------
    # Individual scanners
    # ------------------------------------------------------------

    def _scan_python_files(self, root: Path):
        """Check syntax, unused imports, TODO/FIXME, debug statements in .py files."""
        for py_file in root.rglob("*.py"):
            if any(part in self.ignored_dirs for part in py_file.parts):
                continue
            self._scan_python_file(py_file)

    def _scan_python_file(self, file_path: Path):
        if is_binary(file_path):
            return
        try:
            source = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            self.results.append(ScanResult(
                severity=Severity.WARNING,
                category=Category.CODE,
                title="Could not read file",
                description=str(e),
                file_path=file_path
            ))
            return

        # Syntax check
        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError as e:
            self.results.append(ScanResult(
                severity=Severity.CRITICAL,
                category=Category.CODE,
                title="Syntax Error",
                description=f"{e.msg}",
                file_path=file_path,
                line_number=e.lineno
            ))
            return  # can't continue analysis

        # Unused imports
        self._check_unused_imports(tree, file_path)

        # TODO/FIXME/HACK/XXX
        for i, line in enumerate(source.splitlines(), 1):
            for marker in ["TODO", "FIXME", "HACK", "XXX"]:
                if marker in line:
                    self.results.append(ScanResult(
                        severity=Severity.INFO,
                        category=Category.CODE,
                        title=f"{marker} found",
                        description=f"{marker} at line {i}",
                        file_path=file_path,
                        line_number=i
                    ))
                    break

        # Debug code (print, breakpoint)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in ("print", "breakpoint"):
                    self.results.append(ScanResult(
                        severity=Severity.WARNING,
                        category=Category.CODE,
                        title=f"Possible debug code: {func.id}()",
                        description=f"{func.id}() found in code.",
                        file_path=file_path,
                        line_number=node.lineno
                    ))

    def _check_unused_imports(self, tree: ast.AST, file_path: Path):
        imported_names = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split('.')[0]
                    imported_names[name] = node.lineno
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == '*':
                        continue
                    name = alias.asname or alias.name
                    imported_names[name] = node.lineno

        used_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used_names.add(node.id)
            elif isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name):
                    used_names.add(node.value.id)

        for name, lineno in imported_names.items():
            if name not in used_names:
                self.results.append(ScanResult(
                    severity=Severity.WARNING,
                    category=Category.CODE,
                    title="Unused Import",
                    description=f"Import '{name}' appears to be unused.",
                    file_path=file_path,
                    line_number=lineno
                ))

    def _scan_dependencies(self, root: Path):
        """Check requirements.txt for missing packages and imports."""
        # Check requirements.txt if exists
        req_file = root / "requirements.txt"
        if req_file.exists():
            try:
                lines = req_file.read_text(encoding="utf-8").splitlines()
            except Exception as e:
                self.results.append(ScanResult(
                    severity=Severity.WARNING,
                    category=Category.DEPENDENCIES,
                    title="Could not read requirements.txt",
                    description=str(e),
                    file_path=req_file
                ))
                return
            for i, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                pkg_name = re.split(r'[<>=!~]', line)[0].strip()
                if pkg_name:
                    if importlib.util.find_spec(pkg_name) is None:
                        self.results.append(ScanResult(
                            severity=Severity.CRITICAL,
                            category=Category.DEPENDENCIES,
                            title="Missing dependency",
                            description=f"Package '{pkg_name}' is listed but not installed.",
                            file_path=req_file,
                            line_number=i
                        ))
                    else:
                        self.results.append(ScanResult(
                            severity=Severity.PASSED,
                            category=Category.DEPENDENCIES,
                            title="Dependency installed",
                            description=f"Package '{pkg_name}' is installed.",
                            file_path=req_file,
                            line_number=i
                        ))
        else:
            # no requirements.txt, but we can still check imports
            self._scan_imports_installed(root)

    def _scan_imports_installed(self, root: Path):
        """Check all imports across .py files for installed modules."""
        imported_modules = set()
        for py_file in root.rglob("*.py"):
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imported_modules.add(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported_modules.add(node.module.split('.')[0])

        # Filter out stdlib modules
        stdlib = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else set()
        for mod in imported_modules:
            if mod in stdlib:
                continue
            if importlib.util.find_spec(mod) is None:
                self.results.append(ScanResult(
                    severity=Severity.WARNING,
                    category=Category.DEPENDENCIES,
                    title="Import not found",
                    description=f"Module '{mod}' could not be found.",
                ))

    def _scan_security(self, root: Path):
        """Look for potential secrets in text files."""
        patterns = [
            (r'(?i)(api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s]{6,})', "Possible secret"),
            (r'(?i)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["\']?([^"\'\s]{6,})', "AWS credential"),
            (r'(?i)(private[_-]?key)\s*[:=]\s*["\']?([^"\'\s]{6,})', "Private key"),
        ]
        for file in root.rglob("*"):
            if file.is_file() and not any(part in self.ignored_dirs for part in file.parts):
                if is_binary(file):
                    continue
                try:
                    content = file.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                for line_no, line in enumerate(content.splitlines(), 1):
                    for pattern, title in patterns:
                        match = re.search(pattern, line)
                        if match:
                            secret_value = match.group(2)
                            masked = mask_secret(secret_value)
                            self.results.append(ScanResult(
                                severity=Severity.HIGH,
                                category=Category.SECURITY,
                                title=title,
                                description=f"Value looks like: {masked}",
                                file_path=file,
                                line_number=line_no,
                                details={"secret_masked": masked}
                            ))

    def _scan_structure(self, root: Path):
        """Check for common files and folders."""
        essential_files = {
            "README.md": "Project documentation",
            "requirements.txt": "Python dependencies",
            "LICENSE": "License",
        }
        for filename, desc in essential_files.items():
            if not (root / filename).exists():
                self.results.append(ScanResult(
                    severity=Severity.WARNING,
                    category=Category.STRUCTURE,
                    title=f"Missing {filename}",
                    description=f"{desc} not found.",
                ))
            else:
                self.results.append(ScanResult(
                    severity=Severity.PASSED,
                    category=Category.STRUCTURE,
                    title=f"{filename} exists",
                    description=f"{desc} found.",
                ))

        if not (root / "tests").exists() and not (root / "test").exists():
            self.results.append(ScanResult(
                severity=Severity.INFO,
                category=Category.STRUCTURE,
                title="No tests directory",
                description="Consider adding a tests/ directory.",
            ))

        # .gitignore check
        if (root / ".git").exists() and not (root / ".gitignore").exists():
            self.results.append(ScanResult(
                severity=Severity.WARNING,
                category=Category.STRUCTURE,
                title=".gitignore missing",
                description="Project uses Git but has no .gitignore.",
                file_path=root / ".gitignore"
            ))

    def _scan_duplicates(self, root: Path, files: List[Path]):
        """Find duplicate files by content hash."""
        hash_map: Dict[str, List[Path]] = {}
        for file in files:
            if file.stat().st_size == 0:
                continue
            h = get_file_hash(file)
            if h:
                hash_map.setdefault(h, []).append(file)

        for h, group in hash_map.items():
            if len(group) > 1:
                total_size = sum(f.stat().st_size for f in group)
                self.results.append(ScanResult(
                    severity=Severity.WARNING,
                    category=Category.STORAGE,
                    title="Duplicate files",
                    description=f"Found {len(group)} identical files. Total size: {total_size/1024/1024:.2f} MB.",
                    file_path=group[0],
                    details={"group": [str(f) for f in group]}
                ))


def calculate_scores(results: List[ScanResult]) -> Dict[str, float]:
    """Calculate category scores and overall score."""
    penalties = {cat: 0.0 for cat in Category}
    severity_weight = {
        Severity.CRITICAL: 10,
        Severity.HIGH: 5,
        Severity.WARNING: 2,
        Severity.INFO: 0,
        Severity.PASSED: 0,
    }
    category_weight = {
        Category.CODE: 1.0,
        Category.SECURITY: 1.2,
        Category.DEPENDENCIES: 0.8,
        Category.STRUCTURE: 0.6,
        Category.STORAGE: 0.7,
    }
    for res in results:
        if res.severity == Severity.PASSED:
            continue
        penalties[res.category] += severity_weight.get(res.severity, 0) * category_weight.get(res.category, 1.0)

    scores = {}
    for cat in Category:
        scores[cat.value] = round(max(0, 100 - penalties[cat]), 1)

    # Overall weighted
    total_weight = sum(category_weight.values())
    overall = sum(scores[cat.value] * category_weight[cat] for cat in Category) / total_weight
    scores["overall"] = round(overall, 1)
    return scores