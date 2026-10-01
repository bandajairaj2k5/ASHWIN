"""
ASHWIN Moto G3 Jail & Path Boundary Enforcement (Section 8.8, Section 10, Test T-36).
Strictly confines all file and directory access to the dedicated ASHWIN_STORAGE directory.
Rejects path traversal (..), absolute paths, UNC paths, symlinks, junctions, and null bytes.
"""

import os
from typing import Tuple


class JailSecurityError(Exception):
    """Raised when a path traversal, symlink, or boundary violation is detected."""
    pass


class StorageJail:
    """
    Enforces rigid filesystem isolation for ASHWIN_STORAGE.
    """

    def __init__(self, root_path: str):
        self.raw_root = os.path.abspath(root_path)
        os.makedirs(self.raw_root, exist_ok=True)
        # Canonicalize the jail root once at startup
        self.canonical_root = os.path.realpath(self.raw_root)
        
        # Standard subcategories
        for folder in ["Documents", "Resumes", "Projects", "Photos", "Reports", "Other"]:
            os.makedirs(os.path.join(self.canonical_root, folder), exist_ok=True)

    def validate_and_resolve(self, req_path: str, is_directory: bool = False) -> str:
        """
        Validates request path against the jail root boundary.
        Enforces:
          1. Character sanitization (reject null bytes, backslashes, control characters).
          2. Canonical realpath resolution.
          3. Root boundary prefix check (cannot escape ASHWIN_STORAGE).
          4. Symlink rejection (realpath must match normalized path).
          5. Target existence and object type verification.
        """
        if not req_path or not isinstance(req_path, str):
            raise JailSecurityError("Invalid path: Path must be a non-empty string.")

        # 1. Reject forbidden characters
        if any(c in req_path for c in ['\0', '\\', '\r', '\n', '\t']):
            raise JailSecurityError("Invalid path: Contains illegal characters or backslashes.")

        # Clean leading/trailing slashes
        clean_path = req_path.strip("/ ")
        if not clean_path:
            if is_directory:
                return self.canonical_root
            raise JailSecurityError("Invalid path: Cannot target root as a file.")

        # 2. Resolve relative to canonical root
        target_path = os.path.abspath(os.path.join(self.canonical_root, clean_path))
        canonical_target = os.path.realpath(target_path)

        # 3. Root-Boundary Invariant
        # Ensure target is strictly inside canonical root
        prefix = self.canonical_root + os.sep
        if canonical_target != self.canonical_root and not canonical_target.startswith(prefix):
            raise JailSecurityError(f"Path Traversal Denied: '{req_path}' resolves outside ASHWIN_STORAGE.")

        # 4. Symlink / Reparse Check (RULE-07, Section 8.8)
        # If realpath differs from the normalized path, a symlink/junction was navigated
        if os.path.islink(target_path) or target_path != canonical_target:
            raise JailSecurityError(f"Symlink Navigation Denied: '{req_path}' involves symbolic links.")

        # 5. Object Type Check
        if not os.path.exists(canonical_target):
            raise FileNotFoundError(f"File '{clean_path}' not found in ASHWIN_STORAGE.")

        if is_directory:
            if not os.path.isdir(canonical_target):
                raise JailSecurityError(f"Target '{clean_path}' is not a directory.")
        else:
            if not os.path.isfile(canonical_target):
                raise JailSecurityError(f"Target '{clean_path}' is not a regular file.")

        return canonical_target
