"""Fail-closed signature checks at model load time.

Signing only matters where something refuses to proceed without it. This
module puts that refusal in the place every Python ML stack passes through:
the Hugging Face Hub download path used by ``transformers``,
``sentence-transformers``, ``diffusers`` and vLLM.

    import modelsign.guard as guard
    guard.install(pubkey="~/keys/vendor.pem")

From then on a download whose signature is missing, modified or signed by an
unknown key raises :class:`LoadBlocked` instead of returning weights.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Callable, Optional

from modelsign.api import VerifyError, VerifyResult, default_sig_path, verify_model
from modelsign.oms import DEFAULT_BUNDLE_NAME, OMSError, verify_bundle

__all__ = ["LoadBlocked", "require_verified", "install", "uninstall", "is_installed"]


class LoadBlocked(RuntimeError):
    """A model was refused because it did not verify."""

    def __init__(self, message: str, result: Optional[VerifyResult] = None):
        super().__init__(message)
        self.result = result


def require_verified(
    model_path: Path | str,
    *,
    sig_path: Path | str | None = None,
    pubkey: Path | str | None = None,
    keyring_dir: Path | str | None = None,
    allow_embedded: bool = False,
    allow_unbound_names: bool = False,
) -> VerifyResult:
    """Verify a model or raise :class:`LoadBlocked`.

    ``allow_embedded`` accepts a signature that can only be checked against
    its own embedded key. That proves the bytes are unchanged since signing
    and nothing about who signed them, so it stays off by default.

    ``allow_unbound_names`` accepts a modelsign 1.x signature of a single
    file, where the filename is not covered by the signature and two signed
    files can be presented under each other's names. Also off by default,
    because this runs at the point an attacker's file would be loaded.
    """
    try:
        result = verify_model(
            model_path,
            sig_path=sig_path,
            pubkey=pubkey,
            keyring_dir=keyring_dir,
            require_trusted=not allow_embedded,
            require_name_binding=not allow_unbound_names,
        )
    except VerifyError as e:
        raise LoadBlocked(f"refused {Path(model_path).name}: {e}") from e

    if not result.verified:
        detail = f" — {result.detail}" if result.detail else ""
        raise LoadBlocked(
            f"refused {Path(model_path).name}: {result.error}{detail}", result
        )
    return result


class _HubGuard:
    """Wraps huggingface_hub download functions with a verification step."""

    def __init__(self, **policy: Any):
        self.policy = policy
        self._patches: list[tuple[Any, str, Callable]] = []

    # -- policy ---------------------------------------------------------
    @property
    def allow_unsigned(self) -> bool:
        return bool(self.policy.get("allow_unsigned", False))

    def _check(self, path: Path, sig: Path | None = None) -> None:
        require_verified(
            path,
            sig_path=sig,
            pubkey=self.policy.get("pubkey"),
            keyring_dir=self.policy.get("keyring_dir"),
            allow_embedded=bool(self.policy.get("allow_embedded", False)),
            allow_unbound_names=bool(self.policy.get("allow_unbound_names", False)),
        )

    def _check_oms(self, path: Path, bundle: Path) -> None:
        try:
            result = verify_bundle(
                path,
                bundle,
                pubkey=self.policy["oms_pubkey"],
                allow_unsigned=self.allow_unsigned,
            )
        except (OMSError, VerifyError) as e:
            raise LoadBlocked(f"refused {path.name}: {e}") from e
        if not result.verified:
            detail = f" — {result.detail}" if result.detail else ""
            raise LoadBlocked(
                f"refused {path.name}: {result.error}{detail}", result
            )

    def _unsigned(self, path: Path, unsigned: list[Path] | None = None) -> None:
        if self.allow_unsigned:
            return
        if unsigned:
            names = ", ".join(sorted(str(f.relative_to(path)) for f in unsigned[:5]))
            more = f" (+{len(unsigned) - 5} more)" if len(unsigned) > 5 else ""
            detail = f"unsigned files: {names}{more}"
        else:
            detail = "no signature found"
        raise LoadBlocked(
            f"refused {path.name}: {detail}. Sign it with 'modelsign sign', or pass "
            "allow_unsigned=True to accept unsigned weights."
        )

    # -- wrappers -------------------------------------------------------
    def _wrap_file(self, original: Callable) -> Callable:
        def guarded(*args: Any, **kwargs: Any) -> Any:
            local = Path(original(*args, **kwargs))
            sig = default_sig_path(local)
            if not sig.exists():
                sig = self._fetch_sig(original, local, args, kwargs)
            if sig is None:
                self._unsigned(local)
                return str(local)
            self._check(local, sig)
            return str(local)

        return guarded

    def _wrap_snapshot(self, original: Callable) -> Callable:
        def guarded(*args: Any, **kwargs: Any) -> Any:
            local = Path(original(*args, **kwargs))

            # A directory signature is the strong form: its manifest covers
            # every file, so an added or swapped file breaks the hash.
            whole = default_sig_path(local)
            if whole.exists():
                self._check(local, whole)
                return str(local)

            # An OMS bundle covers the whole repo the same way, so honour it
            # wherever the deployment has told us which key to trust.
            oms_bundle = local / DEFAULT_BUNDLE_NAME
            if oms_bundle.exists() and self.policy.get("oms_pubkey"):
                self._check_oms(local, oms_bundle)
                return str(local)

            # Falling back to per-file signatures, every file must carry one.
            # Verifying only the files that happen to be signed would let an
            # unsigned file ride along beside a signed one.
            files = [
                f for f in local.rglob("*") if f.is_file() and f.suffix != ".sig"
            ]
            unsigned = [f for f in files if not default_sig_path(f).exists()]
            if unsigned:
                self._unsigned(local, unsigned)
                return str(local)

            # A single-file signature authenticates the basename, not the path
            # it sits at, so two files sharing a basename in different
            # directories could be swapped for each other. A directory
            # signature has no such gap; refuse the ambiguity instead.
            by_basename: dict[str, list[Path]] = {}
            for f in files:
                by_basename.setdefault(f.name, []).append(f)
            clashes = {
                name: paths for name, paths in by_basename.items() if len(paths) > 1
            }
            if clashes and not self.allow_unsigned:
                detail = "; ".join(
                    f"{name} at " + ", ".join(
                        sorted(p.relative_to(local).as_posix() for p in paths)
                    )
                    for name, paths in sorted(clashes.items())
                )
                raise LoadBlocked(
                    f"refused {local.name}: per-file signatures authenticate the "
                    f"basename only, and these share one — {detail}. Sign the "
                    "directory instead, which covers every relative path."
                )

            for f in files:
                self._check(f, default_sig_path(f))
            return str(local)

        return guarded

    def _fetch_sig(
        self, original: Callable, local: Path, args: tuple, kwargs: dict
    ) -> Optional[Path]:
        """Try to pull MODEL.sig from the same repo as the file just fetched."""
        filename = kwargs.get("filename")
        if filename is None and len(args) >= 2:
            filename = args[1]
        if filename is None:
            return None

        sig_kwargs = dict(kwargs)
        sig_kwargs["filename"] = str(filename) + ".sig"
        sig_args = args[:1]
        try:
            return Path(original(*sig_args, **sig_kwargs))
        except Exception:
            return None

    # -- install/remove -------------------------------------------------
    def install(self) -> None:
        """Replace every reachable reference to the download functions.

        ``from huggingface_hub import hf_hub_download`` binds the function
        object into the importing module, and transformers does exactly that.
        Patching only the package attribute would leave those bindings
        pointing at the unguarded original, so this rebinds every module in
        sys.modules that holds one — whatever order the imports happened in.
        """
        import huggingface_hub

        wrappers = {
            "hf_hub_download": self._wrap_file,
            "snapshot_download": self._wrap_snapshot,
        }

        guarded_by_original = {}
        for name, wrapper in wrappers.items():
            original = getattr(huggingface_hub, name, None)
            if original is None or getattr(original, "_modelsign_guarded", False):
                continue
            guarded = wrapper(original)
            guarded._modelsign_guarded = True  # type: ignore[attr-defined]
            guarded.__name__ = getattr(original, "__name__", name)
            guarded.__doc__ = getattr(original, "__doc__", None)
            guarded_by_original[original] = (name, guarded)

        if not guarded_by_original:
            return

        for module in list(sys.modules.values()):
            if module is None:
                continue
            for attr, value in list(vars(module).items()) if hasattr(module, "__dict__") else []:
                match = guarded_by_original.get(value) if callable(value) else None
                if match is None:
                    continue
                _, guarded = match
                try:
                    setattr(module, attr, guarded)
                except Exception:
                    continue
                self._patches.append((module, attr, value))

    def remove(self) -> None:
        for module, attr, original in reversed(self._patches):
            try:
                setattr(module, attr, original)
            except Exception:
                continue
        self._patches.clear()


_active: Optional[_HubGuard] = None


def install(
    *,
    pubkey: Path | str | None = None,
    oms_pubkey: Path | str | None = None,
    keyring_dir: Path | str | None = None,
    allow_embedded: bool = False,
    allow_unsigned: bool = False,
    allow_unbound_names: bool = False,
) -> None:
    """Make unverified Hub downloads raise :class:`LoadBlocked`.

    Reads ``MODELSIGN_PUBKEY`` when ``pubkey`` is not given, so a deployment
    can set the trusted key without touching code.
    """
    global _active
    if _active is not None:
        return

    if pubkey is None:
        pubkey = os.environ.get("MODELSIGN_PUBKEY") or None
    if oms_pubkey is None:
        oms_pubkey = os.environ.get("MODELSIGN_OMS_PUBKEY") or None

    guard = _HubGuard(
        pubkey=pubkey,
        oms_pubkey=oms_pubkey,
        keyring_dir=keyring_dir,
        allow_embedded=allow_embedded,
        allow_unsigned=allow_unsigned,
        allow_unbound_names=allow_unbound_names,
    )
    guard.install()
    _active = guard


def uninstall() -> None:
    """Restore the unguarded Hub functions."""
    global _active
    if _active is None:
        return
    _active.remove()
    _active = None


def is_installed() -> bool:
    return _active is not None
