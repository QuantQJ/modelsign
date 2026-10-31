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

#: Conventional name for a directory signature published inside a repository,
#: alongside OMS's ``model.sig``. ``<dir>.sig`` beside the tree also works,
#: but a Hub download never writes outside the snapshot directory.
DIR_SIG_NAME = "modelsign.sig"

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
        self._class_patches: list[tuple[Any, str, Any]] = []

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
            # every relative path, so an added or swapped file breaks it. It
            # may sit beside the tree or, for a published repo, inside it.
            for candidate in (default_sig_path(local), local / DIR_SIG_NAME):
                if candidate.exists():
                    self._check(local, candidate)
                    return str(local)

            # An OMS bundle covers the whole repo the same way, so honour it
            # wherever the deployment has told us which key to trust.
            if self.policy.get("oms_pubkey"):
                for bundle in (
                    local / DEFAULT_BUNDLE_NAME,
                    local.parent / DEFAULT_BUNDLE_NAME,
                ):
                    if bundle.exists():
                        self._check_oms(local, bundle)
                        return str(local)

            # Per-file signatures do not bind a file to its place in the
            # repository, so a snapshot needs a signature over the whole
            # directory unless the caller opts in explicitly.
            if not self.policy.get("allow_per_file", False):
                raise LoadBlocked(
                    f"refused {local.name}: no directory signature "
                    f"({local.name}.sig or {DIR_SIG_NAME}) and no OMS bundle "
                    f"({DEFAULT_BUNDLE_NAME}). Per-file signatures do not bind "
                    "a file to its path; sign the directory, or pass "
                    "allow_per_file=True."
                )

            files = [
                f for f in local.rglob("*") if f.is_file() and f.suffix != ".sig"
            ]

            # Basename ambiguity is about paths, not about missing signatures,
            # so it is refused regardless of the unsigned-file policy.
            by_basename: dict[str, list[Path]] = {}
            for f in files:
                by_basename.setdefault(f.name, []).append(f)
            clashes = {
                name: paths for name, paths in by_basename.items() if len(paths) > 1
            }
            if clashes:
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

            # Every signature present is checked, whatever the policy on files
            # that have none — otherwise allow_unsigned would also wave through
            # a tampered file that *is* signed.
            signed = [f for f in files if default_sig_path(f).exists()]
            for f in signed:
                self._check(f, default_sig_path(f))

            unsigned = [f for f in files if not default_sig_path(f).exists()]
            if unsigned:
                self._unsigned(local, unsigned)
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

    def _wrap_from_pretrained(self, original: Callable) -> Callable:
        """Verify a local path handed straight to from_pretrained.

        A repo id goes through the Hub hooks. A path that already exists
        locally does not download anything, so without this it would load
        unverified.
        """
        def guarded(cls, pretrained_model_name_or_path=None, *args: Any, **kwargs: Any):
            target = pretrained_model_name_or_path
            if target is not None and not isinstance(target, Path) and not isinstance(target, str):
                candidate = None
            else:
                candidate = Path(target).expanduser() if target is not None else None

            if candidate is not None and candidate.exists():
                if candidate.is_dir():
                    for sig in (default_sig_path(candidate), candidate / DIR_SIG_NAME):
                        if sig.exists():
                            self._check(candidate, sig)
                            break
                    else:
                        bundle = candidate / DEFAULT_BUNDLE_NAME
                        if bundle.exists() and self.policy.get("oms_pubkey"):
                            self._check_oms(candidate, bundle)
                        else:
                            self._unsigned(candidate)
                else:
                    sig = default_sig_path(candidate)
                    if sig.exists():
                        self._check(candidate, sig)
                    else:
                        self._unsigned(candidate)

            return original(cls, pretrained_model_name_or_path, *args, **kwargs)

        return guarded

    def _install_local_loaders(self) -> None:
        """Guard from_pretrained for paths that never touch the Hub."""
        transformers = sys.modules.get("transformers")
        if transformers is None:
            try:
                import transformers  # noqa: F811
            except Exception:
                return

        base = getattr(transformers, "PreTrainedModel", None)
        if base is None:
            return
        original = base.__dict__.get("from_pretrained")
        if original is None or getattr(original, "_modelsign_guarded", False):
            return

        underlying = original.__func__ if isinstance(original, classmethod) else original
        guarded = self._wrap_from_pretrained(underlying)
        guarded._modelsign_guarded = True  # type: ignore[attr-defined]
        guarded.__name__ = getattr(underlying, "__name__", "from_pretrained")
        try:
            base.from_pretrained = classmethod(guarded)
        except Exception:
            return
        self._class_patches.append((base, "from_pretrained", original))

    # -- install/remove -------------------------------------------------
    def install(self) -> None:
        """Replace every reachable reference to the download functions.

        ``from huggingface_hub import hf_hub_download`` binds the function
        object into the importing module, and transformers does exactly that.
        Patching only the package attribute would leave those bindings
        pointing at the unguarded original, so this rebinds every module in
        sys.modules that holds one — whatever order the imports happened in.
        """
        try:
            import huggingface_hub
        except ImportError:
            # Nothing to hook on the download path; local loaders still apply,
            # so guarding a workflow that only reads local paths is fine.
            huggingface_hub = None

        wrappers = {
            "hf_hub_download": self._wrap_file,
            "snapshot_download": self._wrap_snapshot,
        }

        replacements: list[tuple[Callable, Callable]] = []
        for name, wrapper in (wrappers.items() if huggingface_hub is not None else ()):
            original = getattr(huggingface_hub, name, None)
            if original is None or getattr(original, "_modelsign_guarded", False):
                continue
            guarded = wrapper(original)
            guarded._modelsign_guarded = True  # type: ignore[attr-defined]
            guarded.__name__ = getattr(original, "__name__", name)
            guarded.__doc__ = getattr(original, "__doc__", None)
            replacements.append((original, guarded))

        if not replacements:
            if self.policy.get("cover_local", True):
                self._install_local_loaders()
            return

        # Compared with `is` rather than looked up in a dict: an arbitrary
        # module attribute may be unhashable, and a TypeError here would abort
        # the sweep with some modules already patched and no way to undo them.
        for module in list(sys.modules.values()):
            if module is None or not hasattr(module, "__dict__"):
                continue
            for attr, value in list(vars(module).items()):
                for original, guarded in replacements:
                    if value is not original:
                        continue
                    try:
                        setattr(module, attr, guarded)
                    except Exception:
                        break
                    self._patches.append((module, attr, value))
                    break

        if self.policy.get("cover_local", True):
            self._install_local_loaders()

    def remove(self) -> None:
        for owner, attr, original in reversed(self._class_patches):
            try:
                setattr(owner, attr, original)
            except Exception:
                continue
        self._class_patches.clear()
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
    allow_per_file: bool = False,
    cover_local: bool = True,
) -> None:
    """Make unverified Hub downloads raise :class:`LoadBlocked`.

    Reads ``MODELSIGN_PUBKEY`` when ``pubkey`` is not given, so a deployment
    can set the trusted key without touching code.
    """
    global _active

    # Environment defaults are resolved before the policy is built, so the
    # comparison below and the guard itself see exactly the same thing.
    if pubkey is None:
        pubkey = os.environ.get("MODELSIGN_PUBKEY") or None
    if oms_pubkey is None:
        oms_pubkey = os.environ.get("MODELSIGN_OMS_PUBKEY") or None

    policy = {
        "pubkey": pubkey,
        "oms_pubkey": oms_pubkey,
        "keyring_dir": keyring_dir,
        "allow_embedded": allow_embedded,
        "allow_unsigned": allow_unsigned,
        "allow_unbound_names": allow_unbound_names,
        "allow_per_file": allow_per_file,
        "cover_local": cover_local,
    }

    if _active is not None:
        if _active.policy == policy:
            return
        raise RuntimeError(
            "modelsign.guard is already installed with a different policy. "
            "Call uninstall() first — silently keeping the earlier policy "
            "would leave a caller believing its own, stricter one was in force."
        )

    # Built from the same dict that was compared, so the two cannot diverge.
    guard = _HubGuard(**policy)
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
