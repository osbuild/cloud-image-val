from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from pathlib import Path

import yaml

_VALID_ENVIRONMENTS = {"local", "automated"}

_REQUIRED_FIELDS = {"resources_file", "output_file"}
_STRING_FIELDS = {
    "instances_json", "ssh_identity_file", "ssh_pub_key_file",
    "ssh_config_file", "test_filter", "include_markers",
}
_BOOL_FIELDS = {"debug", "parallel", "stop_cleanup"}


@dataclass
class CoreConfig:
    resources_file: str
    output_file: str
    environment: str = "local"
    tags: dict[str, str] | None = None
    debug: bool = False
    parallel: bool = False
    stop_cleanup: bool = False
    instances_json: str = "/tmp/civ-instances.json"
    ssh_identity_file: str = "/tmp/civ-ssh-key"
    ssh_pub_key_file: str = "/tmp/civ-ssh-key.pub"
    ssh_config_file: str = "/tmp/civ-ssh-config"
    test_filter: str | None = None
    test_suites: list[str] | None = None
    include_markers: str | None = None

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        for name in _REQUIRED_FIELDS:
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"'{name}' is required and must be a non-empty string"
                )

        for name in _STRING_FIELDS:
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise ValueError(
                    f"'{name}' must be a string, got {type(value).__name__}"
                )

        if not isinstance(self.environment, str) or self.environment not in _VALID_ENVIRONMENTS:
            raise ValueError(
                f"'environment' must be one of {sorted(_VALID_ENVIRONMENTS)}, "
                f"got {self.environment!r}"
            )

        for name in _BOOL_FIELDS:
            value = getattr(self, name)
            if not isinstance(value, bool):
                raise ValueError(
                    f"'{name}' must be a bool, got {type(value).__name__}"
                )

        if self.tags is not None:
            if not isinstance(self.tags, dict):
                raise ValueError(
                    f"'tags' must be a dict or None, got {type(self.tags).__name__}"
                )
            for k, v in self.tags.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    raise ValueError(
                        f"'tags' keys and values must be strings, "
                        f"got key={type(k).__name__}, value={type(v).__name__}"
                    )

        if self.test_suites is not None:
            if not isinstance(self.test_suites, list):
                raise ValueError(
                    f"'test_suites' must be a list or None, got {type(self.test_suites).__name__}"
                )
            for i, item in enumerate(self.test_suites):
                if not isinstance(item, str):
                    raise ValueError(
                        f"'test_suites[{i}]' must be a string, got {type(item).__name__}"
                    )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> CoreConfig:
        if not isinstance(data, dict):
            raise ValueError(
                f"Expected a dict, got {type(data).__name__}"
            )

        for name in _REQUIRED_FIELDS:
            if name not in data or data[name] is None:
                raise ValueError(
                    f"'{name}' is required and must be a non-empty string"
                )

        known = {f.name for f in fields(cls)}
        filtered: dict[str, object] = {}
        for key, value in data.items():
            if key not in known:
                continue
            if key == "stop_cleanup" and value is None:
                value = False
            filtered[key] = value

        return cls(**filtered)

    @classmethod
    def from_yaml(cls, path: str) -> CoreConfig:
        yaml_path = Path(path)
        if not yaml_path.is_file():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(yaml_path) as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as exc:
                raise ValueError(
                    f"Failed to parse YAML config at {path}: {exc}"
                ) from exc

        if not isinstance(data, dict):
            raise ValueError(
                f"Config file must contain a YAML mapping, got {type(data).__name__}"
            )

        return cls.from_dict(data)
