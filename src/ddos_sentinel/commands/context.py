"""Shared CLI context, output and concise error handling."""

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from typer.core import TyperGroup

from ddos_sentinel.core.config import LabConfig
from ddos_sentinel.core.database import Database

console = Console(stderr=True)


class SentinelGroup(TyperGroup):
    def invoke(self, ctx: Any) -> Any:
        try:
            return super().invoke(ctx)
        except (ValueError, OSError, sqlite3.Error) as exc:
            raise typer.BadParameter(str(exc)) from exc


@dataclass
class Context:
    config: LabConfig
    database_path: Path
    json_output: bool = False

    @property
    def db(self) -> Database:
        return Database(self.database_path)


def context(ctx: typer.Context) -> Context:
    value = ctx.find_root().obj
    if not isinstance(value, Context):
        raise ValueError("CLI context is unavailable")
    return value


def emit(value: Any) -> None:
    """Always emit valid JSON for scriptability; Rich safety messages go to stderr."""
    typer.echo(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False))
