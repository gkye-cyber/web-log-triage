from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import json
import mmap
import os
import subprocess
import tempfile

@dataclass
class MemoryRegion:
    start_addr: int
    end_addr: int
    permission: str # eg: 'r-xp', 'rw-p', rwxp'
    path: str       # eg: '[heap]', '[stack]', '[anon:zend_alloc]'
    pid: int = 0
    process_name: str = "php-fpm"

@dataclass
class HeapChunk:
    address: int
    size: int
    is_freed: bool
    target_ptr: int = 0
    owner_worker_pid: int = 0
    current_worker_pid: int = 0

@dataclass
class FunctionPointer:
    symbol_name: str  # eg: 'zend_execute_ex', 'zend_stream_open'
    target_addr: int
    valid_min_addr: int
    valid_max_addr: int
    pid: int = 0

@dataclass
class OpcacheScript:
    script_path: str  # eg: "/var/www/index.php" or "eval()'d code"
    memory_addr: int
    exists_on_disk: bool
    payload_preview: str = ""
    pid: int = 0

@dataclass
class ProcessInfo:
    pid: int
    ppid: int
    name: str          # eg: 'sh', 'bash', 'cmd.exe'
    parent_name: str   # eg: 'php-fpm', 'httpd', 'nginx'
    cmdline: str = ""

@dataclass
class MemorySnapshot:
    source: str
    regions: list[MemoryRegion] = field(default_factory=list)
    heap_chunks: list[HeapChunk] = field(default_factory=list)
    function_pointers: list[FunctionPointer] = field(default_factory=list)
    opcache_scripts: list[OpcacheScript] = field(default_factory=list)
    processes: list[ProcessInfo] = field(default_factory=list)
    raw_signatures: list[str] = field(default_factory=list)