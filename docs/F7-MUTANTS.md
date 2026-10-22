# F7 mutation audit (`retry_rate_store.py`)

Security-critical subset: `flock_timeout_s`, `_accept_live_creating_pending`,
`_writer_still_alive`, `_writer_is_zombie`, `_writer_holds_hw_flock`,
`high_water_lock.write_intent`.

- **Total mutants (subset):** 196
- **Killed (tests):** 189
- **Equivalent (survived with proof):** 7 (+ semantic `sem_timeout_no_blank_check`)
- **Unexplained:** 0

Killer suite: `tests/test_mutmut_f7_killers.py` (plus A1a/A3a/C5/A2b/timeout
tests in `tests/test_settlement.py`). Raise-removal killers:
`tests/test_raise_refusal_killers.py`.

## Priority: timeout bound checks (`≤0`, `>600`, non-finite)

| mutant id | line | change | killing test / equivalence |
|---|---:|---|---|
| `x_flock_timeout_s__mutmut_1` | 498 | `if _ENV_FLOCK_TIMEOUT_S not in os.environ:` → `if _ENV_FLOCK_TIMEOUT_S in os.environ:` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |
| `x_flock_timeout_s__mutmut_2` | 500 | `raw = os.environ.get(_ENV_FLOCK_TIMEOUT_S, "")` → `raw = None` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |
| `x_flock_timeout_s__mutmut_3` | 500 | `raw = os.environ.get(_ENV_FLOCK_TIMEOUT_S, "")` → `raw = os.environ.get(None, "")` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |
| `x_flock_timeout_s__mutmut_4` | 500 | `raw = os.environ.get(_ENV_FLOCK_TIMEOUT_S, "")` → `raw = os.environ.get(_ENV_FLOCK_TIMEOUT_S, None)` | equivalent — Default arg of `os.environ.get` is unused: we only call `get` after confirming `_ENV_FLOCK_TIMEOUT_S in os.environ`, so changing `""`→`None` never observes a missing key. |
| `x_flock_timeout_s__mutmut_5` | 500 | `raw = os.environ.get(_ENV_FLOCK_TIMEOUT_S, "")` → `raw = os.environ.get("")` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |
| `x_flock_timeout_s__mutmut_6` | 500 | `raw = os.environ.get(_ENV_FLOCK_TIMEOUT_S, "")` → `raw = os.environ.get(_ENV_FLOCK_TIMEOUT_S, )` | equivalent — Same as mutmut_4: `get(key, )` is `get(key, None)`; default unused when key is present. |
| `x_flock_timeout_s__mutmut_7` | 500 | `raw = os.environ.get(_ENV_FLOCK_TIMEOUT_S, "")` → `raw = os.environ.get(_ENV_FLOCK_TIMEOUT_S, "XXXX")` | equivalent — Default `"XXXX"` unused when key is present (blank/invalid values come from the env value itself, not the default). |
| `x_flock_timeout_s__mutmut_8` | 501 | `if not str(raw).strip():` → `if str(raw).strip():` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |
| `x_flock_timeout_s__mutmut_9` | 501 | `if not str(raw).strip():` → `if not str(None).strip():` | equivalent — `if not str(None).strip()` is always False (`"None"` is truthy), so the blank branch never fires; blank/`"   "` still fail via `float(...)` → `RetryRateIntegrityError`. |
| `x_flock_timeout_s__mutmut_10` | 505 | `f"for default {_DEFAULT_FLOCK_TIMEOUT_S:g}s)"` → `None` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |
| `x_flock_timeout_s__mutmut_11` | 508 | `val = float(str(raw).strip())` → `val = None` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |
| `x_flock_timeout_s__mutmut_12` | 508 | `val = float(str(raw).strip())` → `val = float(None)` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |
| `x_flock_timeout_s__mutmut_13` | 508 | `val = float(str(raw).strip())` → `val = float(str(None).strip())` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |
| `x_flock_timeout_s__mutmut_14` | 511 | `f"{_ENV_FLOCK_TIMEOUT_S}={raw!r} is not a finite float; refuse"` → `None` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |
| `x_flock_timeout_s__mutmut_15` | 513 | `if not math.isfinite(val):` → `if math.isfinite(val):` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |
| `x_flock_timeout_s__mutmut_16` | 513 | `if not math.isfinite(val):` → `if not math.isfinite(None):` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |
| `x_flock_timeout_s__mutmut_17` | 515 | `f"{_ENV_FLOCK_TIMEOUT_S}={raw!r} is not finite; refuse"` → `None` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |
| `x_flock_timeout_s__mutmut_18` | 517 | `if val <= 0:` → `if val < 0:` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |
| `x_flock_timeout_s__mutmut_19` | 517 | `if val <= 0:` → `if val <= 1:` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |
| `x_flock_timeout_s__mutmut_20` | 519 | `f"{_ENV_FLOCK_TIMEOUT_S}={val!r} must be > 0; refuse"` → `None` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |
| `x_flock_timeout_s__mutmut_21` | 521 | `if val > _MAX_FLOCK_TIMEOUT_S:` → `if val >= _MAX_FLOCK_TIMEOUT_S:` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |
| `x_flock_timeout_s__mutmut_22` | 524 | `f"{_MAX_FLOCK_TIMEOUT_S:g}s; refuse"` → `None` | killed — tests/test_mutmut_f7_killers.py::test_mut_flock_timeout_* / test_flock_timeout_env_refuses_* |

## Original REA survivors (43) — kill or prove

| mutant id | line | change | killing test / equivalence |
|---|---:|---|---|
| `x__writer_is_zombie__mutmut_3` | 425 | `with open(f"/proc/{int(pid)}/stat", "r", encoding="utf-8") as fh:` → `with open(f"/proc/{int(pid)}/stat", "r", encoding=None) as fh:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_zombie_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_is_zombie__mutmut_5` | 425 | `with open(f"/proc/{int(pid)}/stat", "r", encoding="utf-8") as fh:` → `with open(f"/proc/{int(pid)}/stat", encoding="utf-8") as fh:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_zombie_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_is_zombie__mutmut_6` | 425 | `with open(f"/proc/{int(pid)}/stat", "r", encoding="utf-8") as fh:` → `with open(f"/proc/{int(pid)}/stat", "r", ) as fh:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_zombie_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_is_zombie__mutmut_11` | 425 | `with open(f"/proc/{int(pid)}/stat", "r", encoding="utf-8") as fh:` → `with open(f"/proc/{int(pid)}/stat", "r", encoding="UTF-8") as fh:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_zombie_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_is_zombie__mutmut_13` | 459 | `return False` → `return True` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_zombie_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_is_zombie__mutmut_16` | 432 | `rparen = buf.rfind(")")` → `rparen = buf.find(")")` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_zombie_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_is_zombie__mutmut_18` | 433 | `if rparen < 0:` → `if rparen <= 0:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_zombie_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_is_zombie__mutmut_19` | 433 | `if rparen < 0:` → `if rparen < 1:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_zombie_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_is_zombie__mutmut_20` | 459 | `return False` → `return True` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_zombie_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_is_zombie__mutmut_28` | 459 | `return False` → `return True` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_zombie_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_still_alive__mutmut_6` | 475 | `if int(pid) <= 0:` → `if int(pid) < 0:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_still_alive_*` |
| `x__writer_still_alive__mutmut_7` | 475 | `if int(pid) <= 0:` → `if int(pid) <= 1:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_still_alive_*` |
| `x__writer_still_alive__mutmut_15` | 459 | `return False` → `return True` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_still_alive_*` |
| `x__writer_still_alive__mutmut_23` | 459 | `return False` → `return True` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_still_alive_*` |
| `x_flock_timeout_s__mutmut_4` | 500 | `raw = os.environ.get(_ENV_FLOCK_TIMEOUT_S, "")` → `raw = os.environ.get(_ENV_FLOCK_TIMEOUT_S, None)` | **equivalent**: Default arg of `os.environ.get` is unused: we only call `get` after confirming `_ENV_FLOCK_TIMEOUT_S in os.environ`, so changing `""`→`None` never observes a missing key. |
| `x_flock_timeout_s__mutmut_6` | 500 | `raw = os.environ.get(_ENV_FLOCK_TIMEOUT_S, "")` → `raw = os.environ.get(_ENV_FLOCK_TIMEOUT_S, )` | **equivalent**: Same as mutmut_4: `get(key, )` is `get(key, None)`; default unused when key is present. |
| `x_flock_timeout_s__mutmut_7` | 500 | `raw = os.environ.get(_ENV_FLOCK_TIMEOUT_S, "")` → `raw = os.environ.get(_ENV_FLOCK_TIMEOUT_S, "XXXX")` | **equivalent**: Default `"XXXX"` unused when key is present (blank/invalid values come from the env value itself, not the default). |
| `x_flock_timeout_s__mutmut_9` | 501 | `if not str(raw).strip():` → `if not str(None).strip():` | **equivalent**: `if not str(None).strip()` is always False (`"None"` is truthy), so the blank branch never fires; blank/`"   "` still fail via `float(...)` → `RetryRateIntegrityError`. |
| `x__writer_holds_hw_flock__mutmut_1` | 566 | `if pid is None or int(pid) <= 0 or fcntl is None:` → `if pid is None or int(pid) <= 0 and fcntl is None:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_holds_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_holds_hw_flock__mutmut_5` | 566 | `if pid is None or int(pid) <= 0 or fcntl is None:` → `if pid is None or int(pid) < 0 or fcntl is None:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_holds_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_holds_hw_flock__mutmut_6` | 566 | `if pid is None or int(pid) <= 0 or fcntl is None:` → `if pid is None or int(pid) <= 1 or fcntl is None:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_holds_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_holds_hw_flock__mutmut_11` | 459 | `return False` → `return True` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_holds_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_holds_hw_flock__mutmut_14` | 459 | `return False` → `return True` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_holds_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_holds_hw_flock__mutmut_21` | 577 | `with open("/proc/locks", "r", encoding="utf-8") as fh:` → `with open("/proc/locks", "r", encoding=None) as fh:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_holds_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_holds_hw_flock__mutmut_23` | 577 | `with open("/proc/locks", "r", encoding="utf-8") as fh:` → `with open("/proc/locks", encoding="utf-8") as fh:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_holds_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_holds_hw_flock__mutmut_24` | 577 | `with open("/proc/locks", "r", encoding="utf-8") as fh:` → `with open("/proc/locks", "r", ) as fh:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_holds_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_holds_hw_flock__mutmut_30` | 577 | `with open("/proc/locks", "r", encoding="utf-8") as fh:` → `with open("/proc/locks", "r", encoding="UTF-8") as fh:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_holds_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_holds_hw_flock__mutmut_32` | 459 | `return False` → `return True` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_holds_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_holds_hw_flock__mutmut_34` | 584 | `if len(parts) < 6:` → `if len(parts) <= 6:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_holds_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_holds_hw_flock__mutmut_35` | 584 | `if len(parts) < 6:` → `if len(parts) < 7:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_holds_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_holds_hw_flock__mutmut_36` | 551 | `continue` → `break` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_holds_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_holds_hw_flock__mutmut_40` | 551 | `continue` → `break` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_holds_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_holds_hw_flock__mutmut_43` | 551 | `continue` → `break` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_holds_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_holds_hw_flock__mutmut_65` | 551 | `continue` → `break` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_holds_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__writer_holds_hw_flock__mutmut_66` | 598 | `if ino == want_ino and dev == want_dev:` → `if ino == want_ino or dev == want_dev:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_holds_* / test_mut_open_encoding_is_utf8_lowercase` |
| `x__accept_live_creating_pending__mutmut_5` | 618 | `if int(rec.writer_pid or -1) == os.getpid():` → `if int(rec.writer_pid or +1) == os.getpid():` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_accept_*` |
| `x__accept_live_creating_pending__mutmut_6` | 618 | `if int(rec.writer_pid or -1) == os.getpid():` → `if int(rec.writer_pid or -2) == os.getpid():` | **equivalent**: `writer_pid or -1` vs `or -2`: for any falsy pid (`None`/`0`), both yield a negative sentinel ≠ any live `getpid()`; for any truthy pid both yield the pid. Control flow identical. |
| `xǁhigh_water_lockǁwrite_intent__mutmut_4` | 1491 | `rec.writer_pid = None` → `rec.writer_pid = ""` | **equivalent**: Mutates the creating-clear in `write_intent` (L1491); `_atomic_write_hw_record` then forces `writer_pid=None` when `intent is None` (L778–780) before MAC/serialize. |
| `xǁhigh_water_lockǁwrite_intent__mutmut_5` | 1492 | `rec.writer_start = None` → `rec.writer_start = ""` | **equivalent**: Mutates the creating-clear in `write_intent` (L1492); same sanitizer as mutmut_4 for `writer_start=""` → forced `None` when `intent is None` before write. |
| `xǁhigh_water_lockǁwrite_intent__mutmut_13` | 1497 | `"high-water intent already pending for "` → `"XXhigh-water intent already pending for XX"` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_write_intent_*` |
| `xǁhigh_water_lockǁwrite_intent__mutmut_21` | 1503 | `"high-water intent must be confirmed+1 for "` → `"XXhigh-water intent must be confirmed+1 for XX"` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_write_intent_*` |
| `xǁhigh_water_lockǁwrite_intent__mutmut_22` | 1503 | `"high-water intent must be confirmed+1 for "` → `"HIGH-WATER INTENT MUST BE CONFIRMED+1 FOR "` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_write_intent_*` |
| `xǁhigh_water_lockǁwrite_intent__mutmut_27` | 1511 | `if self._write_marker is None:` → `if self._write_marker is not None:` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_write_intent_*` |
| `xǁhigh_water_lockǁwrite_intent__mutmut_28` | 1512 | `self._write_marker = _mark_write_active()` → `self._write_marker = None` | **killed** by `tests/test_mutmut_f7_killers.py::test_mut_write_intent_*` |

## Equivalent survivors (detail)

### `x_flock_timeout_s__mutmut_4`

Default arg of `os.environ.get` is unused: we only call `get` after confirming `_ENV_FLOCK_TIMEOUT_S in os.environ`, so changing `""`→`None` never observes a missing key.

### `x_flock_timeout_s__mutmut_6`

Same as mutmut_4: `get(key, )` is `get(key, None)`; default unused when key is present.

### `x_flock_timeout_s__mutmut_7`

Default `"XXXX"` unused when key is present (blank/invalid values come from the env value itself, not the default).

### `x_flock_timeout_s__mutmut_9`

`if not str(None).strip()` is always False (`"None"` is truthy), so the blank branch never fires; blank/`"   "` still fail via `float(...)` → `RetryRateIntegrityError`.

### `x__accept_live_creating_pending__mutmut_6`

`writer_pid or -1` vs `or -2`: for any falsy pid (`None`/`0`), both yield a negative sentinel ≠ any live `getpid()`; for any truthy pid both yield the pid. Control flow identical.

### `xǁhigh_water_lockǁwrite_intent__mutmut_4`

Mutates `write_intent`'s creating-clear at L1491 (`writer_pid=None` → `""`). `_atomic_write_hw_record` immediately forces `writer_pid=None` when `intent is None` (L778–780) before MAC/serialize, so the empty-string assignment never reaches disk.

### `xǁhigh_water_lockǁwrite_intent__mutmut_5`

Mutates `write_intent`'s creating-clear at L1492 (`writer_start=None` → `""`). Same sanitizer as mutmut_4: empty string forced to `None` when `intent is None` before write.

### `sem_timeout_no_blank_check` (semantic)

**Equivalent.** Removing the blank/`strip()` guard in `flock_timeout_s` does not admit a blank env value: `float("")` / `float("   ")` still raises `ValueError`, which the existing `except` turns into `RetryRateIntegrityError` (`… is not a finite float; refuse`). Same observable refusal as keeping the dedicated blank raise (cf. `x_flock_timeout_s__mutmut_9`).

