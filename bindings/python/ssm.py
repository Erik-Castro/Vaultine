import ctypes
import ctypes.util
from enum import IntEnum
from pathlib import Path
from typing import Callable, Iterator, List, Optional, Tuple, Union


class SSMStatus(IntEnum):
    OK = 0
    ERR_AUTH = 1
    ERR_NOT_FOUND = 2
    ERR_EXPIRED = 3
    ERR_INTEGRITY = 4
    ERR_INTERNAL = 5


class SSMError(Exception):
    def __init__(self, status: int, operation: str = ""):
        self.status = SSMStatus(status)
        self.operation = operation
        msg = ssm_status_to_string(self.status.value)
        prefix = f"[{operation}] " if operation else ""
        super().__init__(f"{prefix}{msg} (code={status})")


def _load_so(path: Optional[Union[str, Path]] = None) -> ctypes.CDLL:
    if path is None:
        candidates = [
            Path("./build/src/libssm.so"),
            Path("./build/libssm.so"),
            Path("./libssm.so"),
            Path("/usr/local/lib/libssm.so"),
        ]
        for c in candidates:
            if c.exists():
                path = str(c.resolve())
                break
        if path is None:
            found = ctypes.util.find_library("ssm")
            if found:
                path = found
            else:
                raise RuntimeError(
                    "libssm.so not found. Pass path explicitly or build with: cmake -B build && cmake --build build"
                )

    lib = ctypes.CDLL(str(path))

    lib.ssm_init.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_size_t,
    ]
    lib.ssm_init.restype = ctypes.c_int

    lib.ssm_destroy.argtypes = [ctypes.c_void_p]
    lib.ssm_destroy.restype = ctypes.c_int

    lib.ssm_user_register.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
    ]
    lib.ssm_user_register.restype = ctypes.c_int

    lib.ssm_user_authenticate.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_int),
    ]
    lib.ssm_user_authenticate.restype = ctypes.c_int

    lib.ssm_user_delete.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
    ]
    lib.ssm_user_delete.restype = ctypes.c_int

    lib.ssm_user_change_password.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
    ]
    lib.ssm_user_change_password.restype = ctypes.c_int

    lib.ssm_secret_store.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_char_p,
    ]
    lib.ssm_secret_store.restype = ctypes.c_int

    lib.ssm_secret_get.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_size_t),
    ]
    lib.ssm_secret_get.restype = ctypes.c_int

    lib.ssm_secret_delete.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
    ]
    lib.ssm_secret_delete.restype = ctypes.c_int

    lib.ssm_secret_list.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p,
        ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_char_p,
                         ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    lib.ssm_secret_list.restype = ctypes.c_int

    lib.ssm_kek_rotate.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.ssm_kek_rotate.restype = ctypes.c_int

    lib.ssm_status_to_string.argtypes = [ctypes.c_int]
    lib.ssm_status_to_string.restype = ctypes.c_char_p

    return lib


def ssm_status_to_string(status: int) -> str:
    return _lib.ssm_status_to_string(status).decode()


_lib = _load_so()

_SecretListCb = ctypes.CFUNCTYPE(
    None, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
    ctypes.c_size_t, ctypes.c_void_p,
)


def _check(status: int, operation: str = "") -> None:
    if status != 0:
        raise SSMError(status, operation)


class SSMHandle:
    def __init__(self, db_path: str = ":memory:",
                 db_key: Optional[bytes] = None,
                 lib_path: Optional[Union[str, Path]] = None):
        self._path = db_path
        self._key = db_key
        self._handle: Optional[ctypes.c_void_p] = None
        if lib_path is not None:
            global _lib
            _lib = _load_so(lib_path)

    def __enter__(self) -> "SSMHandle":
        h = ctypes.c_void_p()
        key_ptr = None
        key_len = 0
        if self._key:
            key_ptr = (ctypes.c_ubyte * len(self._key)).from_buffer_copy(self._key)
            key_len = len(self._key)
        _check(_lib.ssm_init(ctypes.byref(h), self._path.encode(),
                             key_ptr, key_len), "ssm_init")
        self._handle = h
        return self

    def __exit__(self, *args) -> None:
        if self._handle is not None:
            _lib.ssm_destroy(self._handle)
            self._handle = None

    @property
    def _h(self) -> ctypes.c_void_p:
        if self._handle is None:
            raise RuntimeError("SSMHandle not opened (use 'with' statement)")
        return self._handle

    def user_register(self, username: str, password: str) -> None:
        _check(_lib.ssm_user_register(self._h, username.encode(),
                                      password.encode()), "user_register")

    def user_authenticate(self, username: str, password: str) -> bool:
        out = ctypes.c_int()
        _check(_lib.ssm_user_authenticate(self._h, username.encode(),
                                          password.encode(),
                                          ctypes.byref(out)), "user_authenticate")
        return bool(out.value)

    def user_delete(self, username: str, password: str) -> None:
        _check(_lib.ssm_user_delete(self._h, username.encode(),
                                    password.encode()), "user_delete")

    def user_change_password(self, username: str, old: str, new: str) -> None:
        _check(_lib.ssm_user_change_password(self._h, username.encode(),
                                             old.encode(), new.encode()),
               "user_change_password")

    def secret_store(self, username: str, private_key: bytes,
                     public_key: Optional[bytes] = None,
                     name: str = "", description: Optional[str] = None) -> None:
        priv_arr = (ctypes.c_ubyte * len(private_key)).from_buffer_copy(private_key)
        pub_ptr = None
        pub_len = 0
        if public_key:
            pub_arr = (ctypes.c_ubyte * len(public_key)).from_buffer_copy(public_key)
            pub_ptr = pub_arr
            pub_len = len(public_key)
        desc_ptr = description.encode() if description else None
        _check(_lib.ssm_secret_store(
            self._h, username.encode(),
            priv_arr, len(private_key),
            pub_ptr, pub_len,
            name.encode(), desc_ptr,
        ), "secret_store")

    def secret_get(self, username: str, name: str,
                   max_size: int = 65536) -> Tuple[bytes, Optional[bytes]]:
        buf = (ctypes.c_ubyte * max_size)()
        buf_len = ctypes.c_size_t(max_size)
        pub_buf = (ctypes.c_ubyte * max_size)()
        pub_len = ctypes.c_size_t(max_size)
        st = _lib.ssm_secret_get(
            self._h, username.encode(), name.encode(),
            buf, ctypes.byref(buf_len),
            pub_buf, ctypes.byref(pub_len),
        )
        if st == SSMStatus.ERR_INTERNAL and buf_len.value > max_size:
            return self.secret_get(username, name, max_size=buf_len.value)
        _check(st, "secret_get")
        priv = bytes(buf[: buf_len.value])
        pub = bytes(pub_buf[: pub_len.value]) if pub_len.value > 0 else None
        return priv, pub

    def secret_delete(self, username: str, name: str) -> None:
        _check(_lib.ssm_secret_delete(self._h, username.encode(),
                                      name.encode()), "secret_delete")

    def secret_list(self, username: str) -> Iterator[Tuple[str, Optional[str], str, int]]:
        results: List[Tuple[str, Optional[str], str, int]] = []

        def cb(name: bytes, desc: Optional[bytes], updated: bytes,
               pub_len: int, _: int) -> None:
            results.append((
                name.decode(),
                desc.decode() if desc else None,
                updated.decode(),
                pub_len,
            ))

        cb_ptr = _SecretListCb(cb)
        _check(_lib.ssm_secret_list(self._h, username.encode(),
                                    cb_ptr, None), "secret_list")
        yield from results

    def kek_rotate(self, username: str) -> None:
        _check(_lib.ssm_kek_rotate(self._h, username.encode()), "kek_rotate")

    @property
    def raw_handle(self) -> Optional[ctypes.c_void_p]:
        return self._handle
