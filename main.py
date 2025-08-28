# ~~ start base > mp4 to gif ~~

import os
import sys
import stat
import time
import hmac
import random
import string
import hashlib
import secrets
import argparse
import concurrent.futures

from typing import List, Optional, Dict, Callable
from dataclasses import dataclass
from pathlib import Path

class Chrono:
    def __init__(self) -> None:
        self.t0 = time.perf_counter()
    
    def split(self) -> float:
        return time.perf_counter() - self.t0

class Strata:
    def __init__(self, val: str) -> None:
        self.val = val
    
    def __str__(self) -> str:
        return self.val

@dataclass(frozen = True)
class DIRS:
    input: Path
    temp: Path

@dataclass(frozen = True)
class RunCFG:
    threads: int
    block_sz: int
    pass_ct: int
    
    adv: bool
    dry: bool
    strict: bool
    confirm: bool
    
    redo: int
    delay: float
    verbose: bool

@dataclass(frozen = True)
class Job:
    src: Path
    fprint: str
    size: int

@dataclass(frozen = True)
class JobRSLT:
    reason: Optional[str]
    duration: float
    ok: bool
    
    src: Path
    byte_out: int

def RdmName(n: int) -> str:
    alph = string.ascii_letters + string.digits + "-_"
    
    return "".join(random.choice(alph) for _ in range(n))

def PIn(child: Path, parent: Path) -> bool:
    try:
        child_abs = child.resolve(strict = False)
        parent_abs = parent.resolve(strict = False)
        
        return parent_abs in child_abs.parents or child_abs == parent_abs
    
    except Exception:
        return False

def Fhash_SMPL(p: Path, max_bytes: int = 8 * 1024 * 1024) -> bytes:
    hsh = hashlib.sha256()
    
    try:
        size = p.stat().st_size
    
    except Exception:
        size = 0
    
    if size == 0:
        hsh.update(b"zero")
        hsh.update(p.name.encode("utf-8", "ignore"))
        
        return hsh.digest()
    
    with p.open("rb", buffering = 0) as fh:
        pos_list = [0, size // 7, (size * 2) // 7, (size * 3) // 7, (size * 4) // 7, (size * 5) // 7, max(0, size - 1)]
        total = 0
        
        for pos in pos_list:
            fh.seek(pos)
            
            chunk = fh.read(min(65536, size - pos))
            hsh.update(chunk)
            
            total += len(chunk)
            
            if total >= max_bytes:
                break
    
    hsh.update(p.name.encode("utf-8", "ignore"))
    hsh.update(str(size).encode())
    
    return hsh.digest()

def hkdfExpand(key: bytes, info: bytes, nbytes: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    
    while len(out) < nbytes:
        block = hmac.new(key, block + info + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        
        out += block
        counter += 1
    
    return out[:nbytes]

def hkdfStream(key: bytes, info: bytes, block_sz: int):
    ctr = 0
    
    while True:
        piece = hkdfExpand(key, info + ctr.to_bytes(8, "big"), block_sz)
        ctr += 1
        
        yield piece

def digStream(seed: bytes, block_sz: int):
    ctr = 0
    
    while True:
        digest_block = hashlib.sha256(seed + ctr.to_bytes(8, "big")).digest()
        buf = digest_block * (block_sz // len(digest_block) + 1)
        
        yield buf[:block_sz]
        
        ctr += 1

def invStream(base_gen, block_sz: int):
    for block in base_gen:
        yield bytes(byte_val ^ 0xFF for byte_val in block)

def patternStream(byte_val: int, block_sz: int):
    patt = bytes([byte_val]) * block_sz
    
    while True:
        yield patt

def OpatternStream(b1: int, b2: int, block_sz: int):
    pair = bytes([b1, b2]) * (block_sz // 2 + 1)
    
    while True:
        yield pair[:block_sz]

def secretsStream(block_sz: int):
    while True:
        yield secrets.token_bytes(block_sz)

def buildFPRINT(path: Path) -> str:
    hasher = hashlib.sha1()
    
    try:
        with path.open("rb") as fh:
            while True:
                block = fh.read(1 << 15)
                
                if not block:
                    break
                
                hasher.update(block)
    
    except Exception:
        hasher.update(b"x")
    
    return hasher.hexdigest()

def enmTargets(root: Path) -> List[Path]:
    out: List[Path] = []
    
    for dirpath, dirs, files in os.walk(root):
        if ".completed" in dirs:
            dirs.remove(".completed")
        
        for nm in files:
            path_obj = Path(dirpath) / nm
            
            if path_obj.is_file() and not path_obj.is_symlink():
                out.append(path_obj)
    
    return sorted(out)

def clearAttrsFWin(path_obj: Path) -> None:
    if os.name == "nt":
        os.system(f'attrib -R -S -H "{str(path_obj)}" > NUL 2>&1')

class RealRun:
    def __init__(self, dirs: DIRS, cfg: RunCFG) -> None:
        self.cfg = cfg
        self.dirs = dirs
        self.stages: Dict[str, Callable[[Job], JobRSLT]] = {"WIPE": self.JobEmits}
    
    def run(self, jobs: List[Job]) -> List[JobRSLT]:
        if not jobs:
            return []
        
        if self.cfg.verbose:
            print("==============================================")
            print("─── QUEUE ───")
            
            for j in jobs:
                print(f"+ {j.src} :: {j.size} bytes :: {j.fprint[:12]}")
            
            print("==============================================")
        
        rslts: List[JobRSLT] = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers = self.cfg.threads) as pool:
            futs = [pool.submit(self.call, Strata("WIPE"), j) for j in jobs]
            
            for ext in concurrent.futures.as_completed(futs):
                rslts.append(ext.result())
        
        return rslts
    
    def call(self, stage: Strata, job: Job) -> JobRSLT:
        fnd = self.stages.get(str(stage))
        
        if not fnd:
            return JobRSLT(src = job.src, ok = False, reason = "Error (1) ~~ stage not found", duration = 0.0, byte_out = 0)
        
        return fnd(job)
    
    def JobEmits(self, job: Job) -> JobRSLT:
        timer = Chrono()
        
        if not job.src.exists():
            return JobRSLT(src = job.src, ok = False, reason = "Error (2) ~~ missing file", duration = 0.0, byte_out = 0)
        
        try:
            self.ClrFirst(job)
        
        except Exception as e:
            return JobRSLT(src = job.src, ok = False, reason = f"Error (3) ~~ wipe failed: {e}", duration = timer.split(), byte_out = 0)
        
        return JobRSLT(src = job.src, ok = True, reason = None, duration = timer.split(), byte_out = job.size)
    
    def ClrFirst(self, job: Job) -> None:
        if self.cfg.dry:
            return
        
        for _ in range(self.cfg.redo + 1):
            try:
                clearAttrsFWin(job.src)
                os.chmod(job.src, stat.S_IWUSR | stat.S_IRUSR)
                
                break
            
            except Exception:
                time.sleep(self.cfg.delay)
        
        salt = Fhash_SMPL(job.src)
        key = secrets.token_bytes(32)
        size = job.size
        
        if size > 0:
            self.passNew(job.src, size, key, salt)
        
        self.renameMTD(job.src)
        self.Unlink(job.src)
    
    def passNew(self, path_obj: Path, size: int, key: bytes, salt: bytes) -> None:
        blk = self.cfg.block_sz
        
        fd = None
        
        for _ in range(self.cfg.redo + 1):
            try:
                try:
                    fd = os.open(str(path_obj), os.O_RDWR)
                
                except PermissionError:
                    fd = os.open(str(path_obj), os.O_WRONLY)
                
                break
            
            except Exception:
                time.sleep(self.cfg.delay)
        
        if fd is None:
            raise OSError("Error (4) ~~ open failed after retries")
        
        try:
            for pass_idx in range(1, self.cfg.pass_ct + 1):
                gen = self.slctStream(pass_idx, key, salt, blk)
                written = 0
                
                while written < size:
                    chunk_buf = next(gen)
                    write_len = min(len(chunk_buf), size - written)
                    
                    os.write(fd, chunk_buf[:write_len])
                    written += write_len
                
                os.fsync(fd)
                os.lseek(fd, 0, os.SEEK_SET)
                
                if self.cfg.verbose:
                    print(f"pass {pass_idx}/{self.cfg.pass_ct}: {path_obj.name}")
            
            if self.cfg.adv:
                self.RDMZ(fd, size, blk)
        
        finally:
            os.close(fd)
    
    def slctStream(self, idx: int, key: bytes, salt: bytes, blk: int):
        if idx % 8 == 1:
            return patternStream(0x00, blk)
        
        if idx % 8 == 2:
            return patternStream(0xFF, blk)
        
        if idx % 8 == 3:
            return secretsStream(blk)
        
        if idx % 8 == 4:
            return hkdfStream(key, b"HKDF" + salt, blk)
        
        if idx % 8 == 5:
            return invStream(hkdfStream(key, b"HKDF2" + salt, blk), blk)
        
        if idx % 8 == 6:
            return OpatternStream(0xAA, 0x55, blk)
        
        if idx % 8 == 7:
            return digStream(hashlib.sha256(key + salt).digest(), blk)
        
        return secretsStream(blk)
    
    def RDMZ(self, fd: int, size: int, blk: int) -> None:
        offs = list(range(0, size, blk))
        
        random.shuffle(offs)
        
        lim = max(8, len(offs) // 3)
        
        for off in offs[:lim]:
            os.lseek(fd, off, os.SEEK_SET)
            
            buf = secrets.token_bytes(min(blk, size - off))
            
            os.write(fd, buf)
        
        os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
    
    def renameMTD(self, path_obj: Path) -> None:
        for _ in range(self.cfg.redo + 1):
            try:
                for _ in range(3):
                    new_name = RdmName(random.randint(12, 24))
                    new_path = path_obj.with_name(new_name)
                    
                    try:
                        path_obj.rename(new_path)
                        
                        path_obj = new_path
                    
                    except FileExistsError:
                        continue
                    
                    ts = time.time() - random.randint(0, 365 * 86400)
                    os.utime(path_obj, (ts, ts))
                
                ts = time.time() - random.randint(0, 365 * 86400)
                gy = self.dirs.temp / RdmName(8)
                
                path_obj.rename(gy)
                os.utime(gy, (ts, ts))
                
                path_obj = gy
                
                return
            
            except Exception:
                time.sleep(self.cfg.delay)
    
    def Unlink(self, path_obj: Path) -> None:
        for _ in range(self.cfg.redo + 1):
            try:
                os.remove(path_obj)
                return
            
            except FileNotFoundError:
                return
            
            except PermissionError:
                try:
                    clearAttrsFWin(path_obj)
                    
                    os.chmod(path_obj, stat.S_IWUSR)
                    os.remove(path_obj)
                    
                    return
                
                except Exception:
                    time.sleep(self.cfg.delay)
            
            except Exception:
                time.sleep(self.cfg.delay)

def dirCheck(path_obj: Path) -> Path:
    path_obj.mkdir(parents = True, exist_ok = True)
    
    return path_obj

def jobsPyld(root: Path) -> List[Job]:
    targets = enmTargets(root)
    
    jobs: List[Job] = []
    
    for path_obj in targets:
        fp = buildFPRINT(path_obj)
        
        try:
            sz = path_obj.stat().st_size
        
        except Exception:
            sz = 0
        
        jobs.append(Job(src = path_obj, fprint = fp, size = sz))
    
    return jobs

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog = "m_g_f_r")
    
    ap.add_argument("--adv", action = "store_true")
    ap.add_argument("--yes", action = "store_true")
    ap.add_argument("--redo", type = int, default = 2)
    ap.add_argument("--passes", type = int, default = 7)
    ap.add_argument("--input", type = str, default = "input")
    ap.add_argument("--threads", type = int, default = max(2, os.cpu_count() or 2))
    ap.add_argument("--block", type = int, default = 1024 * 1024)
    ap.add_argument("--delay", type = float, default = 0)
    ap.add_argument("--verbose", action = "store_true")
    ap.add_argument("--strict", action = "store_true")
    ap.add_argument("--dry", action = "store_true")
    
    return ap.parse_args(argv)

def main(argv: Optional[List[str]] = None) -> int:
    recv = parse_args(argv)
    
    in_root = dirCheck(Path(recv.input).expanduser().resolve())
    temp_root = dirCheck(in_root.joinpath(".completed").resolve())
    
    cfg = RunCFG(
        threads = recv.threads,
        pass_ct = max(1, recv.passes),
        block_sz = max(4096, recv.block),
        
        adv = bool(recv.adv),
        dry = bool(recv.dry),
        confirm = bool(recv.yes),
        strict = bool(recv.strict),
        
        redo = max(0, recv.redo),
        delay = max(0.0, recv.delay),
        verbose = bool(recv.verbose)
    )
    
    print("==============================================")
    print("─── PARSED ARGS ───")
    print(f"Input: {in_root}")
    print(f"Passes: {cfg.pass_ct}")
    print(f"Block: {cfg.block_sz}")
    print(f"Threads: {cfg.threads}")
    print(f"Advanced: {cfg.adv}")
    print(f"Dry: {cfg.dry}")
    print(f"Redo: {cfg.redo}")
    print(f"Delay: {cfg.delay}")
    print(f"Verbose: {cfg.verbose}")
    print("==============================================")
    
    time.sleep(1.0)
    
    os.system("cls")
    
    if not cfg.confirm:
        print("")
        print(f"Everything inside {in_root} will be unrecoverable type YES to confirm")
        
        answ = input("~> ").strip()
        
        if answ != "YES":
            print("stopped")
            return 0
        
    print("Working...")
    
    jobs = jobsPyld(in_root)
    
    if not jobs:
        print("==============================================")
        print("Error (5) ~~ no files to destroy in input")
        print("==============================================")
        return 0
    
    runner = RealRun(dirs = DIRS(input = in_root, temp = temp_root), cfg = cfg)
    
    timer = Chrono(); rslts = runner.run(jobs)
    took = timer.split()
    
    byte_ammt = sum(r.byte_out for r in rslts)
    ok_ammt = sum(1 for r in rslts if r.ok)
    fails_ammt = len(rslts) - ok_ammt
    
    fpack = hashlib.sha1("".join(j.fprint for j in jobs).encode()).hexdigest() if jobs else "0" * 40
    session_tag = f"S{int(time.time())}_{fpack[:12]}"
    
    os.system("cls")
    
    print("")
    print("==============================================")
    print("─── RESULT ───")
    print(f"ID: {session_tag}")
    print("")
    print(f"SUCCESS: {ok_ammt}")
    print(f"IN_AMMT: {len(jobs)}")
    print(f"FAILED: {fails_ammt}")
    print(f"T_BYTES: {byte_ammt}")
    print("")
    print(f"IN: {in_root}")
    print(f"TMP: {temp_root}")
    print(f"Needed: {took:.3f}s to complete")
    print("==============================================")
    
    if fails_ammt:
        print("─── FAILS ───")
        for r in rslts:
            if not r.ok:
                print(f"x {r.src} :: {r.reason}")
        print("==============================================")
    
    if cfg.strict and fails_ammt:
        return 2
    
    return 0

if __name__ == "__main__":
    random.seed(secrets.randbits(64))
    sys.exit(main())