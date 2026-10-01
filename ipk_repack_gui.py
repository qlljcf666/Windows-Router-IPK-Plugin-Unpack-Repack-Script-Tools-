# -*- coding: utf-8 -*-
"""
解包目录扫描 -> IPK 自动打包 图形化工具

功能:
  1. 选择(或自动发现)解包目录, 定位 system_rootfs/usr/lib/opkg/info
  2. 扫描全部 .control/.list, 列出每个插件的版本/架构/分类/文件数/缺失数
  3. 勾选要打包的插件(支持搜索、仅看缺失、全选/反选)
  4. 后台线程打包, 实时进度与日志, 可随时停止
  5. 输出标准 .ipk (gzip tar: ./debian-binary ./data.tar.gz ./control.tar.gz,
     与 OpenWrt 官方包格式一致, opkg 可直接安装)
     以及按包归类的文件树 packages/<pkg>/
  6. 双击包名查看 control 信息与文件清单(缺失/符号链接高亮)

仅依赖 Python 标准库 (tkinter/tarfile), Windows 直接运行:
    python ipk_repack_gui.py
"""
import os
import sys
import io as _io
import csv
import glob
import shutil
import tarfile
import threading
import queue
import traceback

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ---------------------------------------------------------------------------
# 核心逻辑 (与命令行版 repack_ipk.py 相同的打包规则)
# ---------------------------------------------------------------------------

MAINT_SCRIPTS = ("preinst", "postinst", "prerm", "postrm")


def read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        return f.read()


def parse_control(path):
    fields = {}
    last = None
    for line in read_text(path).splitlines():
        if line.startswith(" ") and last:
            fields[last] += "\n" + line
        elif ":" in line:
            k, v = line.split(":", 1)
            fields[k.strip()] = v.strip()
            last = k.strip()
    return fields


def sanitize(name):
    for ch in '\\/:*?"<>| ':
        name = name.replace(ch, "_")
    return name


def find_info_dir(base):
    """在用户选择的目录下寻找 usr/lib/opkg/info, 返回 (info_dir, rootfs_dir)。"""
    if not base or not os.path.isdir(base):
        return None, None
    rel = os.path.join("usr", "lib", "opkg", "info")
    # 1) 直接是 rootfs
    p = os.path.join(base, rel)
    if os.path.isdir(p):
        return p, os.path.normpath(base)
    # 2) 一级子目录是 rootfs
    for child in sorted(glob.glob(os.path.join(base, "*"))):
        p = os.path.join(child, rel)
        if os.path.isdir(p):
            return p, os.path.normpath(child)
    # 3) 深一层: <base>/*/*_unpack/system_rootfs 等
    for child in sorted(glob.glob(os.path.join(base, "*", "*"))):
        p = os.path.join(child, rel)
        if os.path.isdir(p):
            return p, os.path.normpath(child)
    return None, None


def is_exec_path(rel):
    parts = rel.replace("\\", "/").split("/")
    top = parts[:-1]
    base = parts[-1]
    if any(p in ("bin", "sbin") for p in top):
        return True
    if base.endswith((".sh", ".cgi")):
        return True
    if ".so" in base:
        return True
    if rel.startswith("etc/init.d/") or rel.startswith("etc/hotplug.d/"):
        return True
    return False


def scan_one(info_dir, pkg_stem):
    """扫描单个包, 返回元信息 dict (不做复制/打包)。"""
    cpath = os.path.join(info_dir, pkg_stem + ".control")
    fields = parse_control(cpath)
    pkg = fields.get("Package", pkg_stem)

    entries = []  # (rel, kind)  kind: dir/file/link/missing
    list_path = os.path.join(info_dir, pkg_stem + ".list")
    rootfs = os.path.normpath(os.path.join(info_dir, "..", "..", "..", ".."))
    if os.path.exists(list_path):
        seen = set()
        for ln in read_text(list_path).splitlines():
            ln = ln.strip().lstrip("/")
            if ln and ln not in seen:
                seen.add(ln)
                src = os.path.join(rootfs, ln.replace("/", os.sep))
                if os.path.islink(src):
                    kind = "link"
                elif os.path.isfile(src):
                    kind = "file"
                elif os.path.isdir(src):
                    kind = "dir"
                else:
                    kind = "missing"
                entries.append((ln, kind))

    conf_path = os.path.join(info_dir, pkg_stem + ".conffiles")
    conffiles = []
    if os.path.exists(conf_path):
        conffiles = [l.strip().lstrip("/") for l in read_text(conf_path).splitlines() if l.strip()]

    counts = {"file": 0, "dir": 0, "link": 0, "missing": 0}
    for _, k in entries:
        counts[k] += 1

    return {
        "stem": pkg_stem,
        "package": pkg,
        "version": fields.get("Version", "unknown"),
        "arch": fields.get("Architecture", "all"),
        "section": fields.get("Section", ""),
        "depends": fields.get("Depends", ""),
        "description": fields.get("Description", "").strip().replace("\n", " "),
        "installed_size": fields.get("Installed-Size", ""),
        "entries": entries,
        "conffiles": conffiles,
        "counts": counts,
    }


# ----------------------------- ar / tar 打包 -----------------------------

def _add_bytes(tar, arcname, data, mode=0o644):
    ti = tarfile.TarInfo(name=arcname)
    ti.size = len(data)
    ti.mode = mode
    ti.mtime = 0
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = "root"
    tar.addfile(ti, _io.BytesIO(data))


def _add_member(tar, src, arcname, mode, linktarget=None):
    ti = tarfile.TarInfo(name=arcname)
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = "root"
    ti.mode = mode
    if linktarget is not None:
        ti.type = tarfile.SYMTYPE
        ti.linkname = linktarget
        ti.mtime = 0
        tar.addfile(ti)
        return
    ti.mtime = int(os.path.getmtime(src))
    ti.size = os.path.getsize(src)
    with open(src, "rb") as f:
        tar.addfile(ti, f)


def _add_dir(tar, arcname):
    ti = tarfile.TarInfo(name=arcname.rstrip("/") + "/")
    ti.type = tarfile.DIRTYPE
    ti.mode = 0o755
    ti.mtime = 0
    tar.addfile(ti)


def _write_ipk(path, members):
    """ipk 外层 = gzip tar (OpenWrt 官方格式: ./debian-binary ./data.tar.gz ./control.tar.gz)
    不能用 ar 归档 —— 路由器 opkg 对 ar 格式报 "Malformed package file"。"""
    with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT, compresslevel=9) as t:
        for name, payload in members:
            ti = tarfile.TarInfo("./" + name)
            ti.size = len(payload)
            ti.mode = 0o644
            ti.mtime = 0
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            t.addfile(ti, _io.BytesIO(payload))


def build_one(meta, info_dir, rootfs, out_dir, do_ipk, do_dirs, log):
    """构建单个包的归类目录和/或 ipk, 返回 manifest 行 dict。"""
    pkg = meta["package"]
    pkg_out = os.path.join(out_dir, "packages", pkg)
    ctrl_out = os.path.join(pkg_out, "CONTROL")

    # ---- CONTROL 内容 ----
    control_files = {}
    control_text = read_text(os.path.join(info_dir, meta["stem"] + ".control"))
    if not control_text.endswith("\n"):
        control_text += "\n"
    control_files["control"] = control_text.encode("utf-8")
    if os.path.exists(os.path.join(info_dir, meta["stem"] + ".conffiles")):
        raw = read_text(os.path.join(info_dir, meta["stem"] + ".conffiles"))
        control_files["conffiles"] = (raw if raw.endswith("\n") else raw + "\n").encode("utf-8")
    for s in MAINT_SCRIPTS:
        sp = os.path.join(info_dir, meta["stem"] + "." + s)
        if os.path.exists(sp):
            control_files[s] = read_text(sp).encode("utf-8")

    # ---- 归类目录 ----
    if do_dirs:
        if os.path.isdir(pkg_out):
            shutil.rmtree(pkg_out, ignore_errors=True)
        os.makedirs(ctrl_out, exist_ok=True)
        for name, data in control_files.items():
            with open(os.path.join(ctrl_out, name), "wb") as f:
                f.write(data)

    # ---- data 成员清单 + 文件复制 ----
    conf_set = set(meta["conffiles"])
    file_entries = [(r, k) for r, k in meta["entries"] if k != "dir"]
    needed_dirs = set()
    for rel, _ in file_entries:
        p = os.path.dirname(rel)
        while p:
            needed_dirs.add(p)
            p = os.path.dirname(p)
    # list 中登记的目录本身
    for rel, k in meta["entries"]:
        if k == "dir":
            needed_dirs.add(rel)

    data_specs = []  # (src|None, arc, mode, linktarget, kind)
    for d in sorted(needed_dirs):
        data_specs.append((None, "./" + d, 0o755, None, "dir"))
        if do_dirs:
            os.makedirs(os.path.join(pkg_out, d.replace("/", os.sep)), exist_ok=True)

    for rel, k in file_entries:
        src = os.path.join(rootfs, rel.replace("/", os.sep))
        arc = "./" + rel
        if k == "link":
            target = os.readlink(src)
            data_specs.append((src, arc, 0o777, target, "link"))
            if do_dirs:
                marker = os.path.join(pkg_out, rel.replace("/", os.sep) + ".symlink")
                os.makedirs(os.path.dirname(marker), exist_ok=True)
                with open(marker, "w", encoding="utf-8", newline="") as f:
                    f.write(target)
        elif k == "file":
            mode = 0o755 if is_exec_path(rel) else 0o644
            data_specs.append((src, arc, mode, None, "file"))
            if do_dirs:
                dst = os.path.join(pkg_out, rel.replace("/", os.sep))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)
        # missing: 跳过

    ipk_name = ""
    if do_ipk:
        cbuf = _io.BytesIO()
        with tarfile.open(fileobj=cbuf, mode="w:gz", compresslevel=9) as tar:
            for name, data in control_files.items():
                m = 0o755 if name in MAINT_SCRIPTS else 0o644
                _add_bytes(tar, "./" + name, data, m)

        dbuf = _io.BytesIO()
        with tarfile.open(fileobj=dbuf, mode="w:gz", compresslevel=9) as tar:
            for src, arc, mode, target, kind in data_specs:
                if kind == "dir":
                    _add_dir(tar, arc)
                elif kind == "link":
                    _add_member(tar, src, arc, mode, linktarget=target)
                else:
                    _add_member(tar, src, arc, mode)

        ipk_name = "%s_%s_%s.ipk" % (
            sanitize(pkg), sanitize(meta["version"]), sanitize(meta["arch"]))
        ipk_dir = os.path.join(out_dir, "ipk")
        os.makedirs(ipk_dir, exist_ok=True)
        _write_ipk(os.path.join(ipk_dir, ipk_name), [
            ("debian-binary", b"2.0\n"),
            ("data.tar.gz", dbuf.getvalue()),
            ("control.tar.gz", cbuf.getvalue()),
        ])

    return {
        "package": pkg,
        "version": meta["version"],
        "arch": meta["arch"],
        "section": meta["section"],
        "files": meta["counts"]["file"],
        "symlinks": meta["counts"]["link"],
        "missing": meta["counts"]["missing"],
        "ipk": ipk_name,
        "depends": meta["depends"],
        "description": meta["description"],
    }


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("解包目录扫描 → IPK 自动打包工具")
        self.geometry("1020x740")
        self.minsize(900, 640)

        self.info_dir = None
        self.rootfs = None
        self.metas = []                 # scan_one 结果
        self.selected = {}              # pkg -> bool
        self.row_items = {}             # pkg -> tree item id
        self.q = queue.Queue()
        self.scan_token = 0
        self.cancel_event = threading.Event()
        self.worker = None

        self._build_ui()
        self.after(120, self._poll_queue)

        # 启动时自动发现脚本目录下的解包 rootfs
        auto = self._autodetect()
        if auto:
            self.src_var.set(auto)
            self.after(200, self.start_scan)

    # ---------------- UI 布局 ----------------

    def _build_ui(self):
        pad = {"padx": 8, "pady": 3}
        font = ("Microsoft YaHei UI", 9)
        self.option_add("*Font", font)
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass

        # 1. 源目录
        frm1 = ttk.LabelFrame(self, text=" 1. 解包目录 (选择 *_unpack 目录、system_rootfs 或其上级均可) ")
        frm1.pack(fill="x", **pad)
        self.src_var = tk.StringVar()
        ttk.Entry(frm1, textvariable=self.src_var).pack(
            side="left", fill="x", expand=True, padx=6, pady=6)
        ttk.Button(frm1, text="浏览…", command=self.browse_src).pack(side="left", padx=4)
        ttk.Button(frm1, text="扫描", command=self.start_scan).pack(side="left", padx=(0, 8))

        # 2. 输出目录与选项
        frm2 = ttk.LabelFrame(self, text=" 2. 输出设置 ")
        frm2.pack(fill="x", **pad)
        self.out_var = tk.StringVar()
        ttk.Label(frm2, text="输出目录:").pack(side="left", padx=(8, 4), pady=6)
        ttk.Entry(frm2, textvariable=self.out_var, width=52).pack(side="left", fill="x", expand=True)
        ttk.Button(frm2, text="浏览…", command=self.browse_out).pack(side="left", padx=4)
        self.opt_ipk = tk.BooleanVar(value=True)
        self.opt_dirs = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm2, text="生成 .ipk", variable=self.opt_ipk).pack(side="left", padx=6)
        ttk.Checkbutton(frm2, text="生成归类目录 packages/", variable=self.opt_dirs).pack(side="left", padx=6)

        # 3. 包列表 + 过滤
        frm3 = ttk.LabelFrame(self, text=" 3. 选择要打包的插件 ")
        frm3.pack(fill="both", expand=True, **pad)

        bar = ttk.Frame(frm3)
        bar.pack(fill="x", padx=6, pady=(6, 2))
        ttk.Button(bar, text="全选", width=6, command=lambda: self.select_all(True)).pack(side="left")
        ttk.Button(bar, text="全不选", width=6, command=lambda: self.select_all(False)).pack(side="left", padx=4)
        ttk.Button(bar, text="反选", width=6, command=self.invert_sel).pack(side="left")
        ttk.Label(bar, text="搜索:").pack(side="left", padx=(14, 2))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self.refresh_tree())
        ttk.Entry(bar, textvariable=self.search_var, width=24).pack(side="left")
        self.missing_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="仅显示有缺失的包", variable=self.missing_only,
                        command=self.refresh_tree).pack(side="left", padx=10)
        self.stat_var = tk.StringVar(value="尚未扫描")
        ttk.Label(bar, textvariable=self.stat_var, foreground="#0a6").pack(side="right")

        cols = ("sel", "package", "version", "arch", "section", "files", "links", "missing")
        tree_wrap = ttk.Frame(frm3)
        tree_wrap.pack(fill="both", expand=True, padx=6, pady=4)
        self.tree = ttk.Treeview(tree_wrap, columns=cols, show="headings", selectmode="browse")
        heads = {
            "sel": ("", 44), "package": ("包名 Package", 220), "version": ("版本", 180),
            "arch": ("架构", 110), "section": ("分类", 90), "files": ("文件", 56),
            "links": ("符号链接", 70), "missing": ("缺失", 56),
        }
        for c in cols:
            text, w = heads[c]
            self.tree.heading(c, text=text)
            anchor = "center" if c in ("sel", "files", "links", "missing") else "w"
            self.tree.column(c, width=w, anchor=anchor, stretch=(c == "package"))
        self.tree.tag_configure("missing", foreground="#c33")
        self.tree.tag_configure("odd", background="#f6f8fa")
        vsb = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<Button-1>", self.on_tree_click)
        self.tree.bind("<Double-1>", self.on_tree_double)
        self.tree.bind("<space>", lambda e: self.toggle_focused())

        # 4. 进度与日志
        frm4 = ttk.LabelFrame(self, text=" 4. 进度 / 日志 ")
        frm4.pack(fill="both", **pad)
        self.prog = ttk.Progressbar(frm4, maximum=100)
        self.prog.pack(fill="x", padx=8, pady=(6, 2))
        self.prog_var = tk.StringVar(value="就绪")
        ttk.Label(frm4, textvariable=self.prog_var).pack(anchor="w", padx=8)

        log_wrap = ttk.Frame(frm4)
        log_wrap.pack(fill="both", expand=True, padx=6, pady=4)
        self.log = tk.Text(log_wrap, height=8, wrap="word", state="disabled",
                           background="#1e1e1e", foreground="#d4d4d4", insertbackground="#fff",
                           font=("Consolas", 9))
        lsb = ttk.Scrollbar(log_wrap, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=lsb.set)
        self.log.pack(side="left", fill="both", expand=True)
        lsb.pack(side="right", fill="y")

        # 5. 底部按钮
        bottom = ttk.Frame(self)
        bottom.pack(fill="x", padx=10, pady=(0, 10))
        self.start_btn = ttk.Button(bottom, text="开始打包", command=self.toggle_worker)
        self.start_btn.pack(side="left")
        self.open_btn = ttk.Button(bottom, text="打开输出目录", command=self.open_out, state="disabled")
        self.open_btn.pack(side="left", padx=8)
        self.report_btn = ttk.Button(bottom, text="查看缺失报告", command=self.open_report, state="disabled")
        self.report_btn.pack(side="left")
        ttk.Label(bottom, text="提示: 单击勾选框选择包, 双击行查看 control 与文件清单",
                  foreground="#888").pack(side="right")

    # ---------------- 目录选择与自动发现 ----------------

    def _autodetect(self):
        here = os.getcwd()
        info, rootfs = find_info_dir(here)
        if info:
            # 自动定位时输出目录默认放到解包根
            unpack = os.path.dirname(rootfs)
            self.out_var.set(os.path.join(unpack, "ipk_repack_gui"))
            return rootfs
        return None

    def browse_src(self):
        d = filedialog.askdirectory(title="选择解包目录 / system_rootfs")
        if d:
            self.src_var.set(d)
            self.start_scan()

    def browse_out(self):
        d = filedialog.askdirectory(title="选择输出目录")
        if d:
            self.out_var.set(d)

    # ---------------- 扫描 ----------------

    def start_scan(self):
        base = self.src_var.get().strip()
        info, rootfs = find_info_dir(base)
        self.scan_token += 1
        token = self.scan_token
        if not info:
            self.info_dir = self.rootfs = None
            self.metas = []
            self.selected = {}
            self.refresh_tree()
            self.stat_var.set("未找到 usr/lib/opkg/info")
            messagebox.showerror("扫描失败",
                                 "在所选目录下未找到 usr/lib/opkg/info。\n\n"
                                 "请选择解包后的 *_unpack 目录、system_rootfs, 或它们的上级目录。")
            return
        self.info_dir, self.rootfs = info, rootfs
        if not self.out_var.get().strip():
            self.out_var.set(os.path.join(os.path.dirname(rootfs), "ipk_repack_gui"))
        self.stat_var.set("扫描中…")
        self.prog_var.set("正在扫描 %s …" % info)
        self.append_log("扫描: %s" % rootfs)
        threading.Thread(target=self._scan_worker, args=(info, token), daemon=True).start()

    def _scan_worker(self, info_dir, token):
        try:
            stems = sorted(
                os.path.basename(p)[:-len(".control")]
                for p in glob.glob(os.path.join(info_dir, "*.control")))
            metas = []
            for i, stem in enumerate(stems, 1):
                if token != self.scan_token:
                    return
                metas.append(scan_one(info_dir, stem))
                self.q.put(("scan_prog", i, len(stems)))
            self.q.put(("scan_done", metas, token))
        except Exception:
            self.q.put(("error", traceback.format_exc()))

    # ---------------- Tree ----------------

    def refresh_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.row_items = {}
        kw = self.search_var.get().strip().lower()
        only_missing = self.missing_only.get()
        shown = 0
        for i, m in enumerate(self.metas):
            if kw and kw not in m["package"].lower() and kw not in m["section"].lower():
                continue
            if only_missing and m["counts"]["missing"] == 0:
                continue
            tags = ["odd"] if shown % 2 else []
            if m["counts"]["missing"]:
                tags.append("missing")
            mark = "☑" if self.selected.get(m["package"], False) else "☐"
            item = self.tree.insert(
                "", "end",
                values=(mark, m["package"], m["version"], m["arch"], m["section"],
                        m["counts"]["file"], m["counts"]["link"], m["counts"]["missing"]),
                tags=tuple(tags))
            self.row_items[m["package"]] = item
            shown += 1
        self._update_stat()

    def _update_stat(self):
        total = len(self.metas)
        sel = sum(1 for v in self.selected.values() if v)
        miss_pkgs = sum(1 for m in self.metas if m["counts"]["missing"])
        miss_files = sum(m["counts"]["missing"] for m in self.metas)
        self.stat_var.set("共 %d 个包 | 已选 %d | %d 个包存在缺失(共 %d 项)"
                          % (total, sel, miss_pkgs, miss_files))

    def select_all(self, value):
        for m in self.metas:
            self.selected[m["package"]] = value
        self.refresh_tree()

    def invert_sel(self):
        for m in self.metas:
            self.selected[m["package"]] = not self.selected.get(m["package"], False)
        self.refresh_tree()

    def on_tree_click(self, event):
        if self.tree.identify_column(event.x) == "#1":
            item = self.tree.identify_row(event.y)
            if item:
                pkg = self.tree.item(item, "values")[1]
                self.selected[pkg] = not self.selected.get(pkg, False)
                vals = list(self.tree.item(item, "values"))
                vals[0] = "☑" if self.selected[pkg] else "☐"
                self.tree.item(item, values=vals)
                self._update_stat()

    def toggle_focused(self):
        item = self.tree.focus()
        if item:
            pkg = self.tree.item(item, "values")[1]
            self.selected[pkg] = not self.selected.get(pkg, False)
            vals = list(self.tree.item(item, "values"))
            vals[0] = "☑" if self.selected[pkg] else "☐"
            self.tree.item(item, values=vals)
            self._update_stat()

    def on_tree_double(self, _event):
        item = self.tree.focus()
        if not item:
            return
        pkg = self.tree.item(item, "values")[1]
        meta = next((m for m in self.metas if m["package"] == pkg), None)
        if meta:
            DetailWindow(self, meta)

    # ---------------- 打包 ----------------

    def toggle_worker(self):
        if self.worker and self.worker.is_alive():
            self.cancel_event.set()
            self.start_btn.configure(text="正在停止…", state="disabled")
            self.append_log("收到停止请求, 将在当前包完成后退出…")
            return
        chosen = [m for m in self.metas if self.selected.get(m["package"])]
        if not chosen:
            messagebox.showwarning("未选择包", "请先勾选至少一个插件。")
            return
        if not (self.opt_ipk.get() or self.opt_dirs.get()):
            messagebox.showwarning("未选择输出内容", "请至少勾选 “生成 .ipk” 或 “生成归类目录”。")
            return
        out = self.out_var.get().strip()
        if not out:
            messagebox.showwarning("未设置输出目录", "请先选择输出目录。")
            return
        os.makedirs(out, exist_ok=True)
        self.cancel_event.clear()
        self.start_btn.configure(text="停止")
        self.prog.configure(maximum=len(chosen), value=0)
        self.append_log("-" * 60)
        self.append_log("开始打包 %d 个包 -> %s" % (len(chosen), out))
        self.worker = threading.Thread(
            target=self._build_worker,
            args=(chosen, out, self.opt_ipk.get(), self.opt_dirs.get()),
            daemon=True)
        self.worker.start()

    def _build_worker(self, chosen, out_dir, do_ipk, do_dirs):
        rows = []
        try:
            for i, meta in enumerate(chosen, 1):
                if self.cancel_event.is_set():
                    self.q.put(("canceled", i - 1, len(chosen)))
                    return
                self.q.put(("prog", i, len(chosen), meta["package"]))
                row = build_one(meta, self.info_dir, self.rootfs, out_dir, do_ipk, do_dirs,
                                self.append_log)
                rows.append(row)

            # manifest + report
            if rows:
                with open(os.path.join(out_dir, "_manifest.csv"), "w", encoding="utf-8",
                          newline="") as f:
                    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                    w.writeheader()
                    w.writerows(rows)
                with open(os.path.join(out_dir, "_report.txt"), "w", encoding="utf-8") as f:
                    f.write("rootfs: %s\n" % self.rootfs)
                    f.write("built packages: %d\n\n" % len(rows))
                    total_miss = sum(r["missing"] for r in rows)
                    f.write("total missing entries: %d\n\n" % total_miss)
                    for m in chosen:
                        miss = [r for r, k in m["entries"] if k == "missing"]
                        if miss:
                            f.write("== %s (%d missing) ==\n" % (m["package"], len(miss)))
                            for r in miss:
                                f.write("  " + r + "\n")
            self.q.put(("done", len(chosen), out_dir))
        except Exception:
            self.q.put(("error", traceback.format_exc()))

    # ---------------- 队列/日志/收尾 ----------------

    def append_log(self, text):
        self.q.put(("log", text))

    def _poll_queue(self):
        try:
            while True:
                kind, *args = self.q.get_nowait()
                if kind == "log":
                    self.log.configure(state="normal")
                    self.log.insert("end", args[0] + "\n")
                    self.log.see("end")
                    self.log.configure(state="disabled")
                elif kind == "scan_prog":
                    i, n = args
                    self.prog_var.set("扫描中… %d/%d" % (i, n))
                elif kind == "scan_done":
                    metas, token = args
                    if token == self.scan_token:
                        self._after_scan(metas)
                elif kind == "prog":
                    i, n, pkg = args
                    self.prog.configure(value=i)
                    self.prog_var.set("打包中 %d/%d : %s" % (i, n, pkg))
                elif kind == "done":
                    n, out_dir = args
                    self._after_build(True, n, out_dir)
                elif kind == "canceled":
                    done, n = args
                    self._after_build(False, done, self.out_var.get().strip(), canceled=True)
                elif kind == "error":
                    tb = args[0]
                    self.append_log("[错误]\n" + tb)
                    messagebox.showerror("发生错误", tb[-800:])
                    self.start_btn.configure(text="开始打包", state="normal")
        except queue.Empty:
            pass
        self.after(120, self._poll_queue)

    def _after_scan(self, metas):
        self.metas = metas
        # 新扫描结果默认全选
        self.selected = {m["package"]: True for m in metas}
        self.refresh_tree()
        miss_files = sum(m["counts"]["missing"] for m in metas)
        self.prog_var.set("扫描完成: %d 个包, 缺失条目 %d 项(多为未编入 rootfs 的 .ko/固件)"
                          % (len(metas), miss_files))
        self.append_log("扫描完成: %d 个包, 缺失 %d 项" % (len(metas), miss_files))

    def _after_build(self, ok, n, out_dir, canceled=False):
        self.start_btn.configure(text="开始打包", state="normal")
        self.open_btn.configure(state="normal")
        self.report_btn.configure(state="normal")
        if canceled:
            self.prog_var.set("已停止, 完成 %d 个包" % n)
            self.append_log("已停止。完成 %d 个包, 输出目录: %s" % (n, out_dir))
        else:
            self.prog_var.set("完成: 共打包 %d 个包" % n)
            self.append_log("全部完成: %d 个包 -> %s" % (n, out_dir))
            messagebox.showinfo("完成", "已打包 %d 个插件。\n输出目录:\n%s" % (n, out_dir))

    def open_out(self):
        d = self.out_var.get().strip()
        if d and os.path.isdir(d):
            os.startfile(d)
        else:
            messagebox.showinfo("提示", "输出目录尚不存在, 请先打包。")

    def open_report(self):
        p = os.path.join(self.out_var.get().strip(), "_report.txt")
        if os.path.isfile(p):
            os.startfile(p)
        else:
            messagebox.showinfo("提示", "报告尚未生成, 请先打包。")


# ---------------------------------------------------------------------------
# 包详情窗口
# ---------------------------------------------------------------------------

class DetailWindow(tk.Toplevel):
    def __init__(self, master, meta):
        super().__init__(master)
        self.title("包详情 - %s %s" % (meta["package"], meta["version"]))
        self.geometry("720x600")
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        # control 信息
        p1 = ttk.Frame(nb)
        nb.add(p1, text="control / 信息")
        t1 = tk.Text(p1, wrap="word", font=("Consolas", 10))
        t1.pack(fill="both", expand=True, padx=6, pady=6)
        info = (
            "Package: %s\nVersion: %s\nArchitecture: %s\nSection: %s\n"
            "Depends: %s\nInstalled-Size: %s\n\nDescription:\n%s\n\n"
            "统计: 文件 %d | 目录 %d | 符号链接 %d | 缺失 %d\n"
            % (meta["package"], meta["version"], meta["arch"], meta["section"],
               meta["depends"] or "-", meta["installed_size"] or "-",
               meta["description"],
               meta["counts"]["file"], meta["counts"]["dir"],
               meta["counts"]["link"], meta["counts"]["missing"]))
        t1.insert("1.0", info)
        t1.insert("end", "\nconffiles:\n")
        t1.insert("end", ("\n".join("  " + c for c in meta["conffiles"]) or "  (无)") + "\n")
        t1.configure(state="disabled")

        # 文件清单
        p2 = ttk.Frame(nb)
        nb.add(p2, text="文件清单 (%d)" % len(meta["entries"]))
        tw = ttk.Treeview(p2, columns=("path", "status"), show="headings")
        tw.heading("path", text="rootfs 内路径")
        tw.heading("status", text="状态")
        tw.column("path", width=520)
        tw.column("status", width=120, anchor="center")
        tw.tag_configure("missing", foreground="#c33")
        tw.tag_configure("link", foreground="#06c")
        sb = ttk.Scrollbar(p2, orient="vertical", command=tw.yview)
        tw.configure(yscrollcommand=sb.set)
        tw.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=6)
        sb.pack(side="right", fill="y", pady=6)
        label = {"file": "文件", "dir": "目录", "link": "符号链接", "missing": "缺失"}
        for rel, k in meta["entries"]:
            tw.insert("", "end", values=(rel, label[k]), tags=(k,) if k in ("missing", "link") else ())
        self.transient(master)
        self.grab_set()


if __name__ == "__main__":
    App().mainloop()
