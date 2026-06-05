#!/usr/bin/env python3
"""Simulate poor upload conditions on a real outbound interface.

Shapes EGRESS traffic on the chosen interface to emulate sub-optimal
internet (low bandwidth, latency, jitter, packet loss, reordering). Use
this to see how outbound traffic — like a WebRTC video stream — behaves
when the upstream link is bad.

Defaults are tuned for *realistic* network behaviour:
  - jitter uses correlation + paretonormal/normal distribution
    (uncorrelated uniform jitter creates pathological reordering that
    doesn't exist on real networks and wrecks WebRTC's GCC)
  - bursty loss option uses Gilbert-Elliott (real loss isn't independent)
  - HTB burst is sized for the link (not artificially generous at low rates)
  - netem queue is sized from the bandwidth-delay product, so congestion
    produces realistic tail-drop instead of seconds of bufferbloat

By default this shapes ALL egress on the chosen interface; set a Target IP to
shape only traffic to that host (e.g. a robot) so your own session stays intact.
Shaping sits below the transport, so TCP backs off and retransmits while UDP/RTP
just see the raw loss/delay/jitter/reorder. It is one-way: run it on the sender
to preview what the receiver gets.
"""

import atexit
import ipaddress
import math
import os
import signal
import subprocess
import sys
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

BANDWIDTH_MIN = 0.05   # 50 kbit/s
BANDWIDTH_MAX = 1000   # 1 Gbit/s

DISTRIBUTIONS = ("normal", "paretonormal", "pareto", "uniform")

# Presets tuned to match real-world conditions, not netem's worst-case defaults.
# bursty=True uses Gilbert-Elliott (more realistic for cellular/WiFi).
PRESETS = {
    "Custom":            None,
    "Off (full speed)":  dict(bw=BANDWIDTH_MAX, delay=0,   jitter=0,  distribution="normal",        correlation=25, loss=0, bursty=False, reorder=0),
    "Slow 3G":           dict(bw=0.4,           delay=400, jitter=80, distribution="paretonormal",  correlation=50, loss=2, bursty=True,  reorder=0),
    "Fast 3G":           dict(bw=1.6,           delay=150, jitter=40, distribution="paretonormal",  correlation=50, loss=1, bursty=True,  reorder=0),
    "Patchy 4G":         dict(bw=5,             delay=80,  jitter=30, distribution="paretonormal",  correlation=50, loss=2, bursty=True,  reorder=0),
    "Bad WiFi":          dict(bw=10,            delay=30,  jitter=40, distribution="paretonormal",  correlation=30, loss=3, bursty=True,  reorder=0),
    "Slow DSL":          dict(bw=2,             delay=40,  jitter=8,  distribution="normal",        correlation=60, loss=0, bursty=False, reorder=0),
    "Cable":             dict(bw=20,            delay=20,  jitter=4,  distribution="normal",        correlation=70, loss=0, bursty=False, reorder=0),
}


class PasswordDialog(simpledialog.Dialog):
    def __init__(self, parent, title=None):
        self.password = None
        super().__init__(parent, title=title)

    def body(self, master):
        ttk.Label(master, text="This application requires administrative privileges.").grid(
            row=0, columnspan=2, pady=10, padx=10
        )
        ttk.Label(master, text="Please enter your password:", font=("", 10, "bold")).grid(
            row=1, columnspan=2, pady=5, padx=10
        )
        ttk.Label(master, text="Password:").grid(row=2, column=0, sticky="e", padx=5, pady=10)
        self.password_entry = ttk.Entry(master, show="*", width=30)
        self.password_entry.grid(row=2, column=1, padx=5, pady=10)
        return self.password_entry

    def apply(self):
        self.password = self.password_entry.get()


def request_sudo_privileges():
    if os.geteuid() == 0:
        return True

    temp_root = tk.Tk()
    temp_root.withdraw()

    dialog = PasswordDialog(temp_root, "Authentication Required")
    password = dialog.password
    if not password:
        temp_root.destroy()
        return False

    try:
        cmd = ["sudo", "-S"] + [sys.executable] + sys.argv
        process = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = process.communicate(input=password + "\n", timeout=2)
        if process.returncode == 0:
            temp_root.destroy()
            sys.exit(0)
        else:
            if "incorrect password" in stderr.lower() or "sorry" in stderr.lower():
                messagebox.showerror("Authentication Failed", "Incorrect password.", parent=temp_root)
            else:
                messagebox.showerror("Error", f"Failed to gain privileges:\n{stderr}", parent=temp_root)
            temp_root.destroy()
            return False
    except subprocess.TimeoutExpired:
        if process.poll() is None:
            temp_root.destroy()
            sys.exit(0)
        temp_root.destroy()
        return False
    except Exception as e:
        messagebox.showerror("Error", f"Failed to request privileges:\n{e}", parent=temp_root)
        temp_root.destroy()
        return False


class UploadSimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("Poor Upload Simulator")
        self.root.geometry("720x860")

        if os.geteuid() != 0:
            messagebox.showerror(
                "Error",
                "Failed to obtain admin privileges.\n\nRun with: sudo python3 simulate_poor_upload.py",
            )
            sys.exit(1)

        self.interface = None
        self.iface_mtu = 1500
        self.tc_applied = False
        self.applied_target = None
        self.apply_timer = None
        self.suppress_callbacks = False

        atexit.register(self.cleanup)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        self.root.report_callback_exception = self._on_callback_exception

        self._build_ui()
        self._auto_detect_interface()
        self._pump()

    # ---------- UI ----------

    def _build_ui(self):
        ttk.Label(self.root, text="Poor Upload Simulator", font=("", 16, "bold")).pack(pady=8)

        info = ("Shapes EGRESS on the chosen interface (set a Target IP to spare your own\n"
                "session). One-way: run it on the sender to preview what the receiver gets.\n"
                "Defaults are realistic — uncorrelated uniform jitter wrecks WebRTC's GCC.")
        ttk.Label(self.root, text=info, font=("", 9), foreground="gray",
                  justify="center", wraplength=680).pack(pady=2)

        iface_frame = ttk.LabelFrame(self.root, text="Network Interface", padding=10)
        iface_frame.pack(fill="x", padx=10, pady=5)
        row = ttk.Frame(iface_frame)
        row.pack(fill="x")
        ttk.Label(row, text="Interface:").pack(side="left", padx=5)
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(row, textvariable=self.iface_var, state="readonly", width=22)
        self.iface_combo.pack(side="left", padx=5)
        self.iface_combo.bind("<<ComboboxSelected>>", lambda e: self._on_interface_change())
        ttk.Button(row, text="Refresh", command=self._refresh_interfaces).pack(side="left", padx=5)
        self.iface_status = ttk.Label(iface_frame, text="Detecting…", foreground="orange", font=("", 9))
        self.iface_status.pack(pady=4)

        target_row = ttk.Frame(iface_frame)
        target_row.pack(fill="x", pady=(2, 0))
        ttk.Label(target_row, text="Target IP:").pack(side="left", padx=5)
        self.target_var = tk.StringVar()
        target_entry = ttk.Entry(target_row, textvariable=self.target_var, width=24)
        target_entry.pack(side="left", padx=5)
        target_entry.bind("<Return>", self._on_target_change)
        target_entry.bind("<FocusOut>", self._on_target_change)
        ttk.Label(target_row, text="(blank = whole interface)", font=("", 8),
                  foreground="gray").pack(side="left", padx=5)

        preset_frame = ttk.Frame(self.root, padding=(10, 0))
        preset_frame.pack(fill="x", padx=10, pady=4)
        ttk.Label(preset_frame, text="Preset:").pack(side="left", padx=5)
        self.preset_var = tk.StringVar(value="Off (full speed)")
        preset_menu = ttk.Combobox(preset_frame, textvariable=self.preset_var,
                                   values=list(PRESETS.keys()), state="readonly", width=22)
        preset_menu.pack(side="left", padx=5)
        preset_menu.bind("<<ComboboxSelected>>", lambda e: self._apply_preset())

        params = ttk.LabelFrame(self.root, text="Network Conditions", padding=10)
        params.pack(fill="both", expand=True, padx=10, pady=8)

        self._make_slider(params, 0, "Upload bandwidth:", 0, 100, 100, "bw_var", "bw_label",
                          formatter=self._fmt_bandwidth)
        self._make_slider(params, 1, "Latency:", 0, 1000, 0, "delay_var", "delay_label",
                          formatter=lambda v: f"{int(v)} ms")
        self._make_slider(params, 2, "Jitter:", 0, 500, 0, "jitter_var", "jitter_label",
                          formatter=lambda v: f"{int(v)} ms")

        # Distribution dropdown — controls jitter SHAPE, not magnitude
        ttk.Label(params, text="Jitter distribution:").grid(row=3, column=0, sticky="w", padx=5, pady=4)
        self.distribution_var = tk.StringVar(value="normal")
        dist_combo = ttk.Combobox(params, textvariable=self.distribution_var,
                                  values=DISTRIBUTIONS, state="readonly", width=18)
        dist_combo.grid(row=3, column=1, sticky="w", padx=5, pady=4)
        dist_combo.bind("<<ComboboxSelected>>", lambda e: self._on_slider_change())
        ttk.Label(params, text="(paretonormal ≈ real net)", font=("", 8), foreground="gray").grid(
            row=3, column=2, sticky="w", padx=5)

        self._make_slider(params, 4, "Jitter correlation:", 0, 99, 25, "correlation_var", "correlation_label",
                          formatter=lambda v: f"{int(v)} %")

        self._make_slider(params, 5, "Packet loss:", 0, 50, 0, "loss_var", "loss_label",
                          resolution=0.1, formatter=lambda v: f"{v:.1f} %")

        # Bursty loss checkbox — switches Bernoulli to Gilbert-Elliott
        ttk.Label(params, text="Loss model:").grid(row=6, column=0, sticky="w", padx=5, pady=4)
        self.bursty_var = tk.BooleanVar(value=False)
        bursty_check = ttk.Checkbutton(params, text="Bursty (Gilbert-Elliott)",
                                       variable=self.bursty_var,
                                       command=self._on_slider_change)
        bursty_check.grid(row=6, column=1, sticky="w", padx=5, pady=4)
        ttk.Label(params, text="(realistic for cellular/WiFi)", font=("", 8), foreground="gray").grid(
            row=6, column=2, sticky="w", padx=5)

        self._make_slider(params, 7, "Corrupt:", 0, 50, 0, "corrupt_var", "corrupt_label",
                          resolution=0.1, formatter=lambda v: f"{v:.1f} %")

        self._make_slider(params, 8, "Reorder:", 0, 50, 0, "reorder_var", "reorder_label",
                          resolution=0.1, formatter=lambda v: f"{v:.1f} %")

        params.columnconfigure(1, weight=1)

        btn_frame = ttk.Frame(self.root, padding=10)
        btn_frame.pack(fill="x", padx=10)
        ttk.Button(btn_frame, text="Stop Throttling", command=self.cleanup).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Reset", command=self._reset).pack(side="left", padx=5)

        self.status_label = ttk.Label(self.root, text="Status: idle", foreground="blue",
                                      font=("", 9, "bold"), wraplength=680, justify="center")
        self.status_label.pack(pady=6)

        self.netem_label = ttk.Label(self.root, text="", foreground="gray",
                                     font=("Courier", 8), wraplength=680, justify="center")
        self.netem_label.pack(pady=2)

    def _make_slider(self, parent, row, label_text, lo, hi, default, var_name, label_attr,
                     resolution=1, formatter=None):
        ttk.Label(parent, text=label_text).grid(row=row, column=0, sticky="w", padx=5, pady=4)
        var = tk.DoubleVar(value=default) if resolution != 1 else tk.IntVar(value=default)
        setattr(self, var_name, var)
        scale = ttk.Scale(parent, from_=lo, to=hi, variable=var, orient="horizontal",
                          command=self._on_slider_change)
        scale.grid(row=row, column=1, sticky="ew", padx=5, pady=4)
        fmt = formatter or (lambda v: str(v))
        lbl = ttk.Label(parent, text=fmt(default), width=14)
        lbl.grid(row=row, column=2, padx=5, pady=4)
        setattr(self, label_attr, lbl)
        setattr(self, label_attr + "_fmt", fmt)

    # ---------- Slider math ----------

    def _slider_to_bandwidth(self, val):
        log_min = math.log(BANDWIDTH_MIN)
        log_max = math.log(BANDWIDTH_MAX)
        return math.exp(log_min + (log_max - log_min) * (val / 100))

    def _bandwidth_to_slider(self, bw):
        log_min = math.log(BANDWIDTH_MIN)
        log_max = math.log(BANDWIDTH_MAX)
        bw = max(BANDWIDTH_MIN, min(BANDWIDTH_MAX, bw))
        return 100 * (math.log(bw) - log_min) / (log_max - log_min)

    def _fmt_bandwidth(self, val):
        bw = self._slider_to_bandwidth(val)
        if bw >= 100:
            return f"{bw:.0f} Mbit/s"
        if bw >= 10:
            return f"{bw:.1f} Mbit/s"
        if bw >= 1:
            return f"{bw:.2f} Mbit/s"
        return f"{bw * 1000:.0f} kbit/s"

    def _on_slider_change(self, _event=None):
        self.bw_label.config(text=self.bw_label_fmt(self.bw_var.get()))
        self.delay_label.config(text=self.delay_label_fmt(self.delay_var.get()))
        self.jitter_label.config(text=self.jitter_label_fmt(self.jitter_var.get()))
        self.correlation_label.config(text=self.correlation_label_fmt(self.correlation_var.get()))
        self.loss_label.config(text=self.loss_label_fmt(self.loss_var.get()))
        self.corrupt_label.config(text=self.corrupt_label_fmt(self.corrupt_var.get()))
        self.reorder_label.config(text=self.reorder_label_fmt(self.reorder_var.get()))

        if self.suppress_callbacks:
            return
        if self.preset_var.get() != "Custom":
            self.preset_var.set("Custom")
        if self.interface:
            if self.apply_timer:
                self.root.after_cancel(self.apply_timer)
            self.apply_timer = self.root.after(250, self._apply_settings)

    def _apply_preset(self):
        cfg = PRESETS.get(self.preset_var.get())
        if cfg is None:
            return
        self.suppress_callbacks = True
        try:
            self.bw_var.set(self._bandwidth_to_slider(cfg["bw"]))
            self.delay_var.set(cfg["delay"])
            self.jitter_var.set(cfg["jitter"])
            self.distribution_var.set(cfg["distribution"])
            self.correlation_var.set(cfg["correlation"])
            self.loss_var.set(cfg["loss"])
            self.bursty_var.set(cfg["bursty"])
            self.corrupt_var.set(cfg.get("corrupt", 0))
            self.reorder_var.set(cfg["reorder"])
            self._on_slider_change()
        finally:
            self.suppress_callbacks = False
        if self.interface:
            self._apply_settings()

    def _reset(self):
        self.preset_var.set("Off (full speed)")
        self._apply_preset()

    def _on_target_change(self, _event=None):
        if self.interface:
            self._apply_settings()

    # ---------- Interface discovery ----------

    def _list_interfaces(self):
        try:
            r = subprocess.run(["ip", "-o", "link", "show"],
                               capture_output=True, text=True, check=True)
            ifaces = []
            for line in r.stdout.splitlines():
                parts = line.split(":", 2)
                if len(parts) < 2:
                    continue
                name = parts[1].strip().split("@")[0]
                if name == "lo":
                    continue
                ifaces.append(name)
            return ifaces
        except Exception:
            return []

    def _refresh_interfaces(self):
        ifaces = self._list_interfaces()
        self.iface_combo["values"] = ifaces
        if self.interface and self.interface in ifaces:
            self.iface_combo.set(self.interface)

    def _detect_default_route_iface(self):
        try:
            r = subprocess.run(["ip", "route", "get", "8.8.8.8"],
                               capture_output=True, text=True, check=True)
            parts = r.stdout.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
        except Exception:
            pass
        return None

    def _get_iface_mtu(self, iface):
        try:
            r = subprocess.run(["ip", "link", "show", iface],
                               capture_output=True, text=True, check=True)
            parts = r.stdout.split()
            if "mtu" in parts:
                return int(parts[parts.index("mtu") + 1])
        except Exception:
            pass
        return 1500

    def _auto_detect_interface(self):
        self._refresh_interfaces()
        default = self._detect_default_route_iface()
        if default and default != "lo":
            self.iface_combo.set(default)
            self._on_interface_change()
        elif self.iface_combo["values"]:
            self.iface_combo.current(0)
            self._on_interface_change()
        else:
            self.iface_status.config(text="No usable interfaces found.", foreground="red")

    def _on_interface_change(self):
        new_iface = self.iface_var.get()
        if not new_iface:
            return
        if new_iface == "lo":
            messagebox.showwarning(
                "Loopback not supported",
                "Throttling 'lo' breaks local services (DNS, IPC) and doesn't simulate "
                "real internet conditions. Pick a real interface.",
            )
            if self.interface:
                self.iface_combo.set(self.interface)
            return
        if self.tc_applied and self.interface and self.interface != new_iface:
            self.cleanup()
        self.interface = new_iface
        self.iface_mtu = self._get_iface_mtu(new_iface)
        if not self.tc_applied:
            # Clear any qdisc left behind by a previous run that crashed.
            self._run(f"tc qdisc del dev {new_iface} root 2>/dev/null", show_errors=False)
        self.iface_status.config(
            text=f"Selected: {new_iface}   |   MTU {self.iface_mtu}", foreground="green"
        )
        if self._has_non_default_settings():
            self._apply_settings()

    # ---------- TC application ----------

    def _has_non_default_settings(self):
        # Distribution / correlation / bursty alone don't trigger; they only
        # shape behaviour when combined with non-zero delay / loss.
        return (
            int(self.delay_var.get()) > 0
            or int(self.jitter_var.get()) > 0
            or self.loss_var.get() > 0
            or self.corrupt_var.get() > 0
            or self.reorder_var.get() > 0
            or abs(self._slider_to_bandwidth(self.bw_var.get()) - BANDWIDTH_MAX) > 0.01
        )

    def _build_burst(self, rate_mbit):
        # HTB needs burst >= one scheduler tick of data (and >= MTU). Size it to
        # ~4ms of traffic so the rate holds at high rates while clamping to the
        # MTU at low rates, where a generous burst would leak past the limit.
        rate_bytes_per_sec = rate_mbit * 1_000_000 / 8
        return max(self.iface_mtu, int(rate_bytes_per_sec / 250))

    def _build_netem_args(self, rate_mbit, delay, jitter, distribution, correlation,
                          loss, bursty, corrupt, reorder):
        """Build netem argument list for the given conditions.

        Reorder needs a non-zero delay base to take effect.
        Jitter is meaningless without a base delay >= jitter (otherwise
        netem clamps the negative-delay tail to zero, skewing the
        distribution). Auto-promote the base delay when needed.
        """
        effective_delay = delay
        if effective_delay < jitter:
            effective_delay = jitter        # keep delay range non-negative
        if effective_delay == 0 and reorder > 0:
            effective_delay = 10            # reorder requires a delay clause

        args = [f"limit {self._build_limit(rate_mbit, effective_delay + jitter)}"]

        if effective_delay > 0:
            if jitter > 0:
                args.append(f"delay {effective_delay}ms {jitter}ms {int(correlation)}%")
                # distribution applies to the delay clause; only meaningful with jitter
                if distribution and distribution != "uniform":
                    args.append(f"distribution {distribution}")
            else:
                args.append(f"delay {effective_delay}ms")

        if loss > 0:
            if bursty:
                # Gilbert-Elliott: p = G->B, r = B->G. With defaults
                # (1-h=100%, 1-k=0%) the steady-state loss = p/(p+r).
                # Pick r=30% to give mean burst length ~3-4 packets, then
                # solve for p so the average loss matches the slider.
                r_pct = 30.0
                p_pct = r_pct * loss / max(0.0001, (100.0 - loss))
                args.append(f"loss gemodel {p_pct:.4f}% {r_pct:.2f}%")
            else:
                args.append(f"loss {loss:.2f}%")

        if corrupt > 0:
            args.append(f"corrupt {corrupt:.2f}%")

        if reorder > 0:
            args.append(f"reorder {reorder:.2f}% 50%")

        return args

    def _build_limit(self, rate_mbit, window_ms):
        # netem holds the in-flight delay window plus a standing queue; a fixed
        # limit means seconds of bufferbloat at low rates and silently drops the
        # delay buffer at high rates, so size it from the bandwidth-delay product.
        pkts_per_sec = rate_mbit * 1_000_000 / 8 / self.iface_mtu
        return max(64, math.ceil(pkts_per_sec * (window_ms / 1000 + 0.3)))

    def _run(self, cmd, show_errors=True):
        try:
            subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            return True
        except subprocess.CalledProcessError as e:
            if show_errors:
                print(f"Command failed: {cmd}")
                print(f"Error: {e.stderr.strip()}")
            return False

    def _apply_settings(self):
        if not self.interface:
            return False

        target = self.target_var.get().strip()
        if target:
            try:
                ipaddress.ip_address(target)
            except ValueError:
                self._set_status(f"Invalid target IP: {target}", "red")
                return False

        bw = self._slider_to_bandwidth(self.bw_var.get())
        delay = int(self.delay_var.get())
        jitter = int(self.jitter_var.get())
        distribution = self.distribution_var.get()
        correlation = self.correlation_var.get()
        loss = self.loss_var.get()
        bursty = self.bursty_var.get()
        corrupt = self.corrupt_var.get()
        reorder = self.reorder_var.get()
        burst = self._build_burst(bw)
        netem_args = self._build_netem_args(bw, delay, jitter, distribution, correlation,
                                            loss, bursty, corrupt, reorder)
        iface = self.interface

        if not self._has_non_default_settings():
            self.cleanup()
            self.netem_label.config(text="")
            return True

        netem_tail = " ".join(netem_args)
        htb_class = (f"rate {bw:.4f}mbit ceil {bw:.4f}mbit "
                     f"mtu {self.iface_mtu} burst {burst} cburst {burst}")

        # Rebuild the tree on first apply or when the target changes; otherwise
        # mutate in place so live tuning never briefly unshapes the stream.
        if not self.tc_applied or self.applied_target != target:
            self._run(f"tc qdisc del dev {iface} root 2>/dev/null", show_errors=False)
            if not self._run(f"tc qdisc add dev {iface} root handle 1: htb "
                             f"default {'20' if target else '10'}"):
                self._set_status(f"Failed to add HTB on {iface} (already in use?)", "red")
                return False
            if not self._run(f"tc class add dev {iface} parent 1: classid 1:10 htb {htb_class}"):
                self._run(f"tc qdisc del dev {iface} root 2>/dev/null", show_errors=False)
                self._set_status("Failed to add HTB class", "red")
                return False
            if not self._run(f"tc qdisc add dev {iface} parent 1:10 handle 10: netem {netem_tail}"):
                self._run(f"tc qdisc del dev {iface} root 2>/dev/null", show_errors=False)
                self._set_status("Failed to add netem", "red")
                return False
            if target:
                # Unshaped class for everything except the target, so your own
                # session, control plane and internet on this interface stay fast.
                self._run(f"tc class add dev {iface} parent 1: classid 1:20 htb "
                          f"rate 10gbit ceil 10gbit")
                proto, match = ("ipv6", "ip6") if ":" in target else ("ip", "ip")
                if not self._run(f"tc filter add dev {iface} protocol {proto} parent 1: "
                                 f"prio 1 u32 match {match} dst {target} flowid 1:10"):
                    self._run(f"tc qdisc del dev {iface} root 2>/dev/null", show_errors=False)
                    self._set_status("Failed to add target filter", "red")
                    return False
            self.tc_applied = True
            self.applied_target = target
        else:
            if not self._run(f"tc class change dev {iface} classid 1:10 htb {htb_class}"):
                self._set_status("HTB class change failed", "red")
                return False
            if not self._run(f"tc qdisc replace dev {iface} parent 1:10 handle 10: netem {netem_tail}"):
                self._set_status("netem replace failed", "red")
                return False

        scope = f"dst {target}" if target else f"all egress on {iface}"
        loss_str = f"{loss:.1f}% {'bursty' if bursty else 'random'}" if loss > 0 else "0%"
        self._set_status(
            f"Active ({scope})  |  {self._fmt_bandwidth(self.bw_var.get())}, "
            f"latency {delay}±{jitter}ms ({distribution}, corr {int(correlation)}%), "
            f"loss {loss_str}, corrupt {corrupt:.1f}%, reorder {reorder:.1f}%",
            "green",
        )
        self.netem_label.config(text=f"netem args: {netem_tail}")
        return True

    def _set_status(self, text, colour="blue"):
        self.status_label.config(text=f"Status: {text}", foreground=colour)

    def cleanup(self):
        if self.tc_applied and self.interface:
            self._run(f"tc qdisc del dev {self.interface} root 2>/dev/null", show_errors=False)
            self.tc_applied = False
            self.applied_target = None
            try:
                self._set_status(f"Removed (was on {self.interface})", "blue")
                self.netem_label.config(text="")
            except tk.TclError:
                pass  # window already torn down; the qdisc is what matters

    def _pump(self):
        # Tk's mainloop blocks signal delivery; returning to Python periodically
        # lets SIGINT/SIGTERM reach _signal_handler so tc rules are torn down.
        self.root.after(200, self._pump)

    def _on_callback_exception(self, exc, value, tb):
        self.cleanup()
        sys.excepthook(exc, value, tb)

    def _signal_handler(self, signum, frame):
        self.cleanup()
        sys.exit(0)


def main():
    if os.geteuid() != 0:
        if not request_sudo_privileges():
            sys.exit(1)
    root = tk.Tk()
    app = UploadSimulator(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.cleanup(), root.destroy()))
    try:
        root.mainloop()
    except KeyboardInterrupt:
        app.cleanup()
        sys.exit(0)


if __name__ == "__main__":
    main()
