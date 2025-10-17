#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import subprocess
import os
import sys
import atexit
import signal
import math

# Bandwidth slider range (in Mbit/s)
BANDWIDTH_MIN = 0.05
BANDWIDTH_MAX = 500


class PasswordDialog(simpledialog.Dialog):
    """Custom password dialog."""

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
    """Request sudo privileges with GUI password prompt."""
    # Check if already running as root
    if os.geteuid() == 0:
        return True

    # Create a temporary root window for the password dialog
    temp_root = tk.Tk()
    temp_root.withdraw()

    # Show password dialog
    dialog = PasswordDialog(temp_root, "Authentication Required")
    password = dialog.password

    if not password:
        temp_root.destroy()
        return False

    # Try to re-execute with sudo
    try:
        # Prepare the command to run this script with sudo
        cmd = ["sudo", "-S"] + [sys.executable] + sys.argv

        # Execute with password
        process = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Send password
        stdout, stderr = process.communicate(input=password + "\n", timeout=2)

        if process.returncode == 0:
            # Process completed successfully (shouldn't happen for GUI)
            temp_root.destroy()
            sys.exit(0)
        else:
            # Failed authentication
            if "incorrect password" in stderr.lower() or "sorry" in stderr.lower():
                messagebox.showerror("Authentication Failed", "Incorrect password. Please try again.", parent=temp_root)
            else:
                messagebox.showerror("Error", f"Failed to gain privileges:\n{stderr}", parent=temp_root)
            temp_root.destroy()
            return False

    except subprocess.TimeoutExpired:
        # Timeout means the new process is likely still running (success!)
        # Check if it's actually running
        if process.poll() is None:
            # Still running - success!
            temp_root.destroy()
            sys.exit(0)
        # If it died, fall through to exception handler

    except Exception as e:
        messagebox.showerror("Error", f"Failed to request privileges:\n{e}", parent=temp_root)
        temp_root.destroy()
        return False


class NetworkThrottleGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Throttle Control")
        self.root.geometry("650x600")

        # Check if running with sudo
        if os.geteuid() != 0:
            messagebox.showerror(
                "Error",
                "Failed to obtain administrative privileges.\n\n" "Please run with: sudo python3 network_throttle.py",
            )
            sys.exit(1)

        self.current_ip = None
        self.current_interface = None
        self.tc_applied = False
        self.apply_timer = None  # For debouncing slider changes
        self.auto_apply = False  # Enable after IP is configured

        # Register cleanup handlers
        atexit.register(self.cleanup)
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        self.create_widgets()

    def slider_to_bandwidth(self, slider_val):
        """Convert linear slider value (0-100) to logarithmic bandwidth."""
        log_min = math.log(BANDWIDTH_MIN)
        log_max = math.log(BANDWIDTH_MAX)
        log_bw = log_min + (log_max - log_min) * (slider_val / 100)
        return math.exp(log_bw)

    def bandwidth_to_slider(self, bandwidth):
        """Convert bandwidth to linear slider value (0-100)."""
        log_min = math.log(BANDWIDTH_MIN)
        log_max = math.log(BANDWIDTH_MAX)
        log_bw = math.log(max(BANDWIDTH_MIN, min(BANDWIDTH_MAX, bandwidth)))
        return 100 * (log_bw - log_min) / (log_max - log_min)

    def create_widgets(self):
        # Title
        title_label = ttk.Label(self.root, text="Network Traffic Control", font=("", 16, "bold"))
        title_label.pack(pady=10)

        # IP Configuration Frame
        ip_frame = ttk.LabelFrame(self.root, text="Target Configuration", padding="10")
        ip_frame.pack(fill="x", padx=10, pady=5)

        ip_container = ttk.Frame(ip_frame)
        ip_container.pack(fill="x")

        ttk.Label(ip_container, text="Target IP:").pack(side="left", padx=5)
        self.ip_entry = ttk.Entry(ip_container, width=20)
        self.ip_entry.pack(side="left", padx=5)
        self.ip_entry.insert(0, "10.0.3.2")

        # Bind Enter key to apply IP
        self.ip_entry.bind("<Return>", lambda e: self.apply_ip())

        ttk.Button(ip_container, text="Apply IP", command=self.apply_ip).pack(side="left", padx=5)

        self.status_label = ttk.Label(
            ip_frame, text="Status: Not configured - Click 'Apply IP' to start", foreground="red", font=("", 9, "bold")
        )
        self.status_label.pack(pady=5)

        # Real-time indicator
        self.realtime_label = ttk.Label(
            ip_frame, text="⚡ Real-time mode: Settings apply automatically", foreground="blue", font=("", 8, "italic")
        )
        # Will pack after IP is applied

        # Network Parameters Frame
        params_frame = ttk.LabelFrame(self.root, text="Network Parameters", padding="10")
        params_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Delay/Latency
        self.create_slider(params_frame, 0, "Latency (ms):", 0, 5000, 0, "delay_var", "delay_label", " ms")

        # Jitter
        self.create_slider(params_frame, 1, "Jitter (ms):", 0, 500, 0, "jitter_var", "jitter_label", " ms")

        # Packet Loss
        self.create_slider(
            params_frame, 2, "Packet Loss (%):", 0, 100, 0, "loss_var", "loss_label", " %", resolution=0.1
        )

        # Bandwidth (logarithmic slider, 0-100 maps to 0.05-500 Mbit/s)
        self.create_slider(
            params_frame, 3, "Bandwidth Limit (Mbit/s):", 0, 100, 100, "bandwidth_var", "bandwidth_label", " Mbit/s"
        )

        # Duplicate packets
        self.create_slider(
            params_frame,
            4,
            "Duplicate Packets (%):",
            0,
            100,
            0,
            "duplicate_var",
            "duplicate_label",
            " %",
            resolution=0.1,
        )

        # Corrupt packets
        self.create_slider(
            params_frame, 5, "Corrupt Packets (%):", 0, 100, 0, "corrupt_var", "corrupt_label", " %", resolution=0.1
        )

        # Reorder packets
        self.create_slider(
            params_frame, 6, "Reorder Packets (%):", 0, 100, 0, "reorder_var", "reorder_label", " %", resolution=0.1
        )

        params_frame.columnconfigure(1, weight=1)

        # Control Buttons Frame
        button_frame = ttk.Frame(self.root, padding="10")
        button_frame.pack(fill="x", padx=10, pady=5)

        reset_btn = ttk.Button(button_frame, text="Reset All", command=self.reset_all)
        reset_btn.pack(side="left", padx=5)

        remove_btn = ttk.Button(button_frame, text="Remove Throttling", command=self.cleanup)
        remove_btn.pack(side="left", padx=5)

        # Info label
        info_label = ttk.Label(
            self.root,
            text="Note: Changes apply in real-time to outgoing traffic to the target IP. Requires root privileges.",
            font=("", 8),
            foreground="gray",
            wraplength=600,
        )
        info_label.pack(pady=5)

    def create_slider(self, parent, row, label_text, from_, to, default, var_name, label_name, unit, resolution=1):
        """Helper method to create a slider with label."""
        ttk.Label(parent, text=label_text).grid(row=row, column=0, sticky="w", padx=5, pady=5)

        if resolution == 1:
            var = tk.IntVar(value=default)
        else:
            var = tk.DoubleVar(value=default)

        setattr(self, var_name, var)

        scale = ttk.Scale(parent, from_=from_, to=to, variable=var, orient="horizontal", command=self.on_param_change)
        scale.grid(row=row, column=1, sticky="ew", padx=5, pady=5)

        if resolution == 1:
            label_text = f"{int(default)}{unit}"
        else:
            label_text = f"{default:.1f}{unit}"

        label = ttk.Label(parent, text=label_text, width=12)
        label.grid(row=row, column=2, padx=5, pady=5)
        setattr(self, label_name, label)

    def get_interface_for_ip(self, ip):
        """Get the network interface used to reach the target IP."""
        try:
            result = subprocess.run(["ip", "route", "get", ip], capture_output=True, text=True, check=True)
            # Parse output: "10.0.3.2 dev lxcbr0 src 10.0.3.1 uid 0"
            parts = result.stdout.split()
            for i, part in enumerate(parts):
                if part == "dev" and i + 1 < len(parts):
                    return parts[i + 1]
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get interface for IP {ip}:\n{e}")
        return None

    def run_command(self, cmd, show_errors=True):
        """Run a shell command and return success status."""
        try:
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            return True
        except subprocess.CalledProcessError as e:
            if show_errors:
                print(f"Command failed: {cmd}")
                print(f"Error: {e.stderr}")
            return False

    def cleanup(self):
        """Remove all tc rules."""
        if self.current_interface and self.tc_applied:
            print(f"Cleaning up tc rules on {self.current_interface}...")
            # Silently try to remove (don't show errors if nothing exists)
            self.run_command(f"tc qdisc del dev {self.current_interface} root 2>/dev/null", show_errors=False)
            self.tc_applied = False
            if hasattr(self, "status_label"):
                status_text = "Status: Throttling removed"
                if self.auto_apply and self.current_ip:
                    status_text += f" (configured for {self.current_ip})"
                self.status_label.config(text=status_text, foreground="blue")
            print("Cleanup complete")

    def signal_handler(self, signum, frame):
        """Handle termination signals."""
        print("\nReceived signal, cleaning up...")
        self.cleanup()
        sys.exit(0)

    def apply_ip(self):
        """Apply the new IP address configuration."""
        new_ip = self.ip_entry.get().strip()
        if not new_ip:
            messagebox.showerror("Error", "Please enter a valid IP address")
            return

        # If IP changed, cleanup old rules
        if self.current_ip != new_ip:
            self.cleanup()

        # Get interface for the new IP
        interface = self.get_interface_for_ip(new_ip)
        if not interface:
            return

        self.current_ip = new_ip
        self.current_interface = interface
        self.auto_apply = True  # Enable real-time updates

        # Show real-time indicator
        self.realtime_label.pack(pady=2)

        self.status_label.config(text=f"Status: Ready - {new_ip} on {interface}", foreground="green")

        messagebox.showinfo(
            "Success",
            f"Target configured:\n{new_ip} via {interface}\n\nReal-time mode enabled!\nAdjust sliders to apply throttling.",
        )

        # Apply current settings immediately if any are non-default
        if self.has_non_default_settings():
            self.apply_settings_internal()

    def has_non_default_settings(self):
        """Check if any settings are different from defaults."""
        bandwidth = self.slider_to_bandwidth(self.bandwidth_var.get())
        return (
            int(self.delay_var.get()) != 0
            or int(self.jitter_var.get()) != 0
            or self.loss_var.get() != 0
            or abs(bandwidth - BANDWIDTH_MAX) > 0.01
            or self.duplicate_var.get() != 0
            or self.corrupt_var.get() != 0
            or self.reorder_var.get() != 0
        )

    def on_param_change(self, event=None):
        """Update labels when sliders change and trigger auto-apply."""
        # Update labels
        self.delay_label.config(text=f"{int(self.delay_var.get())} ms")
        self.jitter_label.config(text=f"{int(self.jitter_var.get())} ms")
        self.loss_label.config(text=f"{self.loss_var.get():.1f} %")

        # Bandwidth label with logarithmic conversion
        bandwidth = self.slider_to_bandwidth(self.bandwidth_var.get())
        if bandwidth >= 1:
            self.bandwidth_label.config(text=f"{bandwidth:.1f} Mbit/s")
        else:
            self.bandwidth_label.config(text=f"{bandwidth:.2f} Mbit/s")

        self.duplicate_label.config(text=f"{self.duplicate_var.get():.1f} %")
        self.corrupt_label.config(text=f"{self.corrupt_var.get():.1f} %")
        self.reorder_label.config(text=f"{self.reorder_var.get():.1f} %")

        # Auto-apply with debouncing if enabled
        if self.auto_apply:
            # Cancel pending timer if exists
            if self.apply_timer:
                self.root.after_cancel(self.apply_timer)

            # Set new timer to apply after 300ms of no changes
            self.apply_timer = self.root.after(300, self.apply_settings_auto)

    def apply_settings_auto(self):
        """Apply settings automatically (called by timer)."""
        self.apply_timer = None
        if not self.auto_apply:
            return

        # Show applying indicator
        old_text = self.status_label.cget("text")
        self.status_label.config(text="Status: Applying changes...", foreground="orange")
        self.root.update_idletasks()

        # Apply settings
        success = self.apply_settings_internal()

        # Restore status
        if success:
            self.status_label.config(
                text=f"Status: Active - {self.current_ip} on {self.current_interface}", foreground="green"
            )
        else:
            self.status_label.config(text=old_text, foreground="red")

    def apply_settings_internal(self):
        """Apply the current network throttling settings (internal method)."""
        if not self.current_interface or not self.current_ip:
            return False

        # Get current values
        delay = int(self.delay_var.get())
        jitter = int(self.jitter_var.get())
        loss = self.loss_var.get()
        bandwidth = self.slider_to_bandwidth(self.bandwidth_var.get())
        duplicate = self.duplicate_var.get()
        corrupt = self.corrupt_var.get()
        reorder = self.reorder_var.get()

        interface = self.current_interface
        ip = self.current_ip

        # ALWAYS delete existing qdisc first (unconditionally)
        # This ensures we start with a clean slate every time
        print(f"Cleaning existing tc rules on {interface}...")
        self.run_command(f"tc qdisc del dev {interface} root 2>/dev/null", show_errors=False)
        self.tc_applied = False

        # Small delay to ensure kernel processes the deletion
        import time

        time.sleep(0.1)

        # Check if all settings are at default
        if not self.has_non_default_settings():
            print("All settings at default - no throttling applied")
            return True

        print(f"Applying traffic control to {ip} on {interface}...")

        # Add root qdisc with HTB (default changed to 2 to match classid 1:2)
        if not self.run_command(f"tc qdisc add dev {interface} root handle 1: htb default 2"):
            return False

        # Throttled class (for target IP)
        if not self.run_command(
            f"tc class add dev {interface} parent 1: classid 1:1 htb " f"rate {bandwidth}mbit ceil {bandwidth}mbit"
        ):
            self.cleanup()
            return False

        # Default class (for all other traffic)
        if not self.run_command(f"tc class add dev {interface} parent 1: classid 1:2 htb " f"rate 10gbit ceil 10gbit"):
            self.cleanup()
            return False

        netem_params = []

        if delay > 0:
            if jitter > 0:
                netem_params.append(f"delay {delay}ms {jitter}ms")
            else:
                netem_params.append(f"delay {delay}ms")

        if loss > 0:
            netem_params.append(f"loss {loss}%")

        if duplicate > 0:
            netem_params.append(f"duplicate {duplicate}%")

        if corrupt > 0:
            netem_params.append(f"corrupt {corrupt}%")

        if reorder > 0:
            # Reorder needs delay to work
            if delay == 0:
                netem_params.append(f"delay 10ms reorder {reorder}% 50%")
            else:
                netem_params.append(f"reorder {reorder}% 50%")

        # Add netem qdisc to throttled class if any parameters are set
        if netem_params:
            netem_cmd = f"tc qdisc add dev {interface} parent 1:1 handle 10: " f"netem {' '.join(netem_params)}"
            if not self.run_command(netem_cmd):
                self.cleanup()
                return False
        else:
            # Even if no netem params, add a pfifo_fast qdisc
            if not self.run_command(f"tc qdisc add dev {interface} parent 1:1 handle 10: pfifo_fast"):
                self.cleanup()
                return False

        # Add pfifo_fast to default class
        if not self.run_command(f"tc qdisc add dev {interface} parent 1:2 handle 20: pfifo_fast"):
            self.cleanup()
            return False

        # Add filter to direct traffic to target IP to throttled class
        filter_cmd = f"tc filter add dev {interface} protocol ip parent 1:0 prio 1 " f"u32 match ip dst {ip} flowid 1:1"
        if not self.run_command(filter_cmd):
            self.cleanup()
            return False

        self.tc_applied = True
        print("Traffic control applied successfully")
        return True

    def reset_all(self):
        """Reset all parameters to default values."""
        self.delay_var.set(0)
        self.jitter_var.set(0)
        self.loss_var.set(0)
        self.bandwidth_var.set(BANDWIDTH_MAX)
        self.duplicate_var.set(0)
        self.corrupt_var.set(0)
        self.reorder_var.set(0)
        self.on_param_change()

        if not self.auto_apply:
            self.cleanup()

        messagebox.showinfo("Reset", "All parameters reset to default values")


def main():
    if os.geteuid() != 0:
        if not request_sudo_privileges():
            sys.exit(1)

    root = tk.Tk()
    app = NetworkThrottleGUI(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.cleanup(), root.destroy()))

    try:
        root.mainloop()
    except KeyboardInterrupt:
        app.cleanup()
        sys.exit(0)


if __name__ == "__main__":
    main()
