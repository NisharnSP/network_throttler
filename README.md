# Poor Network Simulator

A **GUI application** for simulating poor or difficult network conditions on
**Linux**, aimed at **robotics and teleoperation**. Degrade an outbound link with
realistic latency, jitter, loss, corruption and reordering so you can configure a
robot and its front-end (TCP vs UDP vs RTP) and see how the stream will be received.

## How it works

The tool uses Linux `tc` with **HTB** (rate limiting) and **netem** (delay, jitter,
loss, corruption, reorder) to shape **egress** traffic.

Because shaping happens *below* the transport layer:

* **TCP** sees the constrained path and reacts — it backs off and retransmits.
* **UDP / RTP** just receive the raw loss/delay/jitter/reorder, so you can exercise
  jitter buffers, FEC, keyframe requests and decoder resilience.

It is **one-way**: it degrades what *leaves* this machine. Run it on the sender to
preview what the receiver gets — e.g. run it on the robot to emulate the operator's
view of the video uplink.

By default it shapes **all egress** on the chosen interface. Set a **Target IP** to
shape only traffic to that host (e.g. the robot/operator), leaving your own SSH,
control plane and internet on that interface at full speed.

## Network conditions

* **Upload bandwidth** — 50 kbit/s to 1 Gbit/s (logarithmic slider)
* **Latency** and **Jitter** (ms), with a selectable jitter **distribution**
  (`paretonormal` best matches real networks) and **correlation**
* **Packet loss** — random (Bernoulli) or **bursty** (Gilbert-Elliott), which is
  realistic for cellular/WiFi
* **Packet corruption** — flips a bit; reaches UDP/RTP, dropped by TCP
* **Packet reordering**

Presets (`Slow 3G`, `Fast 3G`, `Patchy 4G`, `Bad WiFi`, `Slow DSL`, `Cable`, …) are
tuned to real-world behaviour rather than netem's worst-case defaults. The netem
queue is sized from the bandwidth-delay product, so congestion produces realistic
tail-drop instead of unbounded buffering.

## Requirements

* **Linux** (uses `tc` — iproute2)
* **Python 3** with **tkinter**
* **Root/sudo** (modifies system network settings)

## Usage

```bash
sudo python3 simulate_poor_upload.py
```

1. Pick the network interface (the default route is auto-detected).
2. Optionally enter a **Target IP** to shape only traffic to that host.
3. Choose a preset or adjust the sliders — changes apply in real time.
4. Click **Stop Throttling**, **Reset**, or close the window to restore the link.

Rules are removed on exit (including Ctrl-C / `SIGTERM`), and any qdisc left behind
by a crashed run is cleared when you next select that interface.

## Warnings

* **Requires root** — this modifies live system network settings.
* **Affects real traffic** — without a Target IP it shapes the *whole* interface,
  including the session you are connected over. Prefer a Target IP, or run it on an
  interface that does not carry your own session.
* **Linux only** — uses Linux-specific traffic control.
