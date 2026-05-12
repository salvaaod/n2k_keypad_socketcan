from __future__ import annotations

import select
import socket
import struct
import subprocess
import time
from errno import ENOBUFS
import tkinter as tk
from tkinter import messagebox, ttk

GLOBAL_DESTINATION = 0xFF
PGN_ISO_REQUEST = 59904
PGN_ADDRESS_CLAIM = 60928
PGN_HEARTBEAT = 126993
PGN_PRODUCT_INFO = 126996
PGN_BINARY_SWITCH_BANK_STATUS = 127501

SWITCH_COUNT = 6
PGN_BINARY_SWITCH_BANK_CONTROL = 127502
DEFAULT_SWITCH_SOURCE_ADDRESS = 88
DEFAULT_SWITCH_BANK_INSTANCE = 1
DEFAULT_SWITCH_UNIQUE_NUMBER = 123456
DEFAULT_SWITCH_DEVICE_INSTANCE_LOWER = 2
DEFAULT_SWITCH_DEVICE_INSTANCE_UPPER = 0
DEFAULT_SWITCH_DEVICE_FUNCTION = 140
DEFAULT_SWITCH_DEVICE_CLASS = 30
DEFAULT_SWITCH_SYSTEM_INSTANCE = 0
DEFAULT_SWITCH_INDUSTRY_GROUP = 4
DEFAULT_MANUFACTURER_CODE = 176
DEFAULT_PRODUCT_NAME = "Azimut Switch"
DEFAULT_APPLICATION_VERSION = "0.1"
DEFAULT_NMEA2000_VERSION = 2100
DEFAULT_MODEL_VERSION = "SW1"
DEFAULT_PRODUCT_CODE = 1
DEFAULT_PRODUCT_ID = "AZ_SW"
HEARTBEAT_INTERVAL_MS = 1_000
RECEIVE_POLL_INTERVAL_MS = 50
FEEDBACK_LATCH_TIMEOUT_MS = 200
DEFAULT_CAN_INTERFACE = "can0"
DEFAULT_CAN_BITRATE = 250000
CAN_EFF_FLAG = 0x80000000
CAN_EFF_MASK = 0x1FFFFFFF



def build_address_claim(device_name: int) -> bytes:
    return int(device_name & 0xFFFFFFFFFFFFFFFF).to_bytes(8, byteorder="little", signed=False)


def build_heartbeat_payload(interval_ms: int, sequence: int) -> bytes:
    # PGN 126993 Heartbeat: two-byte transmission interval in 0.01 second units,
    # sequence counter, then controller/equipment state bits left unavailable.
    interval = max(0, min(0xFFFF, int(round(interval_ms / 10))))
    return interval.to_bytes(2, byteorder="little", signed=False) + bytes((sequence & 0xFF,)) + bytes((0xFF,) * 5)


def nmea2000_id(priority: int, pgn: int, source: int, destination: int = GLOBAL_DESTINATION) -> int:
    priority_bits = (priority & 0x07) << 26
    source_bits = source & 0xFF
    pf = (pgn >> 8) & 0xFF
    if pf < 240:
        # PDU1 PGNs use the PS byte as destination, with the PGN low byte cleared.
        return priority_bits | ((pgn & 0x3FF00) << 8) | ((destination & 0xFF) << 8) | source_bits
    # PDU2 PGNs include the group extension in the PGN and are always broadcast.
    return priority_bits | ((pgn & 0x3FFFF) << 8) | source_bits


def build_iso_name(
    unique_number: int,
    manufacturer_code: int,
    device_instance_lower: int = DEFAULT_SWITCH_DEVICE_INSTANCE_LOWER,
    device_instance_upper: int = DEFAULT_SWITCH_DEVICE_INSTANCE_UPPER,
    device_function: int = DEFAULT_SWITCH_DEVICE_FUNCTION,
    device_class: int = DEFAULT_SWITCH_DEVICE_CLASS,
    system_instance: int = DEFAULT_SWITCH_SYSTEM_INSTANCE,
    industry_group: int = DEFAULT_SWITCH_INDUSTRY_GROUP,
) -> int:
    value = 0
    value |= int(unique_number) & 0x1FFFFF
    value |= (int(manufacturer_code) & 0x7FF) << 21
    value |= (int(device_instance_lower) & 0x07) << 32
    value |= (int(device_instance_upper) & 0x1F) << 35
    value |= (int(device_function) & 0xFF) << 40
    value |= 0 << 48
    value |= (int(device_class) & 0x7F) << 49
    value |= (int(system_instance) & 0x0F) << 56
    value |= (int(industry_group) & 0x07) << 60
    value |= 1 << 63
    return value


def set_name_manufacturer_code(device_name: int, manufacturer_code: int) -> int:
    # NMEA 2000 NAME bits 21-31 hold the 11-bit manufacturer code.
    manufacturer_mask = 0x7FF << 21
    return (device_name & ~manufacturer_mask) | ((manufacturer_code & 0x7FF) << 21)


def split_fast_packet(payload: bytes, sequence: int) -> list[bytes]:
    sequence_id = (sequence & 0x07) << 5
    payload_length = len(payload)
    frames = [bytes((sequence_id, payload_length & 0xFF)) + payload[:6]]
    remaining = payload[6:]
    frame_number = 1
    while remaining:
        frames.append(bytes((sequence_id | (frame_number & 0x1F),)) + remaining[:7])
        remaining = remaining[7:]
        frame_number += 1
    return frames


def _ascii_field(value: str, length: int = 32) -> bytes:
    raw = value.encode("ascii", errors="ignore")[: length - 1]
    return raw + b"\x00" + (b"\xFF" * (length - len(raw) - 1))


def build_switch_product_info_payload(
    product_name: str,
    application_version: str,
    nmea2000_version: int,
    model_version: str,
    product_code: int,
    product_id: str,
) -> bytes:
    # PGN 126996 Product Information layout:
    # NMEA 2000 version, product code, model ID, software version,
    # model version, model serial code, certification level, load equivalency.
    n2k_version = int(max(0, min(0xFFFF, nmea2000_version))).to_bytes(2, byteorder="little", signed=False)
    product_code_bytes = int(max(0, min(0xFFFF, product_code))).to_bytes(2, byteorder="little", signed=False)
    return (
        n2k_version
        + product_code_bytes
        + _ascii_field(product_name)
        + _ascii_field(application_version)
        + _ascii_field(model_version)
        + _ascii_field(product_id)
        + bytes((1, 1))
    )


def build_binary_switch_bank_control(bank_instance: int, switch_number: int, state_on: bool) -> bytes:
    # PGN 127502 Binary Switch Bank Control uses 2-bit switch fields.
    # Command only the changed switch; all other switch fields are marked as no-command/unavailable.
    switch_commands = [3] * 28
    switch_index = max(1, min(SWITCH_COUNT, switch_number)) - 1
    switch_commands[switch_index] = 1 if state_on else 0
    packed_states = bytearray((0x00,) * 7)
    for index, value in enumerate(switch_commands):
        bit_pos = index * 2
        packed_states[bit_pos // 8] |= (value & 0x03) << (bit_pos % 8)
    return bytes((bank_instance & 0xFF,)) + bytes(packed_states)


def pgn_from_nmea2000_id(frame_id: int) -> int:
    pf = (frame_id >> 16) & 0xFF
    ps = (frame_id >> 8) & 0xFF
    data_page = (frame_id >> 24) & 0x01
    if pf < 240:
        return (data_page << 16) | (pf << 8)
    return (data_page << 16) | (pf << 8) | ps


def source_from_nmea2000_id(frame_id: int) -> int:
    return frame_id & 0xFF


def destination_from_nmea2000_id(frame_id: int) -> int:
    pf = (frame_id >> 16) & 0xFF
    if pf < 240:
        return (frame_id >> 8) & 0xFF
    return GLOBAL_DESTINATION


def requested_pgn_from_iso_request(data: bytes) -> int | None:
    if len(data) < 3:
        return None
    return data[0] | (data[1] << 8) | (data[2] << 16)


class SocketCANDevice:
    """Small SocketCAN transport with interface setup/teardown helpers."""

    _CAN_FRAME = struct.Struct("=IB3x8s")

    def __init__(self, interface_name: str = DEFAULT_CAN_INTERFACE, bitrate: int = DEFAULT_CAN_BITRATE) -> None:
        self.interface_name = interface_name
        self.bitrate = bitrate
        self.socket: socket.socket | None = None

    @staticmethod
    def _run_cmd(cmd: list[str], check: bool = True) -> None:
        result = subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if check and result.returncode != 0:
            error = result.stderr.strip() or f"exit status {result.returncode}"
            raise RuntimeError(f"Command {' '.join(cmd)!r} failed: {error}")

    def _configure_interface(self) -> None:
        # Reset + set bitrate then bring the SocketCAN network interface up.
        # This prevents send failures such as "Network is down" when can0 exists
        # but has not been configured by the OS yet.
        self._run_cmd(["ip", "link", "set", self.interface_name, "down"], check=False)
        self._run_cmd(
            ["ip", "link", "set", self.interface_name, "type", "can", "bitrate", str(self.bitrate)],
            check=False,
        )
        self._run_cmd(["ip", "link", "set", self.interface_name, "up"], check=True)

    def open(self) -> None:
        self.close(set_down=False)
        self._configure_interface()
        can_socket = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        can_socket.bind((self.interface_name,))
        can_socket.setblocking(False)
        self.socket = can_socket

    def close(self, set_down: bool = True) -> None:
        if self.socket is not None:
            self.socket.close()
            self.socket = None
        if set_down:
            self._run_cmd(["ip", "link", "set", self.interface_name, "down"], check=False)

    def send(self, frame_id: int, data: bytes) -> None:
        if self.socket is None:
            raise RuntimeError("SocketCAN device is not open.")
        payload = bytes(data[:8])
        can_id = (frame_id & CAN_EFF_MASK) | CAN_EFF_FLAG
        frame = self._CAN_FRAME.pack(can_id, len(payload), payload.ljust(8, b"\x00"))
        while True:
            try:
                self.socket.send(frame)
                return
            except OSError as exc:
                if exc.errno != ENOBUFS and "No buffer space available" not in str(exc):
                    raise
                # With no ACKing peer on the bus, SocketCAN can report ENOBUFS.
                # Keep retrying until the bus becomes ready again.
                time.sleep(0.05)

    def receive(self, max_frames: int = 50, wait_time_ms: int = 0) -> list[tuple[int, bytes]]:
        if self.socket is None:
            return []
        timeout = max(0, wait_time_ms) / 1000
        frames: list[tuple[int, bytes]] = []
        while len(frames) < max_frames:
            readable, _, _ = select.select([self.socket], [], [], timeout if not frames else 0)
            if not readable:
                break
            try:
                packet = self.socket.recv(self._CAN_FRAME.size)
            except BlockingIOError:
                break
            can_id, data_length, data = self._CAN_FRAME.unpack(packet)
            frames.append((can_id & CAN_EFF_MASK, data[:data_length]))
        return frames


def decode_binary_switch_bank_status(data: bytes, switch_count: int = SWITCH_COUNT) -> tuple[int, list[int]] | None:
    if len(data) < 8:
        return None
    bank_instance = data[0]
    packed = data[1:8]
    states: list[int] = []
    for index in range(min(28, switch_count)):
        bit_pos = index * 2
        states.append((packed[bit_pos // 8] >> (bit_pos % 8)) & 0x03)
    return bank_instance, states


class BinarySwitchSimulatorApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Azimut NMEA2000 Switch Simulator")
        self._enter_fullscreen()
        self.root.bind("<F11>", self._toggle_fullscreen)
        self.root.bind("<Escape>", self._exit_fullscreen)
        self.device: SocketCANDevice | None = None
        self.receive_job: str | None = None
        self.heartbeat_job: str | None = None
        self.is_connected = False
        self.fast_packet_sequence = 0
        self.heartbeat_sequence = 0
        self.switch_states = [False] * SWITCH_COUNT
        self.switch_status_values = [0] * SWITCH_COUNT
        self.pending_switch_targets: list[int | None] = [None] * SWITCH_COUNT
        self.pending_feedback_jobs: list[str | None] = [None] * SWITCH_COUNT
        self.switch_buttons: list[tk.Button] = []
        self.source_address = tk.StringVar(value=str(DEFAULT_SWITCH_SOURCE_ADDRESS))
        self.bank_instance = tk.StringVar(value=str(DEFAULT_SWITCH_BANK_INSTANCE))
        self.manufacturer_code = tk.StringVar(value=str(DEFAULT_MANUFACTURER_CODE))
        self.product_name = tk.StringVar(value=DEFAULT_PRODUCT_NAME)
        self.application_version = tk.StringVar(value=DEFAULT_APPLICATION_VERSION)
        self.nmea2000_version = tk.StringVar(value=str(DEFAULT_NMEA2000_VERSION))
        self.model_version = tk.StringVar(value=DEFAULT_MODEL_VERSION)
        self.product_code = tk.StringVar(value=str(DEFAULT_PRODUCT_CODE))
        self.product_id = tk.StringVar(value=DEFAULT_PRODUCT_ID)
        self._build_ui()
        self.root.after(100, self.connect)

    def _enter_fullscreen(self, _event: tk.Event | None = None) -> None:
        self.root.attributes("-fullscreen", True)

    def _exit_fullscreen(self, _event: tk.Event | None = None) -> None:
        self.root.attributes("-fullscreen", False)

    def _toggle_fullscreen(self, _event: tk.Event | None = None) -> None:
        self.root.attributes("-fullscreen", not bool(self.root.attributes("-fullscreen")))

    def _build_ui(self) -> None:
        self._build_menu()
        main = ttk.Frame(self.root, padding=12)
        main.grid(sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        for column in range(3):
            main.columnconfigure(column, weight=1, uniform="switch_columns")
        for row in range(2):
            main.rowconfigure(row, weight=1, uniform="switch_rows")

        self.status_text = tk.StringVar(value="")

        for index in range(SWITCH_COUNT):
            button = tk.Button(
                main,
                text=f"SW {index + 1}\nOFF",
                width=18,
                height=3,
                command=lambda switch_no=index + 1: self.on_switch_click(switch_no),
                bg="#d9d9d9",
                activebackground="#c8c8c8",
                relief="raised",
                font=("TkDefaultFont", 28, "bold"),
            )
            button.grid(row=index // 3, column=index % 3, padx=8, pady=8, sticky="nsew")
            self.switch_buttons.append(button)
        self._refresh_switch_button_labels()

    def _build_menu(self) -> None:
        menu_bar = tk.Menu(self.root)
        settings_menu = tk.Menu(menu_bar, tearoff=False)
        settings_menu.add_command(label="Node settings...", command=self.open_settings_dialog)
        settings_menu.add_separator()
        settings_menu.add_command(label="Retry connection", command=self.connect)
        settings_menu.add_separator()
        settings_menu.add_command(label="Toggle full screen", command=self._toggle_fullscreen)
        menu_bar.add_cascade(label="Settings", menu=settings_menu)
        self.root.config(menu=menu_bar)

    def open_settings_dialog(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Node settings")
        dialog.transient(self.root)
        dialog.resizable(False, False)
        frame = ttk.Frame(dialog, padding=10)
        frame.grid(sticky="nsew")

        self._add_setting_field(frame, 0, "CAN source address", self.source_address)
        self._add_setting_field(frame, 1, "Bank instance", self.bank_instance)
        self._add_setting_field(frame, 2, "Manufacturer code", self.manufacturer_code)

        ttk.Separator(frame).grid(row=3, column=0, columnspan=2, sticky="ew", pady=(8, 6))
        self._add_setting_field(frame, 4, "Product name", self.product_name)
        self._add_setting_field(frame, 5, "Application version", self.application_version)
        self._add_setting_field(frame, 6, "NMEA 2000 version", self.nmea2000_version)
        self._add_setting_field(frame, 7, "Model version", self.model_version)
        self._add_setting_field(frame, 8, "Product code", self.product_code)
        self._add_setting_field(frame, 9, "Product ID", self.product_id)
        ttk.Label(frame, text="Settings affect subsequent frames; reconnect if hardware identity changes are required.").grid(
            row=10, column=0, columnspan=2, sticky="w", pady=(8, 0)
        )
        ttk.Button(frame, text="Close", command=dialog.destroy).grid(row=11, column=0, columnspan=2, pady=(10, 0))

    def _add_setting_field(self, parent: ttk.Frame, row: int, label: str, variable: tk.StringVar) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=2)
        ttk.Entry(parent, textvariable=variable, width=16).grid(row=row, column=1, sticky="ew", pady=2)

    def _as_int(self, value: str, default: int = 0) -> int:
        try:
            text = value.strip()
            if text.lower().startswith("0x"):
                return int(text, 16)
            return int(float(text))
        except ValueError:
            return default

    def _source_address(self) -> int:
        return max(0, min(251, self._as_int(self.source_address.get(), DEFAULT_SWITCH_SOURCE_ADDRESS)))

    def _device_name(self) -> int:
        manufacturer = self._as_int(self.manufacturer_code.get(), DEFAULT_MANUFACTURER_CODE)
        return build_iso_name(DEFAULT_SWITCH_UNIQUE_NUMBER, manufacturer)

    def _bank_instance(self) -> int:
        return max(0, min(255, self._as_int(self.bank_instance.get(), DEFAULT_SWITCH_BANK_INSTANCE)))

    def _refresh_switch_button_labels(self) -> None:
        state_styles = {
            0: ("OFF", "#d9d9d9", "#c8c8c8"),
            1: ("ON", "#2fb344", "#27963a"),
            2: ("ERROR", "#f0ad4e", "#d99632"),
            3: ("N/A", "#bfbfbf", "#a8a8a8"),
        }
        for index, button in enumerate(self.switch_buttons, start=1):
            state_text, background, active_background = state_styles.get(self.switch_status_values[index - 1], state_styles[3])
            button.configure(
                text=f"SW {index}\n{state_text}",
                bg=background,
                activebackground=active_background,
                fg="white" if self.switch_status_values[index - 1] == 1 else "black",
                activeforeground="white" if self.switch_status_values[index - 1] == 1 else "black",
            )

    def _send_switch_command(self, switch_number: int, state_on: bool) -> None:
        if not self.device:
            return
        payload = build_binary_switch_bank_control(self._bank_instance(), switch_number, state_on)
        frame_id = nmea2000_id(3, PGN_BINARY_SWITCH_BANK_CONTROL, self._source_address(), GLOBAL_DESTINATION)
        self.device.send(frame_id, payload)

    def on_switch_click(self, switch_number: int) -> None:
        switch_index = max(1, min(SWITCH_COUNT, switch_number)) - 1
        current_status = self.switch_status_values[switch_index]
        target_status = 0 if current_status == 1 else 1
        self.pending_switch_targets[switch_index] = target_status
        self._send_switch_command(switch_number, target_status == 1)
        self._schedule_feedback_timeout(switch_index)

    def _schedule_feedback_timeout(self, switch_index: int) -> None:
        existing_job = self.pending_feedback_jobs[switch_index]
        if existing_job is not None:
            self.root.after_cancel(existing_job)
        self.pending_feedback_jobs[switch_index] = self.root.after(
            FEEDBACK_LATCH_TIMEOUT_MS,
            lambda index=switch_index: self._clear_pending_feedback(index),
        )

    def _clear_pending_feedback(self, switch_index: int) -> None:
        self.pending_feedback_jobs[switch_index] = None
        self.pending_switch_targets[switch_index] = None
        self._refresh_switch_button_labels()

    def connect(self) -> None:
        if self.is_connected:
            return
        try:
            self.device = SocketCANDevice(DEFAULT_CAN_INTERFACE, DEFAULT_CAN_BITRATE)
            self.device.open()
            self.is_connected = True
            self.status_text.set("")
            self._schedule_receive()
            self._announce_startup_identity()
            self._schedule_heartbeat()
        except Exception as exc:
            self.device = None
            self.is_connected = False
            self.status_text.set("")
            messagebox.showerror(
                "Connection error",
                f"Could not open SocketCAN interface {DEFAULT_CAN_INTERFACE} @ {DEFAULT_CAN_BITRATE} bps: {exc}",
            )

    def disconnect(self) -> None:
        self._stop_receive()
        self._stop_heartbeat()
        self._clear_all_pending_feedback()
        if self.device:
            try:
                self.device.close()
            except Exception:
                pass
        self.device = None
        self.is_connected = False
        self.status_text.set("")

    def _announce_startup_identity(self) -> None:
        if not self.device or not self.is_connected:
            return
        # Standard NMEA 2000 startup behavior: claim this source address and start heartbeat.
        # Product Information is sent when another node requests PGN 126996 via ISO Request.
        self._send_address_claim()
        self._send_heartbeat()

    def _send_address_claim(self) -> None:
        if not self.device:
            return
        frame_id = nmea2000_id(6, PGN_ADDRESS_CLAIM, self._source_address(), GLOBAL_DESTINATION)
        self.device.send(frame_id, build_address_claim(self._device_name()))

    def _send_product_info(self) -> None:
        if not self.device:
            return
        payload = build_switch_product_info_payload(
            self.product_name.get(),
            self.application_version.get(),
            self._as_int(self.nmea2000_version.get(), DEFAULT_NMEA2000_VERSION),
            self.model_version.get(),
            self._as_int(self.product_code.get(), DEFAULT_PRODUCT_CODE),
            self.product_id.get(),
        )
        frame_id = nmea2000_id(6, PGN_PRODUCT_INFO, self._source_address(), GLOBAL_DESTINATION)
        frames = split_fast_packet(payload, self.fast_packet_sequence)
        self.fast_packet_sequence = (self.fast_packet_sequence + 1) & 0x07
        for frame in frames:
            self.device.send(frame_id, frame.ljust(8, b"\xFF"))


    def _send_heartbeat(self) -> None:
        if not self.device:
            return
        frame_id = nmea2000_id(7, PGN_HEARTBEAT, self._source_address(), GLOBAL_DESTINATION)
        payload = build_heartbeat_payload(HEARTBEAT_INTERVAL_MS, self.heartbeat_sequence)
        self.heartbeat_sequence = (self.heartbeat_sequence + 1) & 0xFF
        self.device.send(frame_id, payload)

    def _schedule_heartbeat(self) -> None:
        if self.heartbeat_job is None:
            self.heartbeat_job = self.root.after(HEARTBEAT_INTERVAL_MS, self._send_heartbeat_and_reschedule)

    def _send_heartbeat_and_reschedule(self) -> None:
        self.heartbeat_job = None
        if self.device and self.is_connected:
            self._send_heartbeat()
            self._schedule_heartbeat()

    def _stop_heartbeat(self) -> None:
        if self.heartbeat_job is not None:
            self.root.after_cancel(self.heartbeat_job)
            self.heartbeat_job = None

    def _clear_all_pending_feedback(self) -> None:
        for index, job in enumerate(self.pending_feedback_jobs):
            if job is not None:
                self.root.after_cancel(job)
                self.pending_feedback_jobs[index] = None
            self.pending_switch_targets[index] = None

    def _schedule_receive(self) -> None:
        if self.receive_job is None:
            self.receive_job = self.root.after(RECEIVE_POLL_INTERVAL_MS, self._receive_and_reschedule)

    def _stop_receive(self) -> None:
        if self.receive_job is not None:
            self.root.after_cancel(self.receive_job)
            self.receive_job = None

    def _receive_and_reschedule(self) -> None:
        self.receive_job = None
        if self.device and self.is_connected:
            self._receive_protocol_messages()
            self.receive_job = self.root.after(RECEIVE_POLL_INTERVAL_MS, self._receive_and_reschedule)

    def _receive_protocol_messages(self) -> None:
        if not self.device:
            return
        for frame_id, data in self.device.receive(max_frames=50, wait_time_ms=0):
            pgn = pgn_from_nmea2000_id(frame_id)
            if pgn == PGN_BINARY_SWITCH_BANK_STATUS:
                self._apply_binary_switch_status(data)
            elif pgn == PGN_ADDRESS_CLAIM:
                self._handle_address_claim(frame_id, data)
            elif pgn == PGN_ISO_REQUEST:
                self._handle_iso_request(frame_id, data)

    def _handle_address_claim(self, frame_id: int, data: bytes) -> None:
        # Simplified address-conflict handling: if another node claims our source address,
        # re-send our address claim so the bus sees this simulated node's NAME again.
        if source_from_nmea2000_id(frame_id) == self._source_address() and data != build_address_claim(self._device_name()):
            self._send_address_claim()

    def _handle_iso_request(self, frame_id: int, data: bytes) -> None:
        destination = destination_from_nmea2000_id(frame_id)
        if destination not in (GLOBAL_DESTINATION, self._source_address()):
            return
        requested_pgn = requested_pgn_from_iso_request(data)
        if requested_pgn == PGN_ADDRESS_CLAIM:
            self._send_address_claim()
        elif requested_pgn == PGN_PRODUCT_INFO:
            self._send_product_info()

    def _apply_binary_switch_status(self, data: bytes) -> None:
        decoded = decode_binary_switch_bank_status(data, SWITCH_COUNT)
        if decoded is None:
            return
        bank_instance, states = decoded
        if bank_instance != self._bank_instance():
            return
        changed = False
        for index, status in enumerate(states):
            if status != self.switch_status_values[index]:
                self.switch_status_values[index] = status
                changed = True
            if status in (0, 1):
                self.switch_states[index] = status == 1
                if self.pending_switch_targets[index] == status:
                    job = self.pending_feedback_jobs[index]
                    if job is not None:
                        self.root.after_cancel(job)
                        self.pending_feedback_jobs[index] = None
                    self.pending_switch_targets[index] = None
                    changed = True
        if changed:
            self._refresh_switch_button_labels()


def main() -> None:
    root = tk.Tk()
    BinarySwitchSimulatorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
