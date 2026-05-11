import os
import platform
import tkinter as tk
from tkinter import messagebox, ttk

from nmea2000_simulator import (
    DEFAULT_CAN_INDEX,
    DEFAULT_DEVICE_INDEX,
    DEFAULT_DEVICE_TYPE,
    DEFAULT_DLL_NAME,
    GLOBAL_DESTINATION,
    PGN_ADDRESS_CLAIM,
    PGN_BINARY_SWITCH_BANK_STATUS,
    PGN_HEARTBEAT,
    PGN_PRODUCT_INFO,
    TIMING0_250K,
    TIMING1_250K,
    DeviceConfig,
    USBCANDevice,
    build_address_claim,
    build_heartbeat_payload,
    nmea2000_id,
    set_name_manufacturer_code,
    split_fast_packet,
)

SWITCH_COUNT = 6
PGN_BINARY_SWITCH_BANK_CONTROL = 127502
DEFAULT_SWITCH_SOURCE_ADDRESS = 55
DEFAULT_SWITCH_BANK_INSTANCE = 1
DEFAULT_SWITCH_DEVICE_NAME = 0x1F2000AA12345678
DEFAULT_MANUFACTURER_CODE = 176
DEFAULT_PRODUCT_NAME = "Azimut Switch"
DEFAULT_APPLICATION_VERSION = "0.1"
DEFAULT_DATABASE_VERSION = 2000
DEFAULT_MODEL_VERSION = "SW1"
DEFAULT_PRODUCT_CODE = 1
DEFAULT_PRODUCT_ID = "AZ_SW"
ADDRESS_CLAIM_INTERVAL_MS = 30_000
HEARTBEAT_INTERVAL_MS = 1_000
RECEIVE_POLL_INTERVAL_MS = 50
FEEDBACK_LATCH_TIMEOUT_MS = 200


def _ascii_field(value: str, length: int = 32) -> bytes:
    return value[:length].ljust(length, "\x00").encode("ascii", errors="ignore")


def build_switch_product_info_payload(
    product_name: str,
    application_version: str,
    database_version: int,
    model_version: str,
    product_code: int,
    product_id: str,
) -> bytes:
    # PGN 126996 Product Information layout. Keep these fields in the secondary
    # settings menu so the main switch panel stays compact.
    database = int(max(0, min(0xFFFF, database_version))).to_bytes(2, byteorder="little", signed=False)
    product_code_bytes = int(max(0, min(0xFFFF, product_code))).to_bytes(2, byteorder="little", signed=False)
    return (
        database
        + product_code_bytes
        + _ascii_field(product_id)
        + _ascii_field(application_version)
        + _ascii_field(model_version)
        + _ascii_field(product_name)
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
        self.device: USBCANDevice | None = None
        self.receive_job: str | None = None
        self.address_claim_job: str | None = None
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
        self.database_version = tk.StringVar(value=str(DEFAULT_DATABASE_VERSION))
        self.model_version = tk.StringVar(value=DEFAULT_MODEL_VERSION)
        self.product_code = tk.StringVar(value=str(DEFAULT_PRODUCT_CODE))
        self.product_id = tk.StringVar(value=DEFAULT_PRODUCT_ID)
        self._build_ui()
        self.root.after(100, self.connect)

    def _build_ui(self) -> None:
        self._build_menu()
        main = ttk.Frame(self.root, padding=12)
        main.grid(sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        for column in range(3):
            main.columnconfigure(column, weight=1)

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
                font=("TkDefaultFont", 11, "bold"),
            )
            button.grid(row=index // 3, column=index % 3, padx=5, pady=5, sticky="nsew")
            self.switch_buttons.append(button)
        self._refresh_switch_button_labels()

    def _build_menu(self) -> None:
        menu_bar = tk.Menu(self.root)
        settings_menu = tk.Menu(menu_bar, tearoff=False)
        settings_menu.add_command(label="Node settings...", command=self.open_settings_dialog)
        settings_menu.add_separator()
        settings_menu.add_command(label="Retry connection", command=self.connect)
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
        self._add_setting_field(frame, 6, "Database version", self.database_version)
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
        return set_name_manufacturer_code(DEFAULT_SWITCH_DEVICE_NAME, manufacturer)

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

    def resolve_dll_path(self) -> str:
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), DEFAULT_DLL_NAME)

    def connect(self) -> None:
        if self.is_connected:
            return
        if platform.system() != "Windows":
            self.status_text.set("")
            messagebox.showerror("Unsupported OS", "This simulator requires Windows because it loads ECanVci.dll.")
            return
        try:
            config = DeviceConfig(
                dll_path=self.resolve_dll_path(),
                device_type=DEFAULT_DEVICE_TYPE,
                device_index=DEFAULT_DEVICE_INDEX,
                can_index=DEFAULT_CAN_INDEX,
                timing0=TIMING0_250K,
                timing1=TIMING1_250K,
            )
            self.device = USBCANDevice(config)
            self.device.open()
            self.is_connected = True
            self.status_text.set("")
            self._send_address_claim()
            self._send_product_info()
            self._send_heartbeat()
            self._schedule_receive()
            self._schedule_address_claim()
            self._schedule_heartbeat()
        except Exception as exc:
            self.device = None
            self.is_connected = False
            self.status_text.set("")
            messagebox.showerror("Connection error", str(exc))

    def disconnect(self) -> None:
        self._stop_receive()
        self._stop_address_claim()
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
            self._as_int(self.database_version.get(), DEFAULT_DATABASE_VERSION),
            self.model_version.get(),
            self._as_int(self.product_code.get(), DEFAULT_PRODUCT_CODE),
            self.product_id.get(),
        )
        frame_id = nmea2000_id(6, PGN_PRODUCT_INFO, self._source_address(), GLOBAL_DESTINATION)
        frames = split_fast_packet(payload, self.fast_packet_sequence)
        self.fast_packet_sequence = (self.fast_packet_sequence + 1) & 0x07
        for frame in frames:
            self.device.send(frame_id, frame.ljust(8, b"\xFF"))

    def _schedule_address_claim(self) -> None:
        if self.address_claim_job is None:
            self.address_claim_job = self.root.after(ADDRESS_CLAIM_INTERVAL_MS, self._send_address_claim_and_reschedule)

    def _send_address_claim_and_reschedule(self) -> None:
        self.address_claim_job = None
        if self.device and self.is_connected:
            self._send_address_claim()
            self._schedule_address_claim()

    def _stop_address_claim(self) -> None:
        if self.address_claim_job is not None:
            self.root.after_cancel(self.address_claim_job)
            self.address_claim_job = None

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

    def _handle_address_claim(self, frame_id: int, data: bytes) -> None:
        # Simplified address-conflict handling: if another node claims our source address,
        # re-send our address claim so the bus sees this simulated node's NAME again.
        if source_from_nmea2000_id(frame_id) == self._source_address() and data != build_address_claim(self._device_name()):
            self._send_address_claim()

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
