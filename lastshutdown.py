"""regrippy plugin"""
"""Not tested"""
import struct
from Registry import Registry
from Registry.RegistryParse import parse_windows_timestamp
from regrippy import BasePlugin, PluginResult, mactime


class Plugin(BasePlugin):
    """List the last shutdown time"""
    __REGHIVE__ = "SYSTEM"

    def run(self):

        key = self.open_key(self.get_currentcontrolset_path() + r"\Control\Windows\ShutdownTime")
        if not key:
            return

        try:
            value = self.convert_byte_value_dt(key.value("ShutdownTime")).isoformat('T') + 'Z'

        except Registry.RegistryValueNotFoundException:
            value = "N/A"

        yield PluginResult(key=key, value=value)

    def convert_byte_value_dt(byte_array):
        """Convert byte_array to datetime variable"""
        raw_shutdown_time = struct.unpack('<Q', byte_array)
        return parse_windows_timestamp(raw_shutdown_time[0])

    def display_human(self, result):
        print(result.key_name, "//", result.custom["ShutdownTime"])

    def display_machine(self, result):
        print(mactime(name=f"{result.key_name}\tShutdownTime={result.custom['ShutdownTime']}", mtime=result.mtime))
