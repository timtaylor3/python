"""
Regrippy plugin
Not tested
"""
from Registry import Registry
from Registry.RegistryParse import parse_windows_timestamp

from regrippy import BasePlugin, PluginResult, mactime


class Plugin(BasePlugin):
    """List the last shutdown time"""
    __REGHIVE__ = "SYSTEM"

    def run(self):
        key = self.open_key(self.get_currentcontrolset_path() + "\\Control\\Windows")
        if not key:
            return

        for lastshutdown in key.subkeys():
            try:
                last_shutdown = self.convert_byte_value_dt(lastshutdown.value("ShutdownTime").value())
            except Registry.RegistryValueNotFoundException:
                last_shutdown = "N/A"

            res = PluginResult(key=lastshutdown, value=None)
            res.custom["last_shutdown"] = last_shutdown.isoformat('T') + 'Z'
            yield res

    def convert_byte_value_dt(byte_array):
        """
        Convert byte_array to datetime variable
        """
        raw_shutdown_time = struct.unpack('<Q', byte_array)
        return parse_windows_timestamp(raw_shutdown_time[0])

    def display_human(self, result):
        print(result.key_name, "//", result.custom["image_path"])

    def display_machine(self, result):
        print(mactime(name=f"{result.key_name}\tImagePath={result.custom['image_path']}", mtime=result.mtime))







