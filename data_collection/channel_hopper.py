"""
	Hop between multiple channels rather than monitoring from single channel.
	Channel awareness is maintained (if this works :D )

	If it works we could add:
		- Hopping for 5 GHz channels
		- Random order for Hopping ( Stealth 100 )

"""



import time
import subprocess
import threading

class ChannelHopper:
	def __init__(self, interface, channels, dwell_time=1.0):
		"""
		Args:
			interface: monitor-mode interface (e.g. wlan0mon)
			channels: list of channels to hop through
			dwell_time: seconds to stay on each channel
		"""
		
		self.interface = interface
		self.channels = channels
		self.dwell_time = dwell_time
		self.current_channel = None
		
		self._stop_event = threading.Event()
		self._thread = None
		
	def _set_channel(self, channel):
		subprocess.run(
			["iw", "dev", self.interface, "set", "channel", str(channel)],
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL
		)
		self.current_channel = channel
		#print(f"[HOP] Now listening on channel {channel}")
		
	def _hop_loop(self):
		while not self._stop_event.is_set():
			for ch in self.channels:
				if self._stop_event.is_set():
					break
				self._set_channel(ch)
				time.sleep(self.dwell_time)
	
	def start(self):
		"""Start channel hopping in a separate thread"""
		if self._thread and self._thread.is_alive():
			return
		self._stop_event.clear()
		self._thread = threading.Thread(target=self._hop_loop, daemon=True)
		self._thread.start()
		
	def stop(self):
		"""Stop hopping and join thread"""
		self._stop_event.set()
		if self._thread:
			self._thread.join()
			
	def get_current_channel(self):
		"""Return the current channel for packet tagging"""
		return self.current_channel	
