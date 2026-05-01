import asyncio
import pyshark


loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

cap = pyshark.LiveCapture(interface='wlp0s20f0u3u1u4',display_filter='(wlan.fc.type_subtype == 0x00 || wlan.fc.type_subtype == 0x01 || wlan.fc.type_subtype == 0x02 || wlan.fc.type_subtype == 0x03 ||  wlan.fc.type_subtype == 0x04 || wlan.fc.type_subtype == 0x05)', debug=True)

#for packet in cap.sniff_continuously():
 #   print(packet.wlan.field_names)  # see all available wlan fields
  #  break

for packet in cap.sniff_continuously():
	for layer in packet.layers:
		print(f"\n-- {layer.layer_name} ---")
		print(layer.field_names)
	break













































































































