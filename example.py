# Copyright (c) 2017, Manito Networks, LLC
# All rights reserved.

# Import what we need
import time, datetime, socket, struct, sys, os, json, socket, collections, itertools, logging, logging.handlers, getopt, ipaddress
from struct import *
from binascii import unhexlify, hexlify

# Windows socket.inet_ntop support via win_inet_pton
try:
	import win_inet_pton
except ImportError:
	pass

from socket import inet_ntoa,inet_ntop
from elasticsearch import Elasticsearch,helpers
from IPy import IP
from xdrlib import Unpacker



### Get the command line arguments ###
try:
	arguments = getopt.getopt(sys.argv[1:],"hl:",["--help","log="])

	for option_set in arguments:
		for opt,arg in option_set:

			if opt in ('-l','--log'): # Log level
				arg = arg.upper() # Uppercase for matching and logging.basicConfig() format
				if arg in ["CRITICAL","ERROR","WARNING","INFO","DEBUG"]:
					log_level = arg # Use what was passed in arguments

			elif opt in ('-h','--help'): # Help file
				with open("./help.txt") as help_file:
					print(help_file.read())
				sys.exit()

			else: # No options
				pass

except:
    sys.exit("Unsupported or badly formed options, see -h for available arguments.")

# Set the logging level per https://docs.python.org/2/howto/logging.html
try:
	log_level # Check if log level was passed in from command arguments
except NameError:
	log_level="WARNING" # Use default logging level

logging.basicConfig(level=str(log_level)) # Set the logging level
logging.warning('Log level set to ' + str(log_level) + " - OK") # Show the logging level for debug

### DNS Lookups ###
#
# Reverse lookups
try:
	if dns is False:
		logging.warning("DNS reverse lookups disabled - DISABLED")
	elif dns is True:
		logging.warning("DNS reverse lookups enabled - OK")
	else:
		logging.warning("DNS enable option incorrectly set - DISABLING")
		dns = False
except:
	logging.warning("DNS enable option not set - DISABLING")
	dns = False

# RFC-1918 reverse lookups
try:
	if lookup_internal is False:
		logging.warning("DNS local IP reverse lookups disabled - DISABLED")
	elif lookup_internal is True:
		logging.warning("DNS local IP reverse lookups enabled - OK")
	else:
		logging.warning("DNS local IP reverse lookups incorrectly set - DISABLING")
		lookup_internal = False
except:
	logging.warning("DNS local IP reverse lookups not set - DISABLING")
	lookup_internal = False

# Check if the sFlow port is specified

sflow_port = 6343
elasticsearch_host = "172.16.2.236:9200"

try:
	sflow_port
except NameError: # Not specified, use default
	sflow_port = 6343
	logging.warning("sFlow port not set in netflow_options.py, defaulting to " + str(sflow_port) + " - OK")

# Set up socket listener
try:
	netflow_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	netflow_sock.bind(('0.0.0.0', sflow_port))
	logging.warning('Bound to UDP port ' + str(sflow_port) + ' - OK')
except ValueError as socket_error:
	logging.critical('Could not open or bind a socket on port ' + str(sflow_port))
	logging.critical(str(socket_error))
	sys.exit("Could not open or bind a socket on port " + str(sflow_port))

### Elasticsearch ###
es = Elasticsearch([elasticsearch_host])

### sFlow Collector ###
if __name__ == "__main__":
	from counter_records import * 	# Functions to parse counter record structures
	from flow_records import * 		# Functions to parse flow record structures
	from sflow_parsers import * 	# Functions to parse headers and misc data chunks
	from sflow_samples import * 	# Functions to parse sFlow samples

	global sflow_data
	sflow_data = [] # For bulk upload to Elasticsearch

	global uuid_cache
	uuid_cache = {}

	record_num = 0 # Record index number for the record cache

	# Continue to run
	while True:

		# Listen for packets inbound
		sflow_packet_contents, sensor_address = netflow_sock.recvfrom(65565)

		### sFlow Datagram Start ###
		try:
			unpacked_data = Unpacker(sflow_packet_contents) # Unpack XDR datagram
			datagram_info = datagram_parse(unpacked_data) # Parse the datagram

			logging.debug(str(datagram_info))
			logging.info("Unpacked an sFlow datagram from " + str(sensor_address[0]) + " - OK")

		except Exception as datagram_unpack_error:
			logging.warning("Unable to unpack the sFlow datagram - FAIL")
			logging.warning(str(datagram_unpack_error))
			continue

		if datagram_info["sFlow Version"] != 5:
			logging.warning("Not an sFlow v5 datagram - SKIPPING")
			continue
		### sFlow Datagram End ###

		### sFlow Samples Start ###
		for sample_num in range(0,datagram_info["Sample Count"]): # For each sample in the datagram

			### Sample Header Start ###
			enterprise_format_num = enterprise_format_numbers(unpacked_data.unpack_uint()) # Enterprise number and format
			sample_length = int(unpacked_data.unpack_uint()) # Sample Length

			logging.info("Sample " + str(sample_num+1) + " of " + str(datagram_info["Sample Count"]) + ", type " + str(enterprise_format_num) + " length " + str(sample_length))

			try:
				unpacked_sample_data = Unpacker(unpacked_data.unpack_fopaque(sample_length)) # Unpack the sample data block
				logging.info("Unpacked opaque sample data chunk - OK")
			except Exception as unpack_error:
				logging.warning("Failed to unpack opaque sample data - FAIL")
				continue
			### Sample Header Finish ###

			### Sample Parsing Start ###
			flow_sample_cache = sample_picker(enterprise_format_num,unpacked_sample_data) # Get the opaque flow sample cache

			if flow_sample_cache is False:
				logging.warning("Unable to parse the sample cache, type " + str([enterprise_format_num,unpacked_sample_data]) + " from " + str(datagram_info["Agent IP"]) + " - SKIPPING")
				continue
			else:
				logging.info(str(flow_sample_cache))

			### Flow Sample ###
			if enterprise_format_num in [[0,1], [0,3]]: # Flow Sample

				# Iterate through the flow records
				for record_counter_num in range(0,flow_sample_cache["Record Count"]): # For each staged sample
					record_ent_form_number = enterprise_format_numbers(unpacked_sample_data.unpack_uint()) # [Enterprise, Format] numbers
					counter_data_length = int(unpacked_sample_data.unpack_uint()) # Length of record
					current_position = int(unpacked_sample_data.get_position()) # Current unpack buffer position
					skip_position = current_position + counter_data_length # Bail out position if unpack fails for skipping

					logging.info(
						"Flow record " +
						str(record_counter_num+1) +
						" of " +
						str(flow_sample_cache["Record Count"]) +
						", type " +
						str(record_ent_form_number) +
						", length " +
						str(counter_data_length) +
						", XDR position " +
						str(current_position) +
						", skip position " +
						str(skip_position)
						)

					# Unpack the opaque flow record
					unpacked_record_data = Unpacker(unpacked_sample_data.unpack_fopaque(counter_data_length))

					# Parse the flow record
					try:
						now = datetime.datetime.utcnow() # Get the current UTC time

						flow_index = {
						"_index": str("sflow-" + now.strftime("%Y-%m-%d")),
						"_type": "Flow",
						"_source": {
						"Flow Type": "sFlow Flow",
						"Sensor": datagram_info["Agent IP"],
						"Sub Agent": datagram_info["Sub Agent"],
						"Enterprise, Format": record_ent_form_number,
						"Data Length": counter_data_length,
						"Time": now.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (now.microsecond / 1000) + "Z",
						}
						}

						flow_index["_source"].update(flow_sample_cache) # Add sample header info to each record

						if record_ent_form_number == [0,1]: # Raw packet header
							flow_index["_source"].update(raw_packet_header(unpacked_record_data))

							header_ascii = raw_packet_header("Header")
							ip_header_hb = hexlify(header_ascii.encode())
							ip_header = ip_header_hb.decode()
							print(ip_header)

							ver = ip_header[0:1]
							# Low 4 bits hold header length in 32-bit words;
							# By multiplying by four 32-bit words are converted to bytes
							hdr_size = (int(ip_header[1:2],16)*4)
							# dscp = hdr_unpacked[1] >> 6  # High 6 bits
							# ecn = hdr_unpacked[1] & 0b11  # Low 2 bits
							tlen = (int(ip_header[5:8],16))
							# id = hdr_unpacked[3]
							# #flags = IPFlags(hdr_unpacked[4] >> 3)
							# # Low 13 bits
							# fragoff = hdr_unpacked[4] & 0b1111111111111
							# ttl = hdr_unpacked[5]
							# proto = hdr_unpacked[6]
							# check_sum = hdr_unpacked[7]
							src_ip = ipaddress.ip_address((int(ip_header[24:32],16))).__str__()
							dst_ip = ipaddress.ip_address((int(ip_header[32:40],16))).__str__()
							src_port = int(ip_header[40:44],16)
							dst_port = int(ip_header[44:48],16)

							# dst_ip = socket.inet_ntoa(hdr_unpacked[9])

							print("IP Version", ver)
							print("IP Header Length", hdr_size, "bytes")
							# print("Diff Services", "{}", dscp)
							# print("Expl Congestion Notification", "{}", ecn)
							print("Total Length", tlen, "bytes")
							# print("Identification", "0x{:04x}", id)
							# #print("Flags", "{}", flags)
							# print("Fragment Offset", "{}", fragoff)
							# print("TTL", "{}", ttl)
							# print("Protocol", proto)
							# print("Checksum", "0x{:04x}", check_sum)
							print("Source IP", src_ip)
							print("Source Port", src_port)
							print("Destination IP", dst_ip)
							print("Destination Port", dst_port)
							print("====")

							flow_index = {} # Reset the flow_index
							record_num += 1
							sys.exit()

					except Exception as fucking_error:
						print(fucking_error)

					sflow_data = []
					record_num = 0 # Reset flow counter
