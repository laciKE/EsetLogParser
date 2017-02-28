#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
EsetLogParser: Python script for parsing ESET (NOD32) virlog.dat file.
Copyright (C) 2017 Ladislav Baco

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

from __future__ import print_function
from datetime import datetime
import argparse
import struct
import os, time
import sys

__author__ = 'Ladislav Baco'
__copyright__ = 'Copyright (C) 2017'
__credits__ = 'Ladislav Baco'
__license__ = 'GPLv3'
__version__ = '0.2'
__maintainer__ = 'Ladislav Baco'
__status__ = 'Development'

TIMEFORMAT = '%Y-%m-%dT%H:%M:%SZ'
NULL = '\x00\x00'
RECORD_HEADER = '\x24\x00\x00\x00\x01\x00\x01\x00'
OBJECT_HEADER = '\xbe\x0b\x4e\x00'
INFILTRATION_HEADER = '\x4d\x1d\x4e\x00'
USER_HEADER = '\xee\x03\x4e\x00'
VIRUSDB_HEADER = '\x17\x27\x4e\x00'
PROGNAME_HEADER = '\xc4\x0b\x4e\x00'
PROGHASH_HEADER = '\x9d\x13\x42\x00'
OBJECTHASH_HEADER = '\x9e\x13\x42\x00'
FIRSTSEEN_HEADER = '\x9f\x13\x46\x00'

_dataTypeHeaders = {'Object': OBJECT_HEADER,
                   'Infiltration': INFILTRATION_HEADER,
                   'User': USER_HEADER,
                   'VirusDB': VIRUSDB_HEADER,
                   'ProgName': PROGNAME_HEADER}
_hashTypeHeaders = {'ObjectHash': OBJECTHASH_HEADER,
               'ProgHash': PROGHASH_HEADER}

def eprint(*args, **kwargs):
	'''Prints debug messages to stderr'''
	print(*args, file=sys.stderr, **kwargs)

def _infoNotFound(field):
	eprint('Info: field not found: ' + field)

def _warningUnexpected(field):
	eprint('Warning: unexpected bytes in field ' + field)

def _winToUnixTimestamp(winTimestamp):
	magicNumber = 11644473600
	return (winTimestamp / 10000000) - magicNumber

def _extractDataType(dataType,rawRecord):
	#Format: dataType_HEADER + '??' + NULL + objectData + NULL

	dataType_HEADER = _dataTypeHeaders[dataType]
	dataOffset = rawRecord.find(dataType_HEADER);
	if dataOffset < 0:
		_infoNotFound(dataType)
		return ''
	if rawRecord[dataOffset+6:dataOffset+8] != NULL:
		_warningUnexpected(dataType)
	# find NULL char, but search for (\x00)*3, because third zero byte is part of last widechar
	dataEnd = dataOffset + 9 + rawRecord[dataOffset+8:].find('\x00' + NULL)
	dataWideChar = rawRecord[dataOffset+8:dataEnd]
	return dataWideChar.decode('utf-16')

def _extractHashType(hashType,rawRecord):
	#Format: hashType_HEADER + '??' + NULL + hashData[20]

	hashType_HEADER = _hashTypeHeaders[hashType]
	hashOffset = rawRecord.find(hashType_HEADER);
	if hashOffset < 0:
		_infoNotFound(hashType)
		return ''
	if rawRecord[hashOffset+6:hashOffset+8] != NULL:
		_warningUnexpected(hashType)
	hashEnd = hashOffset + 9 + 20
	hashHex = rawRecord[hashOffset+8:hashEnd]
	return hashHex.encode('hex')

def _extractFirstSeen(rawRecord):
	#Format: FIRSTSEEN_HEADER + UnixTimestamp[4]

	offset = rawRecord.find(FIRSTSEEN_HEADER);
	if offset < 0:
		_infoNotFound('FirstSeen')
		return ''
	littleEndianTimestamp = rawRecord[offset+4:offset+8]
	timestamp = struct.unpack('<L', littleEndianTimestamp)[0]
	return datetime.utcfromtimestamp(timestamp).strftime(TIMEFORMAT)

def _extractTimestamp(rawRecord):
	#Format: RECORD_HEADER + ID[4] + MicrosoftTimestamp[8]

	littleEndianTimestamp = rawRecord[4:12]
	winTimestamp = struct.unpack('<Q', littleEndianTimestamp)[0]
	timestamp = _winToUnixTimestamp(winTimestamp)
	return datetime.utcfromtimestamp(timestamp).strftime(TIMEFORMAT)

def _checkID(recordId, rawRecord):
	littleEndianIds = [rawRecord[0:4], rawRecord[16:20]]
	for littleEndianId in littleEndianIds:
		if struct.unpack('<L', littleEndianId)[0] != recordId:
			_warningUnexpected('ID')

def getRawRecords(rawData):
	rawRecords = rawData.split(RECORD_HEADER)[1:]
	records = zip(range(len(rawRecords)), rawRecords)
	for recordId, rawRecord in records:
		_checkID(recordId, rawRecord)
	return records

def parseRecord(recordId, rawRecord):
	timestamp = _extractTimestamp(rawRecord)
	virusdb = _extractDataType('VirusDB', rawRecord)
	obj = _extractDataType('Object', rawRecord)
	objhash = _extractHashType('ObjectHash', rawRecord)
	infiltration = _extractDataType('Infiltration', rawRecord)
	user = _extractDataType('User', rawRecord)
	progname = _extractDataType('ProgName', rawRecord)
	proghash = _extractHashType('ProgHash', rawRecord)
	firstseen = _extractFirstSeen(rawRecord)

	return [str(recordId), timestamp, virusdb, obj, objhash, infiltration, user, progname, proghash, firstseen]

def main():
	parser = argparse.ArgumentParser(description='EsetLogParser: Python script for parsing ESET (NOD32) virlog.dat file.')
	parser.add_argument('virlog', help='path to virlog.dat file')
	parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + __version__)


	args = parser.parse_args()

	if not os.path.isfile(args.virlog):
	        raise Exception('Virlog file does not exist')

	with open(args.virlog, 'rb') as f:
		virlog_data = f.read()

	rawRecords = getRawRecords(virlog_data)
	parsedRecords = [['ID', 'Timestamp', 'VirusDB', 'Object', 'ObjectHash','Infiltration', 'User', 'ProgName', 'ProgHash', 'FirstSeen']]
	for recordId, rawRecord in rawRecords:
		parsedRecords.append(parseRecord(recordId, rawRecord))
	print('\n'.join([';'.join(record) for record in parsedRecords]))

if __name__ == '__main__':
	main()
