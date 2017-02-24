#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import struct
import os, time

VERSION = '0.1'
NULL = '\x00\x00'
RECORD_HEADER = '\x01\x00\x00\x00\x02\x00\x00\x00' #prefixed by little-endian representation of 32-bit ID of record
OBJECT_HEADER = '\xbe\x0b\x4e\x00'
INFILTRATION_HEADER = '\x4d\x1d\x4e\x00'
USER_HEADER = '\xee\x03\x4e\x00'
VIRUSDB_HEADER = '\x17\x27\x4e\x00'
PROGNAME_HEADER = '\xc4\x0b\x4e\x00'
PROGHASH_HEADER = '\x9d\x13\x42\x00'
OBJECTHASH_HEADER = '\x9e\x13\x42\x00'

dataTypeHeaders = {'Object': OBJECT_HEADER,
                   'Infiltration': INFILTRATION_HEADER,
                   'User': USER_HEADER,
                   'VirusDB': VIRUSDB_HEADER,
                   'ProgName': PROGNAME_HEADER}
hashTypeHeaders = {'ObjectHash': OBJECTHASH_HEADER,
               'ProgHash': PROGHASH_HEADER}

def _warningNotFound(field):
	print 'Warning: field not found: ' + field

def _warningUnexpected(field):
	print 'Warning: unexpected bytes in field ' + field


def _extractDataType(dataType,rawRecord):
	#Format: dataType_HEADER + '??' + NULL + objectData + NULL

	dataType_HEADER = dataTypeHeaders[dataType]
	dataOffset = rawRecord.find(dataType_HEADER);
	if dataOffset < 0:
		_warningNotFound(dataType)
		return ''
	if rawRecord[dataOffset+6:dataOffset+8] != NULL:
		_warningUnexpected(dataType)
	# find NULL char, but search for (\x00)*3, because third zero byte is part of last widechar
	dataEnd = dataOffset + 9 + rawRecord[dataOffset+8:].find('\x00' + NULL)
	dataWideChar = rawRecord[dataOffset+8:dataEnd]
	return dataWideChar.decode('utf-16')

def _extractHashType(hashType,rawRecord):
	#Format: hashType_HEADER + '??' + NULL + hashData[20]

	hashType_HEADER = hashTypeHeaders[hashType]
	hashOffset = rawRecord.find(hashType_HEADER);
	if hashOffset < 0:
		_warningNotFound(hashType)
		return ''
	if rawRecord[hashOffset+6:hashOffset+8] != NULL:
		_warningUnexpected(hashType)
	hashEnd = hashOffset + 9 + 20
	hashHex = rawRecord[hashOffset+8:hashEnd]
	return hashHex.encode('hex')

def _findRecordOffset(recordId, rawData):
	#Format: litle-endian 32 bit ID + RECORD_HEADER
	littleEndianId = struct.pack('<L', recordId)
	return rawData.find(littleEndianId + RECORD_HEADER)

def getRawRecords(rawData):
	#return virlog_data.split(RECORD_HEADER)[1:]
	rawRecords = []
	recordId = 0
	recordOffset =_findRecordOffset(recordId, rawData)
	nextRecordOffset = _findRecordOffset(recordId+1, rawData)
	while nextRecordOffset > 0:
		rawRecords.append((recordId, rawData[recordOffset:nextRecordOffset]))
		rawData = rawData[nextRecordOffset:]
		recordOffset = 0
		recordId += 1
		nextRecordOffset = _findRecordOffset(recordId+1, rawData)
	rawRecords.append((recordId, rawData[recordOffset:]))

	return rawRecords


def parseRecord(recordId, rawRecord):
	virusdb = _extractDataType('VirusDB', rawRecord)
	obj = _extractDataType('Object', rawRecord)
	objhash = _extractHashType('ObjectHash', rawRecord)
	infiltration = _extractDataType('Infiltration', rawRecord)
	user = _extractDataType('User', rawRecord)
	progname = _extractDataType('ProgName', rawRecord)
	proghash = _extractHashType('ProgHash', rawRecord)

	return [str(recordId), virusdb, obj, objhash, infiltration, user, progname, proghash]

def main():
	parser = argparse.ArgumentParser(description='Eset Log Parser' + VERSION)
	parser.add_argument('virlog', help='virlog.dat file to parse')

	args = parser.parse_args()

	if not os.path.isfile(args.virlog):
	        raise Exception('Virlog file does not exist')

	with open(args.virlog, 'rb') as f:
		virlog_data = f.read()

	rawRecords = getRawRecords(virlog_data)
	parsedRecords = [['ID', 'VirusDB', 'Object', 'ObjectHash','Infiltration', 'User', 'ProgName', 'ProgHash']]
	for recordId, rawRecord in rawRecords:
		parsedRecords.append(parseRecord(recordId, rawRecord))
	print '\n'.join([';'.join(record) for record in parsedRecords])

if __name__ == '__main__':
	main()
