import unittest
import sys
if sys.hexversion >= 0x03000000:
	from io import StringIO
else:
	from StringIO import StringIO
from contextlib import contextmanager

@contextmanager
def capture():
	out, sys.stdout = sys.stdout, StringIO()
	err, sys.stderr = sys.stderr, StringIO()
	try:
		yield sys.stdout, sys.stderr
	finally:
		sys.stdout = out
		sys.stderr = err

class HelperMethodsTest(unittest.TestCase):
	def test_timestamp_conversion(self):
		from EsetLogParser import _winToUnixTimestamp
		self.assertEqual(_winToUnixTimestamp(131349483990000000), 1490474799)
	def test_error_print(self):
		from EsetLogParser import eprint
		hello = 'HelloError'
		with capture() as (out, err):
			eprint(hello)
		self.assertEqual(err.getvalue().strip(), hello)

	def test_info_message(self):
		from EsetLogParser import _infoNotFound
		field = 'FIELD'
		with capture() as (out, err):
			_infoNotFound(field)
		msg = err.getvalue().strip()
		self.assertTrue(msg.find('Info') > -1)
		self.assertTrue(msg.find(field) > -1)

	def test_warning_message(self):
		from EsetLogParser import _warningUnexpected
		field = 'FIELD'
		with capture() as (out, err):
			_warningUnexpected(field)
		msg = err.getvalue().strip()
		self.assertTrue(msg.find('Warning') > -1)
		self.assertTrue(msg.find(field) > -1)

class ArgumentTest(unittest.TestCase):
	def test_virlog_argument(self):
		from EsetLogParser import _parse_args
		virlog = 'virlog.dat'
		args = _parse_args([virlog])
		self.assertEqual(args.virlog, virlog)

class EsetLogParserTest(unittest.TestCase):
	def setUp(self):
		virlog = 'testlog.dat'
		with open(virlog, 'rb') as f:
			self.data = f.read()

	def test_get_raw_records(self):
		from EsetLogParser import getRawRecords
		records = getRawRecords(self.data)
		self.assertEqual(len(records), 2)

	def test_parse_record(self):
		from EsetLogParser import getRawRecords, parseRecord
		records = getRawRecords(self.data)
		with capture() as (out, err):
			parsed = parseRecord(records[0][0], records[0][1])
		self.assertEqual(int(parsed[0]), 0)
		self.assertTrue('@Teststring.Eicar' in parsed)
		self.assertTrue('3395856ce81f2b7382dee72602f798b642f14140a0' in parsed)
	def test_main(self):
		import EsetLogParser
		with capture() as (out, err):
			parsed = EsetLogParser.main(['testlog.dat'])
		msg = out.getvalue()
		self.assertEqual(msg.count('\n'),3)
		self.assertTrue(msg.find('@Teststring.Eicar') > -1)
		self.assertTrue(msg.find('3395856ce81f2b7382dee72602f798b642f14140a0') > -1)
	
if __name__ == '__main__':
    unittest.main()
