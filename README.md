#EsetLogParser
Proof of Concept

##About
Python script for parsing ESET (NOD32) `virlog.dat` file. This file contains records about infections detected during on access scans and it is usually located in `C:\ProgramData\Eset\*\Logs`.

GUI of Eset antivirus program can display content of actual `virlog.dat` file, also it is possible to use Eset Log Collector for collect logs from this file. But none of this official program can easily display content of another `virlog.dat` file, for example file exracted from offline machine for further analysis.
On live system, it is not possible to overwrite the existing `virlog.dat`, because it is used by running instance of Eset and it is not so easy to kill the Eset AV program. (turning off the resident shield is not enough).

*As far as I know, the only solution for displaying content of another virlog.dat file is to use the PC with Eset installed, shut down this PC, overwrite the original virdat.log file and reboot the system.*

This Python script can parse some content from `virlog.dat` files and convert this data to CSV format. This tool is based on reverse engineering the file format of `virlog.dat`, and work is in progress. For this reason, this scrit currently can not parse all the fields from `virlog.dat`.

###Disclaimer
Tested on current version of Eset Nod32 and Smart Security and also on versions from middle of 2016.
Correct functionality of this script is not guaranteed, because the file format of `virlog.dat` is proprietary internal format of Eset and this format may change with new versions of Eset products. In this case please create an Issue and if it is possible, please also provide samples of `virlog.dat`.

##Supported fields
- Detected object
- Infiltration type
- User name
- Version of antivirus database
- Program name (or process) in which the infiltration was detected
- SHA1 hash of detected object
 Detected object
- First seen timestamp

###Note
It seems that not of the above fields are always present in record. If you don't see some of the above fields in the output of EsetLogParser, but you see this value in Eset GUI (Tools -> Logs), please send me the `virlog.dat` file and screenshot of Eset GUI Log Viewer.

##Known fields
The list of curentlly reversed fields in `virlog.dat` file that are not parsed by EsetLogParser:
- Timestamp of detection

##Unknown fields
The list of fields which I have not reversed in `virlog.dat` yet:
- Object type (file, etc.)
- Scanner (resident shield)
- Action (erase, quarantine)

##Usage
`python EsetLogParser.py path_to_virlog.dat`

##TODO
- reversing all the fields in `virlog.dat` file
- turn this PoC into real parser
	- change fields extractor to fields parser
