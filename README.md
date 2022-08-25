# pysmapper
Pysmapper is a simple command-line tool to map the available ciphers of a host. It can be used to check whether the ssl
is valid on a specific host.
## The command line tool
### Command line options
Here are the command line option and descritption
#### -v | --verbose
Défini si la commande doit afficher les résultats de manière facilement lisible
#### -i | --input
An option that describe a path to file a file which will be used to indicate hosts. The file must list the addresses
separated by carriage return. Addresses can be IPv4 addresses or domain name
#### -p | --port
An option that describe a specific port to check the ciphers on, by default it is set to 443 which is the HTTPS tcp port
#### -mp | --module_path
Define a specific path to the module path containing the program config, by default it will look in its current directory
#### -u | --update
Define a path to a python file update in aim to update the SSL/TLS cipher list for new versions
#### -h | --help
Give the help menu of the command line tool
#### -f | --format
Define a special format for the output, if the format is not handled format output will be csv.
There is 3 native format supported, the verbose, the csv and the openmetrics sorted by address which can be called by
passing argument `-f openmetrics-by-address` or `--format openmetrics-by-address`. 
#### -ount | --on-unsecure-text
Default text to be displayed and sent to the text handler if an unsecure cipher is detected. If not specified the
character sent is `u`.
#### -oat | --on-accepted-text
Default text to be sent to the text handler if the cipher is accepted. If not specified the character is `y`
### Updating pysmapper
To update psymapper you need to execute `pysmapper.py --update <config file>` where config file is a path to a python.
It is the same as describe just above. However, the python update file need some specific element to work well.