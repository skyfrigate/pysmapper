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