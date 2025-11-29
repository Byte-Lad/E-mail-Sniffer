# E-mail-Sniffer


This script is a sniffer written in Python using the Scapy library, designed to capture credentials sent in plain text on older email protocols such as POP3 (110), SMTP (25), and IMAP (143).

The script monitors TCP traffic on these ports and identifies any payload containing terms such as “USER” or “PASS,” which are common in POP3 authentication. Once detected, it displays the packet destination and the received content.
