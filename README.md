# Network layer filtering using suricata
  In this project I'm going to demonstrate how to apply rule filtering and thresholding for network layer attacks using Suricata in pfsense. For this we'll launch DOS attack from Kali Linux using hping3. From this we'll learn how to filter and alert for DOS attack.

  Rule filtering in network security means defining rules to detect and block malicious traffic according to specific patterns. In this project we will use SYN and ICMP floods for demonstration. These rules inspect the headers and payloads to match predefined rules. Thresholding helps reduce the false positive rate by controlling how often an alert has to be triggered. For example, if 30 packets are incoming in 5 seconds then alert has to be triggered instead for raising alert for what may not be an attack. Sometimes large amount of traffic might be normal, so it is essential we understand what might be right amount to focus on actual threat.

Steps:
      1. Run the network_filter.sh file. Before that make it executable file using chmod +x network_filter.sh, then use command ./network_filter.sh to run.
      2. Run hping3 command in Kali Linux for required port and IP address of firewall machine.
      3. You can find the log of the attack in /var/log/suricata/eve.json and /var/log/suricata/eve.json. 
       
 Below images show log of detection for both SYN and ICMP floods
       
 <img width="463" alt="custom rules" src="https://github.com/user-attachments/assets/7cbc1a74-2e37-4a93-8e06-c5440bd63b56" />

       
 <img width="491" alt="tcp_fast log" src="https://github.com/user-attachments/assets/c4ae8805-8c57-4234-94b6-c827e9d6e6e8" />

       
 <img width="406" alt="icmp_flood" src="https://github.com/user-attachments/assets/aa7a96ec-8951-4b4b-9383-7a352770b85c" />

       
 <img width="413" alt="icmp_fast log" src="https://github.com/user-attachments/assets/69bc22af-08a2-4ad4-b5f7-f21e8c5944f6" />



       


       
