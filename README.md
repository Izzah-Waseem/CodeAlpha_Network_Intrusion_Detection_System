# CodeAlpha_Network_Intrusion_Detection_System

We used Snort to develop a network-based intrusion detection system (NIDS). We'll follow these steps:

**Step 1: Install Snort**

**For Ubuntu/Debian:**

  
Update your package list and install the required dependencies:

    sudo apt-get update


**Download and install Snort:**

    sudo apt-get install snort

**Step 2: Configure Snort**

**Download and configure Snort rules:**

Download the Snort community rules from the Snort website:

    wget https://www.snort.org/downloads/community/community-rules.tar.gz
    tar -xvzf community-rules.tar.gz -C /etc/snort/rules

**Edit the Snort configuration file (/etc/snort/snort.conf):**

    var RULE_PATH /etc/snort/rules
    var SO_RULE_PATH /etc/snort/so_rules
    var PREPROC_RULE_PATH /etc/snort/preproc_rules
    include $RULE_PATH/local.rules
    include $RULE_PATH/community.rules
    
    output alert_fast: stdout
    output unified2: filename snort.log, limit 128


**Step 3: Set Up Rules and Alerts**

**Add custom rules to local.rules:**

    nano /etc/snort/rules/local.rules

Example rules to detect requests:

    alert icmp any any -> any any (msg:"ICMP Packet Detected"; sid:1000001; rev:1;)
    alert tcp any any -> any 80 (msg:"TCP Traffic on Port 80"; sid:1000002; rev:1;)
    alert tcp any any -> any 22 (msg:"SSH Login Attempt"; sid:1000003; rev:1;)
    alert tcp any any -> any 80 (msg:"HTTP GET Request Detected"; content:"GET"; sid:1000004; rev:1;)
    alert tcp any any -> any 80 (msg:"Access to google.com Detected"; content:"google.com"; sid:1000005; rev:1;)
    alert tcp any any -> any 21 (msg:"FTP Login Attempt"; content:"USER"; sid:1000006; rev:1;)
    alert udp any any -> any 53 (msg:"DNS Query Detected"; sid:1000007; rev:1;)
    alert tcp any any -> any 23 (msg:"Telnet Connection Detected"; sid:1000008; rev:1;)
    alert tcp any any -> any 445 (msg:"SMB Traffic Detected"; sid:1000009; rev:1;)
    alert tcp any any -> any 80 (msg:"Suspicious User-Agent Detected"; content:"BadUserAgent"; sid:1000010; rev:1;)

**Step 4: Test Snort and Analyze Logs**

Make sure Snort is running and monitoring the correct network interface. If running Snort manually:

    sudo snort -c /etc/snort/snort.conf -T

**Run Snort Verbosely:**

Execute Snort with the following command to see real-time alerts on the console:

    sudo snort -A console -i ens33 -c /etc/snort/snort.conf -K ascii -v

**Generate Traffic:**

From another terminal or machine, generate traffic that matches your rules. For example:

      ping -c 4 <target_IP>
      curl http://<target_IP>
      ssh user@<target_IP>

Replace <target_IP> with the appropriate IP address you want to test against.

**Verifying Alerts**

As traffic is generated, you should see alerts in the console where Snort is running. For example, you should see alerts similar to the provided screenshots.

**Step 5: Visualizing**

**Visualizing:** Use tools like Wireshark to visualize captured packets and analyze detected attacks. Snort itself can log alerts to files (/var/log/snort/alert) that you can analyze manually or with other tools.

**Step 6: Fine-tuning and Alerts**

**Fine-tuning:** Adjust rules based on false positives or missed detections.

**Alerts:** Configure alerts to notify administrators via email, syslog, or other methods when suspicious activity is detected.

**Step 7: Monitoring and Response**

Continuously monitor Snort alerts and logs. Develop response procedures for confirmed incidents based on detected attacks.
