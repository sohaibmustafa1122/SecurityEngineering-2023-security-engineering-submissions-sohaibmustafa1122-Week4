# SecurityEngineering-2023-security-engineering-submissions-sohaibmustafa1122-Week4
Week4



Task 1:

Meltdown is a timing-based side-channel attack that exploits out-of-order execution in modern CPUs. It bypasses the CPU's privilege separation to access kernel memory, which is normally protected. By utilizing speculative execution, the attack reads kernel memory and measures timing differences to infer sensitive data (Kocher et al., 2018). This vulnerability primarily affects Intel CPUs manufactured before 2018, as well as some ARM and AMD processors. Systems based on x86 architecture, such as desktops, laptops, servers, and virtual machines, are particularly vulnerable (Intel Security Center, 2018).

Through this side channel, Meltdown can leak sensitive information stored in kernel memory, including passwords, cryptographic keys, and other critical data that user-level programs should not have access to (CVE-2017-5754 Documentation). While there is no publicly confirmed case of Meltdown being exploited in real-life attacks, its discovery in 2018 raised significant concerns about the potential for misuse, particularly in targeted or pre-disclosure scenarios (Kocher et al., 2018).

The vulnerability has been addressed through both software and hardware updates. Operating systems implemented Kernel Page-Table Isolation (KPTI), which ensures that kernel memory is separated from user processes. Additionally, CPUs manufactured post-2018 incorporated hardware-based changes to prevent speculative execution from accessing privileged memory spaces (Intel Security Center, 2018). These mitigations have significantly reduced the risk posed by Meltdown in modern systems.

References
Kocher, P., et al. (2018). "Spectre and Meltdown."
Intel Security Center. (2018).
CVE-2017-5754 Documentation.
Meltdownattack.com. (2018). "Meltdown Overview and Impact."



Task 2:
The Slowloris Denial-of-Service (DoS) attack works by exploiting the way web servers handle HTTP headers. It sends partial HTTP requests and keeps these connections open for as long as possible by periodically sending more headers without completing the request. This prevents the server from closing the connections, consuming server resources, and blocking legitimate traffic (OWASP Slowloris Project, 2021).

What makes Slowloris unique compared to high-bandwidth Distributed Denial-of-Service (DDoS) attacks is its low resource requirement. Instead of overwhelming the server with a massive flood of traffic, it uses a small number of requests to monopolize the server's connection pool. This makes the attack stealthier and more targeted, as it requires minimal bandwidth from the attacker while still achieving significant disruption (Ristic, 2013).

The effects of a Slowloris attack are severe for targeted servers. It consumes all available connections, leading to slow responses or complete inaccessibility for legitimate users. Servers that are older or poorly configured are particularly vulnerable, as they may lack safeguards against prolonged connections or resource exhaustion (CVE-2009-3555 Documentation).

Mitigating Slowloris involves several strategies. Configuring servers to reduce connection timeout durations and limit the maximum number of open connections per IP address is effective. Using reverse proxies, load balancers, or web application firewalls (WAFs) helps to filter out malicious requests. Additionally, intrusion prevention systems (IPS) and rate-limiting techniques can restrict repeated requests from the same source, further protecting against this type of attack (Arbor Networks, 2021).

Notable instances of Slowloris attacks include its use during the Iranian presidential protests in 2009. Activists used the method to disrupt government websites, demonstrating its effectiveness as a low-resource attack to target online services (Cloudflare, 2021).

References
OWASP Slowloris Project (2021). "Slowloris DoS Attack Overview."
Ristic, I. (2013). ModSecurity Handbook.
CVE-2009-3555 Documentation.
Arbor Networks (2021). "DDoS Threat Reports."
Cloudflare (2021). "Understanding Slowloris DDoS Attack."



Task 3:

Tools Installed
BurpSuite Community Edition: Downloaded and installed from PortSwigger's official site.

For installation, I created a temporary project with default settings and accessed the dashboard.

Docker Desktop: Already installed and configured to run Docker containers.

Verified functionality by running the hello-world test image.

DVWA (Damn Vulnerable Web Application):

Pulled the DVWA image using:
code:
docker pull vulnerables/web-dvwa


Ran the container using:
code:
docker run --rm -it -p 80:80 vulnerables/web-dvwa

Confirmed that DVWA was accessible via http://localhost.


2. Setting Up DVWA

Accessed DVWA in the browser using http://127.0.0.1.

Logged in with the provided credentials:

Username: admin

Password: password

Initialized the DVWA database by clicking "Create / Reset Database" on the setup page.

Logged in again and confirmed the DVWA application was running.

3. BurpSuite Configuration

Opened the BurpSuite browser via Target > Open Browser and navigated to http://localhost.

Ensured BurpSuite Proxy was active and correctly intercepting traffic.

4. Subtask 1: Intercepting Traffic

Opened the Proxy tab in BurpSuite and turned interception ON.

Performed the following actions:

Attempted to log in with incorrect credentials to generate traffic.

Observed the intercepted requests in the HTTP history.

Logged in with correct credentials while interception was still active:

Username: admin

Password: password.

Intercepted the POST request and modified the User-Agent header to include:

Value: My name + a household item (e.g., User-Agent: Kettle).

5. Reviewing and Saving the Modified Request



Forwarded the modified POST request and completed the login process.

Turned interception OFF.

Reviewed the HTTP history to locate the modified request:

Switched to the Edited Request view to confirm the changes.

Captured screenshots showing:

Edited POST request in raw format.

HTTP history, including timestamps, methods, and ports.

6. Submission

Screenshots in the Repository

DVWA setup and database initialization.

Logged-in DVWA interface.

BurpSuite intercept settings.

Intercepted POST request before and after modification.

HTTP history showing timestamps and edited requests.



