#  Wazuh Deployment 
## 1. Architecture
The system is deployed as an **All-in-one Centralized Manager**.
* **Wazuh Version:** 4.14.3
* **Operating System:** Ubuntu 22.04.5 LTS
* **Deployment Method:**  Wazuh's official installation assistant script, single-node mode.

## 2. Hardware Specifications
* **Instance:** 4 vCPUs, 8 GB RAM
* **Storage:** 500GB SSD

## 3. Architecture Diagram
The diagram illustrates the three logical zones of the deployment:

<a href="./wazuh_architecture_diagram.jpg">
  <img src="./wazuh_architecture_diagram.jpg" alt="Wazuh Architecture Diagram" width="800">
</a>


| Component | Port | Purpose |
|---|---|---|
| Agent → Server | 1514 (TCP/UDP) | Log forwarding |
| Agent → Server | 1515 (TCP) | Enrollment |
| Server → Indexer | 9200 | Filebeat → Indexer API |
| Dashboard ↔ Server | 55000 (TCP) | Management API |
| User → Dashboard | 443 (HTTPS) | Web access |

## 4. References
[`Wazuh Installation Guide`](https://documentation.wazuh.com/current/installation-guide/index.html)
