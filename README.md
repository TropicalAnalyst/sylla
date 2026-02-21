# SyllaApp - Open Source Analyst Intelligence platform

A lightweight, Python-based security application for managing and maintaining SOC Analyst's intelligence. SyllaApp helps teams track and store security incidents through a simple web interface. Perfect for small to all-sized organizations looking to maintain their own threat database without complex infrastructure.

## Features 

- **Threat Intelligence Management**: Collect and organize security indicators (IOCs)
- **Relationship Analysis**: Automatically discover connections between threats
- **Retention Management**: Automated cleanup of old data with configurable retention
- **User Management**: Role-based access control
- **Export/Import**: Backup and restore functionality
- **Incident Response Collaboration**: Bulk add IOCs to an incident in real time! 
- **Event Detection**: Rule-Based threat detection and alerting

![Dashboard](/Images/sylla1.png)

![Sources](/Images/Sylla2.png)

![Events](/Images/Sylla3.png)

![IR](/Images/Sylla4.png)

## Deploy with Docker

1. **Clone the repository**
   ```bash
   git clone https://github.com/TropicalAnalyst/sylla.git
   cd sylla
   ```
### Docker Compose (Recommended)

```bash
# Start SyllaApp
docker-compose up -d
```
When starting SyllaApp for the first time, a temporary password will be generated. Make sure to use the logs to look for it!
```bash

# Check docker logs
docker logs [ContainerID]

# To get the contaienr ID use the below command
docker ps
```


```bash
# Stop SyllaApp
docker-compose down
```

## Accessing the Application

1. Open your browser to `http://localhost:8000`
2. Log in with default credentials:
   - Username: `sylla`
   - Password: `Auto-Generated - Check Logs`
3. **Important**: Change the password after first login!