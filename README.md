# 🕵️‍♂️ Threat Hunt Report: Unauthorized TOR Usage

**Detection Objective:**  
Detection of Unauthorized TOR Browser Installation and Use on Workstation: `________________`

---

## 📚 Scenario Summary

**Context:**  
Management suspects that employees may be using the TOR browser to circumvent corporate security policies. Network telemetry has shown encrypted traffic matching TOR fingerprint patterns, including potential connections to known TOR entry nodes. Anonymous internal reports have suggested some staff may be accessing restricted content during work hours.

**Objective:**  
Detect TOR browser installation or usage across endpoints and network logs using Microsoft Defender for Endpoint and Log Analytics, and initiate a response if TOR usage is confirmed.

---

## 🔍 High-Level IoC Discovery Plan

| Indicator Type         | Action Taken                                           |
|------------------------|--------------------------------------------------------|
| File Activity          | Searched `DeviceFileEvents` for `tor.exe` or `firefox.exe` |
| Process Execution      | Searched `DeviceProcessEvents` for TOR-related processes |
| Network Traffic        | Searched `DeviceNetworkEvents` for known TOR ports (e.g., 9001, 9030, 9050) and IPs  |

---

## 🛠️ Steps Taken

1. Queried the `DeviceFileEvents` table for creation and execution of suspicious TOR binaries:
   ```kql
   DeviceFileEvents
   | where FileName has_any ("tor.exe", "firefox.exe")
   ```

2. Queried `DeviceProcessEvents` for runtime evidence of TOR-related applications:
   ```kql
   DeviceProcessEvents
   | where ProcessCommandLine has_any ("tor", "firefox") 
   | where InitiatingProcessCommandLine has "Users"
   ```

3. Queried `DeviceNetworkEvents` for TOR port usage:
   ```kql
   DeviceNetworkEvents
   | where RemotePort in (9001, 9030, 9050)
   | where InitiatingProcessFileName has_any ("tor.exe", "firefox.exe")
   ```

4. Correlated suspicious timestamps across tables to build a timeline of events

5. Verified activity against public lists of TOR entry nodes

---

## ⏱️ Chronological Events

| Time (UTC) | Event Type        | Details |
|------------|-------------------|---------|
| 2024-10-16 09:12 | File Execution     | `tor.exe` executed from `C:\Users\...\Downloads` |
| 2024-10-16 09:13 | Process Initiated | PowerShell script initiated `tor.exe` |
| 2024-10-16 09:14 | Network Event     | Outbound connection on port 9050 to `185.220.101.4` (TOR node) |

---

## ✅ Summary

- TOR browser (`tor.exe`) was downloaded and executed from a user directory.
- Device established outbound connections on TOR-related ports (9050) to known exit node IPs.
- User account: `j.doe@company.com`
- Device involved: `workstation-001`

---

## 🚨 Response Taken

- TOR usage was **confirmed** on endpoint `workstation-001`.
- The device was **isolated** using Microsoft Defender for Endpoint.
- The user's **direct manager was notified**.
- Evidence logs have been archived and retained for HR and legal review.

---

## 📎 Attachments / Artifacts

- [KQL Queries Used](#)
- [Device Timeline Export (.csv)](#)
- [TOR Entry Node IP List](https://check.torproject.org/torbulkexitlist)

---

**Report Completed By:**  
