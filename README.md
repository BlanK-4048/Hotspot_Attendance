# Smart Wi-Fi/Hotspot-Based Attendance System

## Automated Attendance System Using Python, Tkinter & Wireless MAC Detection

------------------------------------------------------------------------

## 📌 Overview

This project implements a **contactless attendance system** that detects
users based on their smartphone Wi-Fi hotspot presence. When users
enable their mobile hotspot, the system scans the network, retrieves
their MAC address, and marks attendance automatically.

No biometrics, RFID, QR scanning, or manual entry required.

------------------------------------------------------------------------

## ✅ Key Features

-   Automatic attendance marking
-   MAC address--based user identification
-   Register & remove user devices
-   Real-time scan & device detection
-   Export attendance logs (CSV)
-   Debug console with live events
-   Works **offline** -- no internet needed

------------------------------------------------------------------------

## 🧠 Tech Stack

  Component        Technology
  ---------------- ---------------------------
  Frontend / GUI   Tkinter (Python)
  Backend Logic    Python
  Networking       ARP, SSDP, Netsh, NBTSTAT
  Storage          CSV File
  OS Support       Windows

------------------------------------------------------------------------

## 🛠️ How It Works

1.  Register device with Name + MAC address
2.  User turns ON phone hotspot
3.  System scans Wi-Fi network and ARP cache
4.  Matches MAC with registered list
5.  Marks **Present / Absent**
6.  Logs stored & exportable

------------------------------------------------------------------------

## ▶️ Run Instructions

### Install Python Packages

``` bash
pip install tkinter
```

*(Tkinter usually comes with Python)*

### Run the Application

``` bash
python main.py
```

------------------------------------------------------------------------

## 📂 Project Structure

    📦 WiFi-Attendance-System
    ├── main.py
    ├── requirements.txt
    └── README.md

------------------------------------------------------------------------

## 📊 Sample Attendance Output

  Name    MAC                 Status    Timestamp
  ------- ------------------- --------- ---------------------
  Aarav   7C-DB-AC-XX-XX-12   Present   2025-11-02 09:10:34
  Riya    60-45-BE-XX-20-E1   Absent    2025-11-02 09:10:34

------------------------------------------------------------------------

## 🚀 Future Enhancements

-   Android companion app
-   Cloud database & analytics dashboard
-   Bluetooth-based attendance fallback
-   Face-recognition hybrid mode
-   Multi-classroom support
-   Bypass MAC randomization strategies

------------------------------------------------------------------------

## 🔐 Limitations

-   Works only with hotspot-enabled devices
-   MAC address randomization on some devices
-   Windows only (uses `netsh` & ARP cache)

------------------------------------------------------------------------

## 🤝 Contributions

Pull requests and suggestions are welcome!

------------------------------------------------------------------------

## 👨‍💻 Developed By

**Samik Sarkar**\
B.Tech CSE --- Wireless & Mobile Communication Project (2025)

------------------------------------------------------------------------

## 📜 License

Open-source for academic use.
