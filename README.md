# Cocytus Framework

A zero-dependency, multi-language systems automation framework. Bridges native user-mode memory manipulation with a custom asynchronous controller interface and a remote telemetry infrastructure backend.

---

## 1. Unified Project Structure

```text
Cocytus/
├── .gitignore               # Multi-language build artifact exclusion rules
├── README.md                # Structural system documentation
├── CoreBridge.asm           # 64-bit raw MASM assembly direct kernel entry point
├── SysGateway.h             # Native C++ type definitions, hidden structs, and exports
├── SysGateway.cpp           # Runtime export parsing and dynamic SSN resolution logic
├── NativeBridge.pas         # Pascal raw function pointers mapping to native library exports
├── ServerController.pas     # Asynchronous Pascal HTTP infrastructure client 
├── MainForm.pas             # Desktop management panel user interface control module
├── config.php               # PDO database connectivity configuration context
├── auth.php                 # Asymmetric hardware fingerprint verification gate
└── telemetry.php            # Administrative operational log capture pipeline
```

---

## 2. Low-Level Subsystem Specifications

### Core Network Interface Mapping
The control panel is decoupled into modular layers to ensure native performance, cross-language compatibility, and clean data routing:

```text
[ MainForm.pas (UI Panel) ]
          │
          ├───► [ NativeBridge.pas ] ───► [ SysGateway.dll (C++/ASM) ] ───► Windows Kernel
          │
          └───► [ ServerController.pas ] ───► [ Remote Panel (PHP/MySQL) ]
```

### System Integrity Architecture
* **SysGateway Module:** Scrapes the raw export address table of `ntdll.dll` directly inside memory to map System Service Numbers (SSNs). Bypasses API hooks and monitors by routing memory allocations, reads, and writes through custom assembly stubs.
* **Controller Interface:** Operates as an event-driven control interface linking compiled system hooks to visual data logs and remote telemetry configurations.
* **Database Pipeline:** Handles persistent hardware authorization checks, unique execution session tracking tokens, and encrypted execution diagnostic dumps.

---

## 3. Toolchain & Development Environment Requirements

To compile and deploy the entire multi-language pipeline, you must install the following software suites and tools:

### C++ / Assembly Toolchain (SysGateway Module)
* **IDE:** Microsoft Visual Studio Community Edition (Select the "Desktop development with C++" workload during setup).
* **Compilers:** Microsoft Visual C++ (MSVC) + Microsoft Macro Assembler (MASM).
* **Target Environment:** Windows 10 / 11 SDK (Minimum Version 10.0.17763.0).
* **Download Resource:** [Visual Studio IDE Official Tools](https://microsoft.com)

### Delphi Toolchain (Visual Application Subsystem)
* **IDE:** Embarcadero RAD Studio / Delphi (Community or Professional Edition).
* **Framework:** VCL (Visual Component Library) Win64 Native Application.
* **Component Library:** System.Net.HttpClient (Included natively in modern Delphi runtimes).
* **Download Resource:** [Embarcadero RAD Studio & Delphi Tools](https://embarcadero.com)

### Web Deployment Backend (Telemetry Hub Panel)
* **Local Test Stack:** XAMPP (Bundles Apache Web Server, MariaDB/MySQL Database Engine, and PHP Interpreter).
* **Language Runtime:** PHP 8.1 or higher (Requires the PDO MySQL extension enabled inside `php.ini`).
* **Database Engine:** MySQL 8.0+ or MariaDB equivalent.
* **Download Resource:** [XAMPP Distribution Hub](https://apachefriends.org)

---

## 4. Setup & Compilation Guide

### Phase A: Compiling the Native Library (`SysGateway.dll`)
1. Launch **Visual Studio** and select **Create a new project**. Choose **Dynamic-Link Library (DLL)** using C++. Name the solution `SysGateway`.
2. Move `SysGateway.h` into your **Header Files** folder and `SysGateway.cpp` into your **Source Files** folder. Copy `CoreBridge.asm` into your project directory.
3. Enable assembly compilation: Right-click your project name in the Solution Explorer -> Select **Build Dependencies** -> Click **Build Customizations...** -> Check the box next to **masm (.targets, .props)** and hit OK.
4. Set assembly file properties: Right-click `CoreBridge.asm` -> Select **Properties** -> Under **Item Type**, select **Microsoft Macro Assembler**. Click Apply.
5. Set compilation architecture target: Set the top-level configuration dropdown menus to **Release** and **x64**.
6. Execute build: Press `Ctrl + Shift + B`. Your output binary file (`SysGateway.dll`) will generate in your solution's `x64\Release` directory.

### Phase B: Compiling the Controller Executable
1. Open **RAD Studio**, create a new **VCL Forms Application** project using Delphi, and target the **Windows 64-bit** platform.
2. In the Project Manager, right-click and add `NativeBridge.pas` and `ServerController.pas` into your project directory tree.
3. Open your project's main form unit file and replace the boilerplate structural code entirely with the logic inside `MainForm.pas`.
4. Compile the client: Build the project to generate your native executable application binary.
5. Link binaries: Copy your compiled `SysGateway.dll` directly into the directory where your Delphi executable file resides.

### Phase C: Configuring the Database and Server API Panel
1. Start the **Apache** and **MySQL** modules inside your local XAMPP control center.
2. Open your web browser and navigate to your database dashboard (typically `http://127.0.0`).
3. Run the following raw layout configuration script in your SQL terminal to build the infrastructure tables:

```sql
CREATE DATABASE IF NOT EXISTS framework_infrastructure;
USE framework_infrastructure;

CREATE TABLE IF NOT EXISTS system_nodes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    identity_hash VARCHAR(64) NOT NULL UNIQUE,
    status_state ENUM('AUTHORIZED', 'REVOKED') DEFAULT 'AUTHORIZED',
    tracking_group VARCHAR(50) DEFAULT 'DEFAULT_DEV',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS system_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    node_id INT NOT NULL,
    access_token VARCHAR(64) NOT NULL UNIQUE,
    expiration_stamp DATETIME NOT NULL,
    FOREIGN KEY (node_id) REFERENCES system_nodes(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS system_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    node_id INT NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    details_payload TEXT NOT NULL,
    logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (node_id) REFERENCES system_nodes(id) ON DELETE CASCADE
) ENGINE=InnoDB;
```

4. Create an entry to authorize your initial machine execution layout test instance (Replace `TARGET_HASH_HERE` with the SHA256 string matching your test environment's HWID):
```sql
INSERT INTO system_nodes (identity_hash, status_state, tracking_group) 
VALUES ('TARGET_HASH_HERE', 'AUTHORIZED', 'ADMIN_NODES');
```
5. Move `config.php`, `auth.php`, and `telemetry.php` directly into your web server's public document root directory (e.g., `C:\xampp\htdocs\backend\`).
6. Update the database credentials inside `config.php` to match your target MySQL system user privileges and host details.

---

## 5. Official Language Documentation Resources

For language references, structural standard updates, and native API specifications, consult the official documentation sources:

* **C++ Programming Standards:** [ISO International Standard for C++ Reference](https://isocpp.org)
* **Windows API Documentation:** [Microsoft Developer Network Win32 API Catalog](https://microsoft.com)
* **Delphi Object Pascal Guides:** [Embarcadero Documentation Portal & Language Reference](https://embarcadero.com)
* **PHP Language Reference Docs:** [PHP Official Documentation Engine Manual](https://php.net)
* **MySQL/MariaDB Storage Engine Reference:** [Oracle MySQL Document Reference Manual](https://mysql.com)

* **PHP Language Reference Docs:** [PHP Official Documentation Engine Manual](https://php.net)
* **MySQL/MariaDB Storage Engine Reference:** [Oracle MySQL Document Reference Manual](https://mysql.com)
