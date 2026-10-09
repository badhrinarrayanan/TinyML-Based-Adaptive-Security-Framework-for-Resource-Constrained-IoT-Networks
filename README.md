# TinyML-Based Adaptive Security Framework for Resource-Constrained IoT Networks

An ESP32-based IoT security prototype that combines edge-based threat detection with adaptive cryptographic protection.

The framework monitors network behaviour, executes a four-class XGBoost model on an ESP32-S3 Edge-AI Hub, and selects a security profile based on the estimated threat level.

## Hardware Setup

![Hardware setup of the ESP32-based adaptive security framework](assets/hardware-setup.jpg)

*Experimental hardware setup with ESP32-based devices and the wireless communication environment.*

## Dashboard Demonstration

The dashboard displays network telemetry, threat-score changes, the selected security policy, cryptographic status, and serial logs from the connected devices.

### Normal Security State

![Normal security state](assets/dashboard-normal.png)

**Policy:** AES-128-GCM

### Elevated Security State

![Elevated security state](assets/dashboard-elevated.png)

**Policy:** AES-256-GCM

### Critical Security State

![Critical security state](assets/dashboard-critical.png)

**Policy:** ML-KEM-512 key establishment with AES-256-GCM

> All public screenshots must use demonstration data and must not expose shared secrets, private keys, credentials, or other sensitive material.

## Project Objectives

- Monitor network traffic and radio-related behaviour on an IoT network.
- Extract lightweight traffic features for threat assessment.
- Perform local machine-learning inference on an ESP32-S3.
- Convert model probabilities into a weighted threat score.
- Adapt the cryptographic security profile according to the estimated threat condition.
- Evaluate classification performance and embedded communication behaviour.

## System Architecture

```text
ESP32 IoT Node
      |
      | Sensor and network traffic
      v
Linux Relay
      |
      | Forwarded traffic
      v
ESP32-S3 Edge-AI Hub
      |
      v
12-Feature Extraction
      |
      v
Embedded XGBoost Classifier
      |
      v
Weighted Threat Score
      |
      v
Adaptive Security Policy
      |
      +-- NORMAL   -> AES-128-GCM
      |
      +-- ELEVATED -> AES-256-GCM
      |
      +-- CRITICAL -> ML-KEM-512
                       +
                     AES-256-GCM
```

## Hardware and Software

### Hardware

- ESP32 development board — protected IoT node
- ESP32-S3 development board — Edge-AI security hub
- MQ-series gas/smoke sensor interface
- Linux computer for traffic relay and controlled network experiments
- Wi-Fi network and USB serial connections

### Software and Technologies

- Embedded C/C++
- ESP32 Arduino framework
- PlatformIO and Visual Studio Code
- Python and XGBoost for model development
- Embedded C/C++ model implementation
- UDP communication
- AES-GCM authenticated encryption
- ML-KEM-512 key establishment
- HTML, CSS and JavaScript for the monitoring dashboard, where applicable

## Machine Learning Model

The final four-class XGBoost model uses 12 network and radio features:

- RSSI mean, variance, minimum, maximum and range
- Packet loss
- Inter-arrival-time mean, variance, minimum and maximum
- Packet rate
- Invalid packet count

The classifier predicts four traffic classes:

| Class | Meaning |
|---|---|
| NORMAL | Normal traffic conditions |
| LOW | Low abnormality level |
| MEDIUM | Medium abnormality level |
| HIGH | High abnormality level |

The predicted class probabilities are converted into a weighted threat score. The adaptive policy engine then maps that score to one of three security profiles.

## Reported Model Performance

The final four-class XGBoost evaluation reported the following results on a held-out test set:

| Metric | Result |
|---|---:|
| Accuracy | 95.83% |
| Precision | 95.91% |
| Recall | 95.83% |
| F1-score | 95.83% |

The evaluation used a dataset of 479 samples and an 80:20 stratified train-test split.

These figures describe the reported test-set classification results; they do not establish equivalent detection performance across all real-world networks or attack types.

## Repository Structure

- `FInal_Hub/` — ESP32-S3 hub firmware and its PlatformIO configuration.
- `Final_Node/` — ESP32 node firmware and its PlatformIO configuration.
- `assets/` — Hardware photographs and sanitized dashboard screenshots.
- `README.md` — Project documentation.

## Build and Run

1. Install Visual Studio Code and the PlatformIO extension.
2. Open the hub and node projects separately.
3. Verify the board configuration and required libraries in each `platformio.ini`.
4. Configure the network addresses and communication settings for your test environment.
5. Build and upload the node firmware to the ESP32.
6. Build and upload the hub firmware to the ESP32-S3.
7. Start the Linux relay and configure the dashboard connection as required by your implementation.
8. Monitor serial output and test the normal, elevated and critical security states.

Refer to the source code for the exact configuration and execution requirements.

## Limitations

- The training dataset contains a limited number of experimentally generated samples.
- Generalization to unseen attack types and different network environments requires further evaluation.
- The threat-score thresholds are specific to the experimental implementation.
- The Linux relay provides controlled network conditions and does not represent every real-world attacker.
- Production deployment would require appropriate key management, secure key storage, and broader security validation.

## Future Work

- Evaluate additional network conditions and unseen attack scenarios.
- Measure inference latency, RAM usage, flash usage and energy consumption on the target hardware.
- Improve cryptographic key lifecycle management.
- Conduct longer-duration reliability and communication tests.

## Academic Project

Developed as a mini project for Artificial Intelligence and Machine Learning for Electronic Engineering.

**Focus areas:** Embedded Systems, TinyML, IoT Security, Edge AI, Adaptive Cryptography and Post-Quantum Cryptography.
