# Powerkatz — Powerful Mimikatz (Version 1.0)

<div align="center">
    <img src="./src/core/static/img/Powerkatz_logo_alt.png" alt="Powerkatz logo" style="width:25%;">
</div>

## Table of Contents

- [💬 Introduction](#-introduction)
- [✨ Features](#-features)
- [📥 Installation](#-installation)
    - [🖥️ Debian / Kali Linux](#%EF%B8%8F-debian--kali-linux)
- [🚀 Start Powerkatz](#-start-powerkatz)
- [🎬 Demonstration](#-demonstration)
- [🎯 Todo](#-todo)

## 💬 Introduction

Powerkatz (Powerful Mimikatz) is a user-friendly Web-UI tool that aims to **reduce penetration testers' workload** and **lower [Mimikatz](https://github.com/gentilkiwi/mimikatz)'s learning difficulty**.

## ✨ Features

- Automatically load [Invoke-Mimikatz.ps1](https://github.com/clymb3r/PowerShell/blob/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1) into memory
- Automatically dump and crack password hashes
- Automatically gather compromised targets' information 
- Automatically setup tunneling via [Ligolo-ng](https://github.com/nicocha30/ligolo-ng) for lateral movement
- Intuitive Web-UI (***THREE steps*** to perform desired actions)
- Most Mimikatz parameters are autofilled
- Present Mimikatz outputs in a user-friendly manner

## 📥 Installation

To install Powerkatz, you can copy and paste the following Bash commands to your terminal:

### 🖥️ Debian / Kali Linux

```bash
git clone https://github.com/siunam321/powerkatz.git
cd powerkatz/
./install.sh
```

## 🚀 Start Powerkatz

After that, you can execute the following Bash command to start the Powerkatz application:

```bash
./powerkatz
```

## 🎬 Demonstration

https://github.com/siunam321/powerkatz/assets/104430134/65701c75-5a53-438f-8d1a-73a534ad56e4

## 🎯 Todo

- History command replay and compare previous history result
- Execute attack functions on Executor's agents
- Generate findings report
- Real-time notification system
