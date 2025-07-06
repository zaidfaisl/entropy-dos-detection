# Entropy-Based DoS Attack Detection in SDN

This project implements a detection mechanism for SYN Flood DoS attacks in Software-Defined Networks (SDN) using entropy analysis. The system calculates entropy values in real-time via the Ryu controller and classifies network behavior based on dynamic thresholds.

## 🔧 Features
- Detection of SYN Flood attacks using entropy drop analysis
- Real-time monitoring with Mininet and Ryu
- Dynamic threshold calculation from baseline entropy
- Logging of entropy values and classification decisions
- Evaluation using confusion matrix and CPU usage metrics

## 📁 Project Structure

```
controller_code/         → Ryu controller files (entropy logic)
traffic_generation/      → Scripts for normal and attack traffic
mininet_topology/        → Tree topology generator script
results/                 → CSV output files of entropy values
figures/                 → Plots and confusion matrix figures
appendices/              → Supplemental data and configurations
```

## ⚙️ Requirements

- Python 3.x  
- Mininet  
- Ryu Controller  
- Scapy  
- hping3  
- matplotlib  
- pandas

Install dependencies:
```bash
pip install -r requirements.txt
```

## ▶️ How to Run

1. Start the Mininet topology:
```bash
sudo sudo mn --topo=tree,depth=2,fanout=3 --controller=remote --mac
```

2. Launch the Ryu controller:
```bash
ryu-manager controller_code/entropy_controller.py
```

3. Run traffic generation:
in host run:
```bash
sudo python3 traffic_generation/normal_traffic.py

```

4. Monitor output in `results/` directory and visualize results from `figures/`.

## 📊 Evaluation

The detection performance was evaluated using accuracy, precision, recall, F1-score, and CPU usage. See the `report.pdf` and `appendices/` folder for full details.

## 📄 License

This project is developed as part of a graduation thesis and is open for educational purposes.
