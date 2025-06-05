# DeSIST: Emergent Security in IoT - Simulation Framework

This repository contains a Python-based simulation framework for the "DeSIST: Emergent Security in IoT through Decentralized Strategic Interactions - A Game-Theoretic Zero Trust Framework" paper. The simulation models IoT nodes making decentralized decisions based on game theory to enhance network security and resilience against common attacks.

**Paper:** (UNDER REVIEW)
*DeSIST: Emergent Security in IoT through Decentralized Strategic Interactions - A Game-Theoretic Zero Trust Framework*
Seyed Hossein Ahmadpanah, Meghdad Mirabi, Sanaz Sobhanloo, Pania Afsharfarnia, Donya Fallah

## Table of Contents

1.  [Introduction](#introduction)
2.  [Core DeSIST Concepts Modeled](#core-desist-concepts-modeled)
    *   [Game Formulation Engine (GFE)](#game-formulation-engine-gfe)
    *   [Local Information Assessor (LIA)](#local-information-assessor-lia)
    *   [Strategic Decision Unit (SDU)](#strategic-decision-unit-sdu)
    *   [Interaction Games](#interaction-games)
3.  [Features](#features)
4.  [Simulation Components](#simulation-components)
5.  [Requirements](#requirements)
6.  [How to Run](#how-to-run)
7.  [Configuration Parameters](#configuration-parameters)
8.  [Output and Statistics](#output-and-statistics)
9.  [Limitations](#limitations)
10. [Future Work & Contributions](#future-work--contributions)
11. [License](#license)

## Introduction

The DeSIST framework proposes a novel approach to IoT security by leveraging game theory and Zero Trust principles. Instead of relying on explicit trust scores or centralized authorities, individual IoT nodes act as rational agents. They make decisions to maximize their own expected utility in various interactions (like packet forwarding or parent selection in RPL). Security emerges organically as these game-theoretic interactions incentivize cooperative behavior among legitimate devices and lead to the strategic isolation of malicious or non-compliant actors.

This simulation implements key aspects of DeSIST to evaluate its performance under different network conditions and attack scenarios.

## Core DeSIST Concepts Modeled

The simulation embodies the core architectural components of DeSIST within each `IoTNode`:

### Game Formulation Engine (GFE)

The GFE defines the "rules of engagement" for interactions. In this simulation, the GFE is implicitly represented by:
*   Pre-defined payoff matrices and utility weights (e.g., `PFG_SENDER_PAYOFFS`, `PSG_CHILD_WEIGHTS`, `IRG_REPORTER_PAYOFFS`).
*   The defined strategies available to nodes in different game scenarios.

### Local Information Assessor (LIA)

Each node's LIA gathers immediate, local, and contextual information about its neighbors and interactions.
*   **Functionality:** Implemented through methods like `lia_update_pfg`, `lia_update_psg_from_dio`, `lia_get_pfg_p_cooperate`, `lia_get_psg_parent_score`.
*   **Data Store:** `self.lia_data` in `IoTNode` stores short-term memory about neighbors (e.g., last PFG outcome, cooperation/defection counts, RPL rank stability).
*   **Minimal State:** The LIA focuses on recent events to keep the overhead low, crucial for resource-constrained IoT devices.

### Strategic Decision Unit (SDU)

The SDU is the "brain" of the node, making decisions to maximize expected utility based on LIA data and GFE rules.
*   **Functionality:** Implemented through methods like `sdu_pfg_select_forwarder`, `sdu_psg_select_parent`, `sdu_irg_decide_report`.
*   **Decision Making:** Uses expected utility maximization (e.g., calculating expected utility of sending a packet via a specific neighbor in PFG).

### Interaction Games

The simulation models several key IoT interactions as strategic games:

1.  **Packet Forwarding Game (PFG):**
    *   **Players:** A sender node and a potential next-hop forwarder.
    *   **Sender Strategies:** 'Send' to a specific forwarder, 'Hold' (or choose alternative).
    *   **Forwarder Strategies (implicit):** 'Cooperate' (forward correctly), 'Defect' (drop/modify/delay).
    *   **SDU Logic:** `sdu_pfg_select_forwarder` selects the forwarder maximizing expected utility.
    *   **LIA Logic:** `lia_update_pfg` updates based on observed outcomes (e.g., ACK received or not, inferred from higher layers).

2.  **RPL Parent Selection Game (PSG):**
    *   **Players:** A child node and potential parent nodes advertising RPL DIO messages.
    *   **Child Strategies:** Select one of the candidates as a parent.
    *   **Parent Strategies (implicit):** 'HonestAdvertiser', 'DeceptiveAdvertiser' (e.g., false rank, unstable version).
    *   **SDU Logic:** `sdu_psg_select_parent` selects the parent maximizing a utility score based on rank, stability, link quality, etc.
    *   **LIA Logic:** `lia_update_psg_from_dio` processes DIOs, `lia_get_psg_parent_score` provides input to SDU.

3.  **Information Reporting Game (IRG) (Basic):**
    *   **Players:** An observing node, a potentially misbehaving node, and a recipient of the report (implicit network).
    *   **Observer Strategies:** 'ReportMisbehavior', 'DoNotReport'.
    *   **SDU Logic:** `sdu_irg_decide_report` makes a probabilistic decision to report based on repeated negative interactions.
    *   **Payoffs:** Defined in `IRG_REPORTER_PAYOFFS`.

## Features

*   **Discrete-Event Simulation:** Built using the `SimPy` library.
*   **DeSIST Node Model:** Implements LIA and SDU logic for game-theoretic decision-making.
*   **Network Model:**
    *   Nodes deployed randomly in a 2D area.
    *   Radio range-based neighbor discovery.
    *   Simplified packet transmission with probabilistic loss and delay.
*   **RPL-like Protocol:** Basic DIO broadcasting and parent selection logic influenced by DeSIST's PSG.
*   **Attacker Models:**
    *   **Blackhole Attacker:** Attracts traffic (e.g., by advertising good RPL rank) and drops all data packets. (Implicitly handled by PFG if attacker drops packets).
    *   **Selfish Node:** May drop packets to conserve energy if its PFG utility for defecting is higher.
    *   **RPL Rank Attacker:** Advertises a consistently false (attractive) rank.
*   **Energy Consumption Model:** Tracks energy for transmitting, receiving, SDU/LIA computations, and idle listening.
*   **Statistics Collection:** Gathers metrics on packet delivery, energy, delays, and DeSIST-specific behaviors.

## Simulation Components

The core logic is contained within `main.py`:

*   **`Packet` Class:** Represents data and control packets traversing the network.
*   **`IoTNode` Class:** The main class representing an IoT device. It encapsulates:
    *   Node properties (ID, position, energy, neighbors).
    *   RPL attributes (parent, rank, DIO logic).
    *   LIA data structures and update methods.
    *   SDU decision-making algorithms for PFG, PSG, IRG.
    *   Communication methods (`_send_message`, `_receive_message`).
    *   SimPy process `run()` for its main operational loop.
*   **Global Parameters:** Configuration settings at the top of the script (e.g., `NUM_NODES`, attacker percentages, payoffs, energy costs).
*   **`STATS` Dictionary:** A global dictionary used to collect various simulation metrics.
*   **Setup and Execution Functions:**
    *   `generate_attackers()`: Assigns attacker roles to nodes.
    *   `setup_environment()`: Initializes the SimPy environment, creates nodes, and discovers neighbors.
    *   `run_simulation()`: Starts and runs the SimPy simulation.
    *   `print_stats()`: Calculates and prints key performance indicators after the simulation.

## Requirements

*   Python 3.7+
*   SimPy (`pip install simpy`)
*   NumPy (`pip install numpy`)

## How to Run

1.  Ensure you have Python and the required libraries installed.
2.  Save the code as a Python file (e.g., `desist_simulation.py`).
3.  Run the simulation from your terminal:
    ```bash
    python main.py
    ```
4.  The simulation will run for the configured `SIM_DURATION` and then print the collected statistics.

## Configuration Parameters

Key parameters can be adjusted at the top of the `desist_simulation.py` script:

*   **Simulation Time & Scale:**
    *   `SIM_DURATION`: Total simulation time units.
    *   `NUM_NODES`: Number of IoT nodes in the network.
    *   `AREA_X`, `AREA_Y`: Dimensions of the simulation area.
    *   `RADIO_RANGE`: Communication range of nodes.
*   **Attacker Configuration:**
    *   `PERCENT_ATTACKERS_BLACKHOLE`: Percentage of nodes acting as blackhole attackers.
    *   `PERCENT_ATTACKERS_SELFISH`: Percentage of nodes acting as selfish forwarders.
    *   `PERCENT_ATTACKERS_RPL_RANK`: Percentage of nodes manipulating RPL rank.
*   **DeSIST Game Payoffs:**
    *   `PFG_SENDER_PAYOFFS`: Defines utilities for the Packet Forwarding Game.
    *   `PSG_CHILD_WEIGHTS`: Defines weights for factors in RPL Parent Selection Game.
    *   `IRG_REPORTER_PAYOFFS`: Defines utilities for the Information Reporting Game.
*   **Energy Model:**
    *   `E_TX_PKT`, `E_RX_PKT`, etc.: Energy costs for various operations.
*   **RPL Parameters:**
    *   `rpl_dio_interval`: Base interval for DIO broadcasts.

Experiment with these parameters to observe their impact on network performance and security.

## Output and Statistics

After the simulation completes, `print_stats()` will output key metrics, including:

*   **Packet Delivery Ratio (PDR):** `(packets_received_dest / packets_generated)`
*   **Average End-to-End Delay:** For successfully delivered packets.
*   **Packets Dropped:** Categorized by blackhole, selfish, or other reasons.
*   **Average Energy Consumed per Node:**
*   **Network Lifetime Indicator:** Number of nodes still alive at the end.
*   **RPL Parent Changes:** Average number of parent changes per node.
*   **LIA PFG Outcomes:** Counts of Cooperate/Defect observations.
*   **SDU PFG/PSG Choices:** Counts of specific forwarder/parent selections.
*   **IRG Reports Made:** Number of malicious behavior reports initiated.
*   **Control Packets Sent:** Counts of different control packet types (DIO, ACK, etc.).

The raw counts are stored in the global `STATS` dictionary.

## Limitations

This simulation, while capturing core DeSIST mechanics, has certain simplifications:

*   **MAC Layer:** No explicit MAC layer (e.g., CSMA/CA, collisions) is modeled. Packet transmission success is probabilistic or assumes ideal channel access.
*   **RPL Complexity:** The RPL implementation is simplified, focusing on DIOs and parent selection, omitting features like DAO/DIS messages, DODAG maintenance details, or complex loop avoidance.
*   **Idealized LIA Inputs:** The LIA's ability to perfectly discern outcomes (e.g., whether a packet was truly dropped by a specific neighbor vs. lost due to channel error) is assumed for PFG updates.
*   **Static Payoffs:** Game payoffs are static. In a real-world scenario, these might need to be adaptable.
*   **Limited Attacker Sophistication:** Does not currently model highly sophisticated attacks like collusion among multiple attackers or advanced Sybil attacks.
*   **No Cryptography:** Assumes underlying mechanisms for identity or message integrity if needed by specific LIA/SDU logic (though DeSIST primarily focuses on behavioral trust).
*   **IRG Implementation:** The Information Reporting Game is basic; a full implementation would require defined report recipients and consequences.

## Future Work & Contributions

This framework can be extended in several ways:

*   **Advanced Attacker Models:** Implement colluding attackers, Sybil attacks, more sophisticated RPL manipulations (e.g., version number attacks).
*   **Dynamic Payoff Calibration:** Explore mechanisms for nodes to adapt their payoff matrices based on network conditions or observed global behavior.
*   **More Realistic Network Layers:** Integrate a more detailed MAC layer or physical layer model.
*   **Enhanced LIA/SDU:** Implement more sophisticated learning or inference mechanisms within LIA/SDU (e.g., Bayesian updates, simple machine learning).
*   **Visualization:** Add dynamic visualization of network topology, packet flows, and attacker isolation.
*   **Comparative Analysis:** Benchmark DeSIST against traditional security mechanisms or other trust management systems within this framework.
*   **Handling Irrationality:** Explore DeSIST's resilience when some nodes behave irrationally or are faulty.

Contributions are welcome! Please feel free to fork the repository, make improvements, and submit pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

