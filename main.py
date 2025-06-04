import simpy
import random
import numpy as np
import collections

# --- Global Parameters & Configuration ---
SIM_DURATION = 5000  # Simulation time units
NUM_NODES = 50
PERCENT_ATTACKERS_BLACKHOLE = 0.1
PERCENT_ATTACKERS_SELFISH = 0.1
PERCENT_ATTACKERS_RPL_RANK = 0.05  # New attacker type

RADIO_RANGE = 70  # meters
AREA_X, AREA_Y = 300, 300  # Simulation area dimensions

# DeSIST Game Payoffs (GFE)
PFG_SENDER_PAYOFFS = {
    ('Send', 'Cooperate'): 4,    # Reward for cooperation minus cost
    ('Send', 'Defect'): -11,     # Penalty for defection minus cost
    ('Hold', 'N/A'): -0.1        # Small penalty for holding/delaying
}

PSG_CHILD_WEIGHTS = {'rank': 0.5, 'stability': 0.3, 'link_quality': 0.2, 'change_penalty': -2}

IRG_REPORTER_PAYOFFS = {
    ('Report', 'ActualMisbehavior'): 5,
    ('Report', 'NormalBehavior'): -3,
    ('NoReport', 'ActualMisbehavior'): -2,
    ('NoReport', 'NormalBehavior'): 0
}

# Energy Costs (Joules - conceptual units)
E_TX_PKT = 0.05       # Transmit data packet
E_RX_PKT = 0.02       # Receive data packet
E_TX_CTRL = 0.01      # Transmit control packet
E_RX_CTRL = 0.005     # Receive control packet
E_SDU_COMPUTE = 0.001 # SDU decision cost
E_LIA_UPDATE = 0.0005 # LIA update cost
E_IDLE_LISTEN = 0.0001 # Per time unit idle listening

# --- Data Structures ---
class Packet:
    def __init__(self, packet_id, source_id, dest_id, creation_time, data="payload", p_type="DATA"):
        self.id = packet_id
        self.source_id = source_id
        self.dest_id = dest_id
        self.creation_time = creation_time
        self.data = data
        self.path = [source_id]
        self.current_hop_sender_id = None
        self.type = p_type  # DATA, DIO, DAO, DIS, ACK, REPORT

    def __repr__(self):
        return f"Pkt({self.id} T:{self.type} S:{self.source_id} D:{self.dest_id})"

# Statistics
STATS = {
    "packets_generated": 0,
    "packets_received_dest": 0,
    "packets_dropped_blackhole": 0,
    "packets_dropped_selfish": 0,
    "packets_dropped_other": 0,
    "total_delay": 0,
    "nodes_energy": {},
    "rpl_parent_changes": collections.defaultdict(int),
    "lia_pfg_outcomes": collections.defaultdict(lambda: collections.defaultdict(lambda: {'C': 0, 'D': 0})),
    "sdu_pfg_choices": collections.defaultdict(lambda: collections.defaultdict(int)),
    "sdu_psg_choices": collections.defaultdict(lambda: collections.defaultdict(int)),
    "irg_reports_made": collections.defaultdict(int),
    "control_packets_sent": collections.defaultdict(lambda: collections.defaultdict(int)),
}

# --- DeSIST Node Class ---
class IoTNode:
    def __init__(self, env, node_id, is_attacker_type=None):
        self.env = env
        self.id = node_id
        self.is_attacker_type = is_attacker_type
        self.radio_range = RADIO_RANGE
        self.position = (random.uniform(0, AREA_X), random.uniform(0, AREA_Y))
        self.neighbors = {}  # {node_id: node_object}
        self.energy = 100.0
        self.is_sink = (node_id == 0)
        self.alive = True

        # RPL Attributes
        self.rpl_parent_id = None
        self.rpl_rank = 0 if self.is_sink else float('inf')
        self.rpl_version_number = 0
        self.rpl_dio_interval = random.uniform(20, 40)
        self.rpl_last_dio_sent_time = -1

        # LIA Data Store
        self.lia_data = collections.defaultdict(lambda: {
            'pfg_last_outcome': None,
            'pfg_coop_count': 0,
            'pfg_defect_count': 0,
            'psg_last_rank_advertised': None,
            'psg_rank_stability_score': 1.0,
            'psg_dio_timestamps': collections.deque(maxlen=5),
            'irg_reported_as_malicious_count': 0,
            'link_quality_rssi': random.uniform(-80, -40)
        })

        self.packet_queue = simpy.Store(env)
        self.action = env.process(self.run())
        self.packet_id_counter = 0
        STATS["nodes_energy"][self.id] = self.energy

    def discover_neighbors(self, all_nodes):
        for other_node in all_nodes:
            if self.id == other_node.id:
                continue
            dist = np.sqrt((self.position[0] - other_node.position[0]) ** 2 +
                           (self.position[1] - other_node.position[1]) ** 2)
            if dist <= self.radio_range:
                self.neighbors[other_node.id] = other_node
                _ = self.lia_data[other_node.id]

    def consume_energy(self, cost_type, amount=None):
        if not self.alive:
            return
        cost_map = {
            'tx_pkt': E_TX_PKT,
            'rx_pkt': E_RX_PKT,
            'tx_ctrl': E_TX_CTRL,
            'rx_ctrl': E_RX_CTRL,
            'sdu': E_SDU_COMPUTE,
            'lia': E_LIA_UPDATE,
            'idle': E_IDLE_LISTEN
        }
        actual_cost = amount if amount is not None else cost_map.get(cost_type, 0)
        self.energy -= actual_cost
        STATS["nodes_energy"][self.id] = self.energy
        if self.energy <= 0:
            self.energy = 0
            self.alive = False
            self.action.interrupt("energy_depleted")

    # --- LIA Update Methods ---
    def lia_update_pfg(self, neighbor_id, outcome):
        self.consume_energy('lia')
        entry = self.lia_data[neighbor_id]
        entry['pfg_last_outcome'] = outcome
        if outcome == 'Cooperate':
            entry['pfg_coop_count'] += 1
        else:
            entry['pfg_defect_count'] += 1
        STATS['lia_pfg_outcomes'][self.id][neighbor_id][outcome[0]] += 1  # 'C' or 'D'

    def lia_update_psg_from_dio(self, sender_id, rank, version):
        self.consume_energy('lia')
        entry = self.lia_data[sender_id]
        entry['psg_dio_timestamps'].append(self.env.now)

        if entry['psg_last_rank_advertised'] is not None:
            if abs(rank - entry['psg_last_rank_advertised']) > 2:
                entry['psg_rank_stability_score'] *= 0.8
            else:
                entry['psg_rank_stability_score'] = min(1.0, entry['psg_rank_stability_score'] * 1.05 + 0.05)
        entry['psg_last_rank_advertised'] = rank

    def lia_get_pfg_p_cooperate(self, neighbor_id):
        self.consume_energy('lia')
        entry = self.lia_data[neighbor_id]
        total = entry['pfg_coop_count'] + entry['pfg_defect_count']
        if total == 0:
            return 0.5  # Neutral prior

        base_p_coop = entry['pfg_coop_count'] / total
        if entry['pfg_last_outcome'] == 'Defect':
            base_p_coop = max(0.01, base_p_coop * 0.3)
        elif entry['pfg_last_outcome'] == 'Cooperate':
            base_p_coop = min(0.99, base_p_coop * 1.1 + 0.2)
        return np.clip(base_p_coop, 0.01, 0.99)

    def lia_get_psg_parent_score(self, candidate_id, candidate_rank):
        self.consume_energy('lia')
        entry = self.lia_data[candidate_id]
        freq_penalty = 0.0
        if len(entry['psg_dio_timestamps']) >= 3:
            if (entry['psg_dio_timestamps'][-1] - entry['psg_dio_timestamps'][-3]) < 10:
                freq_penalty = -0.5

        score = PSG_CHILD_WEIGHTS['rank'] * (-candidate_rank) + \
                PSG_CHILD_WEIGHTS['stability'] * entry['psg_rank_stability_score'] + \
                PSG_CHILD_WEIGHTS['link_quality'] * (entry['link_quality_rssi'] / -40.0) + \
                freq_penalty
        return score

    # --- SDU Decision Methods ---
    def sdu_pfg_select_forwarder(self, packet, candidate_fw_ids):
        self.consume_energy('sdu')
        if not candidate_fw_ids:
            return None, 'Hold'

        best_fw_id = None
        max_eu = PFG_SENDER_PAYOFFS[('Hold', 'N/A')]
        action_taken = 'Hold'

        for fw_id in candidate_fw_ids:
            p_coop = self.lia_get_pfg_p_cooperate(fw_id)
            eu_send = (p_coop * PFG_SENDER_PAYOFFS[('Send', 'Cooperate')]) + \
                      ((1 - p_coop) * PFG_SENDER_PAYOFFS[('Send', 'Defect')])

            if eu_send > max_eu:
                max_eu = eu_send
                best_fw_id = fw_id
                action_taken = 'Send'

        STATS['sdu_pfg_choices'][self.id][best_fw_id if best_fw_id else 'Hold'] += 1
        return best_fw_id, action_taken

    def sdu_psg_select_parent(self, potential_parents_info):
        self.consume_energy('sdu')
        if not potential_parents_info:
            return None

        best_parent_id = None
        max_parent_utility = -float('inf')

        if self.rpl_parent_id is not None and self.neighbors.get(self.rpl_parent_id):
            current_parent_node = self.neighbors[self.rpl_parent_id]
            max_parent_utility = self.lia_get_psg_parent_score(self.rpl_parent_id, current_parent_node.rpl_rank)
            best_parent_id = self.rpl_parent_id

        for p_id, p_rank, p_version in potential_parents_info:
            if p_rank >= self.rpl_rank:
                continue

            utility = self.lia_get_psg_parent_score(p_id, p_rank)
            if p_id != self.rpl_parent_id:
                utility += PSG_CHILD_WEIGHTS['change_penalty']

            if utility > max_parent_utility:
                max_parent_utility = utility
                best_parent_id = p_id

        if best_parent_id != self.rpl_parent_id and best_parent_id is not None:
            STATS['rpl_parent_changes'][self.id] += 1

        STATS['sdu_psg_choices'][self.id][best_parent_id if best_parent_id else 'None'] += 1
        return best_parent_id

    def sdu_irg_decide_report(self, observed_node_id, suspected_behavior_type):
        self.consume_energy('sdu')
        if self.lia_data[observed_node_id]['pfg_defect_count'] >= 3 and \
           self.lia_data[observed_node_id]['pfg_coop_count'] < self.lia_data[observed_node_id]['pfg_defect_count']:
            if random.random() < 0.8:
                STATS['irg_reports_made'][self.id] += 1
                return True
        return False

    # --- Communication Methods ---
    def _send_message(self, target_node_obj, packet):
        self.consume_energy('tx_ctrl' if packet.type != "DATA" else "tx_pkt")
        STATS['control_packets_sent'][self.id][packet.type] += 1
        dist = np.sqrt((self.position[0] - target_node_obj.position[0]) ** 2 +
                       (self.position[1] - target_node_obj.position[1]) ** 2)
        delay = random.uniform(0.01, 0.05) * dist / 10
        yield self.env.timeout(delay)

        if random.random() < 0.02:
            return None

        return target_node_obj.env.process(target_node_obj._receive_message(packet, self.id))

    def _receive_message(self, packet, sender_id):
        if not self.alive:
            return False
        self.consume_energy('rx_ctrl' if packet.type != "DATA" else "rx_pkt")

        if packet.type == "DIO":
            self.handle_dio(packet, sender_id)
            return
        elif packet.type == "DATA":
            return self.handle_data_packet(packet, sender_id)
        elif packet.type == "ACK":
            self.handle_ack(packet, sender_id)
            return
        elif packet.type == "REPORT":
            self.handle_report(packet, sender_id)
            return
        return False

    # --- RPL Methods (Simplified) ---
    def broadcast_dio(self):
        if not self.alive:
            return
        self.rpl_last_dio_sent_time = self.env.now
        dio_packet = Packet(f"{self.id}-dio-{int(self.env.now)}", self.id, "BROADCAST", self.env.now,
                            data={'rank': self.rpl_rank, 'version': self.rpl_version_number}, p_type="DIO")
        for neighbor_node in self.neighbors.values():
            if neighbor_node.alive:
                self.env.process(self._send_message(neighbor_node, dio_packet))

    def handle_dio(self, dio_packet, sender_id):
        sender_rank = dio_packet.data['rank']
        sender_version = dio_packet.data['version']

        self.lia_update_psg_from_dio(sender_id, sender_rank, sender_version)

        if self.is_attacker_type == "rpl_rank":
            return

        new_parent_id = self.sdu_psg_select_parent([(sender_id, sender_rank, sender_version)])

        if new_parent_id and new_parent_id == sender_id:
            old_parent = self.rpl_parent_id
            self.rpl_parent_id = new_parent_id
            self.rpl_rank = sender_rank + 1  # Rank increment by 1 hop
            if old_parent != new_parent_id:
                STATS['rpl_parent_changes'][self.id] += 1

    # Placeholder for run method and other handlers (data packet, ack, report)
    def run(self):
        try:
            while self.alive:
                # Node main loop: send DIO periodically, process packets, etc.
                yield self.env.timeout(self.rpl_dio_interval)
                self.broadcast_dio()
        except simpy.Interrupt as interrupt:
            if str(interrupt.cause) == "energy_depleted":
                pass  # Node stops operation

    def handle_data_packet(self, packet, sender_id):
        # Simplified forwarding logic
        if self.id == packet.dest_id:
            STATS["packets_received_dest"] += 1
            delay = self.env.now - packet.creation_time
            STATS["total_delay"] += delay
            return True  # ACK success
        else:
            # Forward packet to best forwarder
            candidate_fw_ids = list(self.neighbors.keys())
            next_hop, action = self.sdu_pfg_select_forwarder(packet, candidate_fw_ids)
            if action == 'Send' and next_hop is not None:
                next_node = self.neighbors[next_hop]
                packet.path.append(self.id)
                self.env.process(self._send_message(next_node, packet))
                return True
            else:
                STATS["packets_dropped_selfish"] += 1
                return False

    def handle_ack(self, packet, sender_id):
        # ACK handling logic (if needed)
        pass

    def handle_report(self, packet, sender_id):
        # IRG report handling logic (if needed)
        pass