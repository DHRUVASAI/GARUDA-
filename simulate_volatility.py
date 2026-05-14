import os
import time

os.environ["GARUDA_DHCP_VOLATILE_RANGE"] = "192.168.1.200-192.168.1.250"
os.environ["GARUDA_ARP_NEW_MAC_MIN_SIGHTINGS"] = "2"
os.environ["GARUDA_ARP_OLD_MAC_MIN_SEC"] = "2"
os.environ["GARUDA_DB_PATH"] = "garuda_test.db"

import database
database.init_db()

conn = database.get_conn()
conn.execute("DELETE FROM alerts")
conn.execute("DELETE FROM arp_snapshots")
conn.execute("DELETE FROM devices")
conn.commit()
conn.close()

import monitor

def get_alerts():
    conn = database.get_conn()
    c = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

class MockNetSc:
    def __init__(self):
        self.table = {}
    def get_arp_table(self):
        return self.table
    def get_gateway(self):
        return "192.168.1.1"

monitor.net_sc = MockNetSc()

def run_arp_check(table_state):
    monitor.net_sc.table = table_state
    monitor.check_arp_spoofing()

def check_alerts(expected_count, test_name):
    alerts = get_alerts()
    arp_alerts = [a for a in alerts if a["type"] == "ARP_SPOOF"]
    if len(arp_alerts) == expected_count:
        print(f"PASS: {test_name}")
    else:
        print(f"FAIL: {test_name} (Expected {expected_count}, got {len(arp_alerts)})")

print("=== ARP SPOOFING REGRESSION ===")

# Baseline: Gateway at AA:11
print("1. Establishing baseline...")
run_arp_check({"192.168.1.1": "AA:11:11:11:11:11"})
time.sleep(3) # Wait > 2 seconds so span > 2
run_arp_check({"192.168.1.1": "AA:11:11:11:11:11"})
# Now AA:11 has a span > 2 sec

# MAC changes
print("2. First sighting of new MAC (should be blocked by sightings gate)...")
run_arp_check({"192.168.1.1": "00:22:22:22:22:22"})
check_alerts(0, "Sightings gate blocked alert")

# Second sighting of new MAC
print("3. Second sighting of new MAC (should pass gates & alert)...")
run_arp_check({"192.168.1.1": "00:22:22:22:22:22"})
check_alerts(1, "Alert successfully generated")

conn = database.get_conn()
conn.execute("DELETE FROM alerts")
conn.commit()
conn.close()

print("\n=== VOLATILE DHCP EXCLUSION ===")
run_arp_check({"192.168.1.205": "CC:33:33:33:33:33"})
time.sleep(3)
run_arp_check({"192.168.1.205": "CC:33:33:33:33:33"})
run_arp_check({"192.168.1.205": "DD:44:44:44:44:44"})
run_arp_check({"192.168.1.205": "DD:44:44:44:44:44"})
check_alerts(0, "Volatile DHCP range blocked alert")

print("\n=== RANDOMIZED MAC EXCLUSION ===")
run_arp_check({"192.168.1.10": "EE:55:55:55:55:55"})
time.sleep(3)
run_arp_check({"192.168.1.10": "EE:55:55:55:55:55"})
run_arp_check({"192.168.1.10": "02:66:66:66:66:66"})
run_arp_check({"192.168.1.10": "02:66:66:66:66:66"})
check_alerts(0, "Randomized MAC blocked alert")

print("\n=== THREAT INTELLIGENCE: PORT CHANGE ===")
conn = database.get_conn()
conn.execute("DELETE FROM alerts")
conn.commit()
conn.close()

monitor._last_port_state = {}
print("1. Baseline ports...")
monitor.check_port_changes({"192.168.1.50": [80, 443]})
print("2. Opening risky port 22 & 3389...")
monitor.check_port_changes({"192.168.1.50": [80, 443, 22, 3389]})
alerts = get_alerts()
pc_alerts = [a for a in alerts if a["type"] == "PORT_CHANGE"]
if pc_alerts:
    print(f"PASS: Risky port alert!")
else:
    print("FAIL: No risky port alert")

print("\n=== THREAT INTELLIGENCE: LATERAL MOVEMENT ===")
conn = database.get_conn()
conn.execute("DELETE FROM alerts")
conn.commit()
conn.close()

port_data = {
    "192.168.1.10": [22, 445],
    "192.168.1.11": [22, 445],
    "192.168.1.12": [22, 445],
    "192.168.1.13": [22, 445]
}
monitor.check_lateral_movement(port_data)
alerts = get_alerts()
lm_alerts = [a for a in alerts if a["type"] == "LATERAL_MOVEMENT"]
if lm_alerts:
    print(f"PASS: Lateral movement alert! ({len(lm_alerts)} alerts generated)")
else:
    print("FAIL: No lateral movement alert")

print("\n=== THREAT INTELLIGENCE: PERSISTENT THREAT ===")
conn = database.get_conn()
conn.execute("DELETE FROM alerts")
conn.commit()
conn.close()

database.save_alert("NEW_DEVICE", "MEDIUM", "Test1", "Test1", "192.168.1.100")
time.sleep(0.1)
database.save_alert("PORT_CHANGE", "MEDIUM", "Test2", "Test2", "192.168.1.100")
time.sleep(0.1)
database.save_alert("LATERAL_MOVEMENT", "HIGH", "Test3", "Test3", "192.168.1.100")

devices = [{"ip": "192.168.1.100", "type": "NODE"}]
monitor.check_persistent_threat(devices)
alerts = get_alerts()
pt_alerts = [a for a in alerts if a["type"] == "PERSISTENT_THREAT"]
if pt_alerts:
    print("PASS: Persistent threat alert!")
else:
    print("FAIL: No persistent threat alert")

print("\n=== ALL REGRESSION TESTS COMPLETED ===")
