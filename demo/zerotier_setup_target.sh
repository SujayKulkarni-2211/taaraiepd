#!/data/data/com.termux/files/usr/bin/bash
# TAARA Demo — Target Setup (run once on Termux/phone)
# Creates realistic sensitive data for the demo scenario.

echo "=== TAARA ZeroTier Demo — Target Setup ==="

mkdir -p ~/company_data/customers ~/company_data/finance ~/company_data/config

cat > ~/company_data/customers/customer_db.csv << 'EOF'
id,name,email,phone,contract_value
C001,Rajiv Mehta,rajiv@infratech.in,9876543210,4500000
C002,Priya Sharma,priya@fincore.in,9845123456,2200000
C003,Arjun Nair,arjun@govtech.in,9912345678,8900000
C004,Sunita Rao,sunita@healthplus.in,9823456789,1750000
EOF

cat > ~/company_data/finance/q1_revenue.txt << 'EOF'
GoodWinSun Q1 2026 — CONFIDENTIAL
Total Revenue: ₹4.2 Cr
Projected Q2: ₹6.8 Cr
Active Contracts: 14
Pending: 3
EOF

cat > ~/company_data/config/app_config.json << 'EOF'
{
  "db_host": "10.10.1.15",
  "db_port": 5432,
  "db_user": "admin",
  "db_pass": "gws_prod_2026",
  "api_secret": "sk-gws-7f3a9b2c1d4e8f2a",
  "env": "production"
}
EOF

cat > ~/company_data/config/access.log << 'EOF'
2026-05-19 09:12:03 INFO  user=rajiv action=login ip=10.10.1.5
2026-05-19 09:15:44 INFO  user=priya action=view_report ip=10.10.1.8
2026-05-19 10:02:11 INFO  user=admin action=config_read ip=10.10.0.1
EOF

echo "[+] Company data ready:"
find ~/company_data -type f | sort
echo ""
echo "ZeroTier IP: 10.248.248.67"
echo "SSH port: 8022"
echo "Setup complete."
