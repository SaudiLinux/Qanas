# واجهة برمجة التطبيقات (API) لـ Qanas

## نظرة عامة

توفر Qanas واجهة برمجة تطبيقات (API) تتيح للمطورين دمج وظائف المسح والاستطلاع في تطبيقاتهم الخاصة. يمكن استخدام هذه الواجهة لأتمتة عمليات المسح، وتكامل النتائج مع أنظمة أخرى، وبناء واجهات مستخدم مخصصة.

## الاستخدام الأساسي

### استيراد المكتبة

```python
# استيراد المكتبة الرئيسية
from qanas import Qanas

# استيراد وحدات محددة
from qanas.modules import port_scanner, web_scanner, dns_scanner, vuln_scanner, recon_scanner
```

### إنشاء كائن Qanas

```python
# إنشاء كائن Qanas مع الإعدادات الافتراضية
scanner = Qanas()

# إنشاء كائن Qanas مع إعدادات مخصصة
scanner = Qanas(
    output_dir="/path/to/custom/output",
    scan_mode="airstrike",
    verbose=True,
    threads=10
)
```

### إجراء عملية مسح

```python
# مسح هدف واحد
results = scanner.scan_target("example.com")

# مسح عدة أهداف
targets = ["example.com", "192.168.1.1", "subdomain.example.org"]
results = scanner.scan_multiple_targets(targets)

# مسح أهداف من ملف
results = scanner.scan_targets_from_file("/path/to/targets.txt")
```

### الوصول إلى النتائج

```python
# الوصول إلى نتائج المسح
port_results = results.get('port_scan', {})
web_results = results.get('web_scan', {})
dns_results = results.get('dns_scan', {})
vuln_results = results.get('vuln_scan', {})
recon_results = results.get('recon', {})

# طباعة المنافذ المفتوحة
for port, service in port_results.get('open_ports', {}).items():
    print(f"Port {port}: {service}")

# الوصول إلى الثغرات المكتشفة
for vuln in vuln_results.get('vulnerabilities', []):
    print(f"Vulnerability: {vuln['name']} - Severity: {vuln['severity']}")
```

### توليد تقارير

```python
# توليد تقرير HTML
scanner.generate_html_report(results, "/path/to/report.html")

# توليد تقرير JSON
scanner.export_to_json(results, "/path/to/report.json")

# توليد تقرير XML
scanner.export_to_xml(results, "/path/to/report.xml")
```

## استخدام الوحدات بشكل منفصل

### مسح المنافذ

```python
from qanas.modules import port_scanner

# إجراء مسح سريع للمنافذ
results = port_scanner.quick_scan("192.168.1.1")

# إجراء مسح كامل للمنافذ
results = port_scanner.full_scan("example.com", ports="1-65535")

# استخدام Masscan للمسح السريع
results = port_scanner.masscan_scan("192.168.1.0/24", ports="22,80,443,8080")
```

### مسح تطبيقات الويب

```python
from qanas.modules import web_scanner

# إجراء مسح شامل لتطبيق ويب
results = web_scanner.comprehensive_web_scan("https://example.com")

# مسح باستخدام أدوات محددة
whatwebResults = web_scanner.whatweb_scan("https://example.com")
niktoResults = web_scanner.nikto_scan("https://example.com")
dirbResults = web_scanner.dirb_scan("https://example.com")

# اكتشاف نظام إدارة المحتوى
cms = web_scanner.detect_cms("https://example.com")
if cms == "wordpress":
    wpResults = web_scanner.wpscan("https://example.com")
```

### استطلاع DNS

```python
from qanas.modules import dns_scanner

# إجراء مسح شامل لـ DNS
results = dns_scanner.comprehensive_dns_scan("example.com")

# استخراج سجلات DNS محددة
records = dns_scanner.get_dns_records("example.com", record_type="A")

# اكتشاف النطاقات الفرعية
subdomains = dns_scanner.enumerate_subdomains("example.com")

# محاولة نقل المنطقة
zone_transfer = dns_scanner.attempt_zone_transfer("example.com")
```

### اكتشاف الثغرات

```python
from qanas.modules import vuln_scanner

# إجراء مسح شامل للثغرات
results = vuln_scanner.comprehensive_vuln_scan("https://example.com")

# مسح باستخدام أدوات محددة
sqlmapResults = vuln_scanner.sqlmap_scan("https://example.com/page.php?id=1")
xssResults = vuln_scanner.xsstrike_scan("https://example.com/search.php?q=test")
sslResults = vuln_scanner.sslyze_scan("example.com")
```

### جمع المعلومات

```python
from qanas.modules import recon_scanner

# إجراء استطلاع شامل
results = recon_scanner.comprehensive_recon("example.com")

# استخدام أدوات محددة
whoisInfo = recon_scanner.whois_lookup("example.com")
emails = recon_scanner.harvest_emails("example.com")
shodanResults = recon_scanner.shodan_lookup("example.com", api_key="YOUR_SHODAN_API_KEY")
```

## إضافة إضافات (Plugins)

```python
from qanas import Qanas
from qanas.plugins import register_plugin

# تعريف plugin جديد
class MyCustomPlugin:
    def __init__(self):
        self.name = "my_custom_plugin"
        self.description = "A custom plugin for Qanas"
        self.enabled = True
    
    def run(self, target, options=None):
        # تنفيذ المسح المخصص
        results = {}
        # ... منطق المسح ...
        return results

# تسجيل الـ plugin
register_plugin(MyCustomPlugin())

# استخدام Qanas مع الـ plugin المسجل
scanner = Qanas()
results = scanner.scan_target("example.com")
# نتائج الـ plugin ستكون متاحة في results['my_custom_plugin']
```

## تخصيص الإعدادات

```python
from qanas import Qanas
from qanas.config import ScanOptions

# تعريف خيارات مسح مخصصة
options = ScanOptions(
    port_scan=True,
    port_scan_type="quick",  # "quick" or "full"
    web_scan=True,
    web_scan_tools=["whatweb", "nikto", "dirb"],
    dns_scan=True,
    vuln_scan=True,
    vuln_scan_tools=["sqlmap", "xsstrike", "sslyze"],
    recon=True,
    threads=5,
    timeout=60,
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
)

# إنشاء كائن Qanas مع الخيارات المخصصة
scanner = Qanas(options=options)
results = scanner.scan_target("example.com")
```

## معالجة الأخطاء

```python
from qanas import Qanas
from qanas.exceptions import QanasError, ConnectionError, ScanError

try:
    scanner = Qanas()
    results = scanner.scan_target("example.com")
except ConnectionError as e:
    print(f"Connection error: {e}")
except ScanError as e:
    print(f"Scan error: {e}")
except QanasError as e:
    print(f"General error: {e}")
```

## أمثلة متقدمة

### دمج مع نظام المراقبة

```python
from qanas import Qanas
import time
import json

def monitor_targets(targets, interval_hours=24):
    scanner = Qanas()
    while True:
        for target in targets:
            try:
                results = scanner.scan_target(target)
                # حفظ النتائج في قاعدة بيانات أو ملف
                with open(f"{target}_latest.json", "w") as f:
                    json.dump(results, f)
                
                # التحقق من وجود ثغرات جديدة
                if results.get('vuln_scan', {}).get('new_vulnerabilities'):
                    send_alert(target, results['vuln_scan']['new_vulnerabilities'])
            except Exception as e:
                print(f"Error scanning {target}: {e}")
        
        # الانتظار حتى الفحص التالي
        time.sleep(interval_hours * 3600)

def send_alert(target, vulnerabilities):
    # إرسال تنبيه (مثلاً عبر البريد الإلكتروني أو Slack)
    pass

# بدء المراقبة
monitor_targets(["example.com", "example.org"])
```

### تكامل مع واجهة مستخدم ويب

```python
from flask import Flask, request, jsonify
from qanas import Qanas

app = Flask(__name__)
scanner = Qanas()

@app.route('/api/scan', methods=['POST'])
def scan_target():
    data = request.json
    target = data.get('target')
    scan_type = data.get('scan_type', 'normal')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    try:
        scanner.scan_mode = scan_type
        results = scanner.scan_target(target)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/<target>')
def get_report(target):
    try:
        # استرجاع التقرير المخزن
        with open(f"loot/{target}/report.json", "r") as f:
            report = json.load(f)
        return jsonify(report)
    except FileNotFoundError:
        return jsonify({'error': 'Report not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)
```

## ملاحظات هامة

- تأكد من استخدام Qanas بشكل قانوني وأخلاقي، وفقط على الأنظمة التي لديك إذن صريح لاختبارها.
- بعض وظائف المسح قد تكون مكثفة للموارد، لذا يجب مراعاة قيود النظام عند استخدامها.
- قد تتطلب بعض الوظائف مفاتيح API خارجية (مثل Shodan أو Censys)، والتي يجب توفيرها في ملف التكوين.

## المساهمة في تطوير API

إذا كنت ترغب في المساهمة في تطوير واجهة برمجة التطبيقات، يرجى الاطلاع على [دليل المساهمة](CONTRIBUTING.md) للحصول على معلومات حول كيفية المساهمة في المشروع.