"""
Test script to verify DMARC Analyzer backend functionality
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dmarc_processor import DMARCProcessor
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_xml_parsing():
    """Test XML parsing with sample data"""
    print("\n" + "="*50)
    print("Testing DMARC XML Parsing")
    print("="*50)
    
    processor = DMARCProcessor(logger)
    
    # Create sample XML
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>Test Org</org_name>
    <email>test@example.com</email>
    <report_id>test-123</report_id>
    <date_range>
      <begin>1640000000</begin>
      <end>1640086400</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>none</p>
    <sp>none</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>192.168.1.1</source_ip>
      <count>10</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.com</domain>
        <r>pass</r>
      </dkim>
      <spf>
        <domain>example.com</domain>
        <r>pass</r>
      </spf>
    </auth_results>
  </record>
</feedback>"""
    
    # Save to temp file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(sample_xml)
        temp_file = f.name
    
    try:
        # Parse the file
        report = processor._parse_dmarc_xml(temp_file)
        
        if report:
            print("✓ XML parsing successful!")
            print(f"  - Organization: {report['org_name']}")
            print(f"  - Domain: {report['domain']}")
            print(f"  - Records: {len(report['records'])}")
            print(f"  - Total Messages: {sum(r['count'] for r in report['records'])}")
            return True
        else:
            print("✗ XML parsing failed!")
            return False
    finally:
        # Cleanup
        os.unlink(temp_file)

def test_analytics():
    """Test analytics generation"""
    print("\n" + "="*50)
    print("Testing Analytics Generation")
    print("="*50)
    
    processor = DMARCProcessor(logger)
    
    # Sample report data
    sample_reports = [{
        'org_name': 'Test Provider',
        'report_id': 'test-001',
        'domain': 'example.com',
        'policy': 'none',
        'date_begin': 1640000000,
        'date_end': 1640086400,
        'records': [
            {
                'source_ip': '192.168.1.1',
                'count': 100,
                'disposition': 'none',
                'dkim': 'pass',
                'spf': 'pass',
                'header_from': 'example.com'
            },
            {
                'source_ip': '192.168.1.2',
                'count': 50,
                'disposition': 'none',
                'dkim': 'fail',
                'spf': 'pass',
                'header_from': 'example.com'
            }
        ]
    }]
    
    # Generate analytics
    analytics = processor._generate_analytics(sample_reports)
    
    if analytics:
        print("✓ Analytics generation successful!")
        print(f"  - Total Messages: {analytics['summary']['total_messages']}")
        print(f"  - DMARC Compliance: {analytics['authentication']['dmarc_compliance']:.1f}%")
        print(f"  - DKIM Pass Rate: {analytics['authentication']['dkim']['pass_rate']:.1f}%")
        print(f"  - SPF Pass Rate: {analytics['authentication']['spf']['pass_rate']:.1f}%")
        print(f"  - Top Sources: {len(analytics['top_sources'])} IPs")
        print(f"  - Threats Detected: {len(analytics['threats'])}")
        return True
    else:
        print("✗ Analytics generation failed!")
        return False

def test_imports():
    """Test if all required imports work"""
    print("\n" + "="*50)
    print("Testing Dependencies")
    print("="*50)
    
    try:
        import flask
        print(f"✓ Flask {flask.__version__}")
    except ImportError as e:
        print(f"✗ Flask not found: {e}")
        return False
    
    try:
        import flask_cors
        print("✓ Flask-CORS installed")
    except ImportError as e:
        print(f"✗ Flask-CORS not found: {e}")
        return False
    
    try:
        import xml.etree.ElementTree
        print("✓ XML parser available")
    except ImportError as e:
        print(f"✗ XML parser not found: {e}")
        return False
    
    try:
        import zipfile
        import gzip
        import tarfile
        print("✓ Archive handlers available")
    except ImportError as e:
        print(f"✗ Archive handlers not found: {e}")
        return False
    
    return True

if __name__ == '__main__':
    print("\n" + "="*60)
    print(" DMARC Analyzer Backend Test Suite")
    print("="*60)
    
    all_passed = True
    
    # Run tests
    all_passed &= test_imports()
    all_passed &= test_xml_parsing()
    all_passed &= test_analytics()
    
    # Summary
    print("\n" + "="*60)
    if all_passed:
        print(" ✓ ALL TESTS PASSED!")
        print("="*60)
        print("\nBackend is ready to use. You can now:")
        print("  1. Run: python app.py")
        print("  2. Start the frontend")
        print("  3. Upload DMARC reports")
    else:
        print(" ✗ SOME TESTS FAILED")
        print("="*60)
        print("\nPlease check the errors above and:")
        print("  1. Ensure all dependencies are installed")
        print("  2. Run: pip install -r requirements.txt")
        sys.exit(1)
    
    print("\n")
