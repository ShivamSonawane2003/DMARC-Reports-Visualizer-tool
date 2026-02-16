import xml.etree.ElementTree as ET
import os
import zipfile
import gzip
import tarfile
import shutil
from collections import defaultdict
from datetime import datetime
import ipaddress
import socket


class DMARCProcessor:
    """Process DMARC XML reports and generate analytics"""
    
    def __init__(self, logger):
        self.logger = logger
        
    def process_files(self, file_paths, session_dir):
        """
        Process multiple DMARC report files
        Returns aggregated analytics data
        """
        try:
            # Extract all XML files
            xml_files = []
            for file_path in file_paths:
                extracted = self._extract_files(file_path, session_dir)
                xml_files.extend(extracted)
            
            self.logger.info(f'Found {len(xml_files)} XML file(s) to process')
            
            if not xml_files:
                return {
                    'error': 'No valid DMARC XML files found',
                    'files_processed': 0
                }
            
            # Parse all XML files
            reports = []
            parse_errors = []
            
            for xml_file in xml_files:
                try:
                    report = self._parse_dmarc_xml(xml_file)
                    if report:
                        reports.append(report)
                        self.logger.info(f'Successfully parsed: {os.path.basename(xml_file)}')
                except Exception as e:
                    error_msg = f'Error parsing {os.path.basename(xml_file)}: {str(e)}'
                    self.logger.error(error_msg)
                    parse_errors.append(error_msg)
            
            if not reports:
                return {
                    'error': 'No valid DMARC reports could be parsed',
                    'parse_errors': parse_errors,
                    'files_processed': 0
                }
            
            # Generate analytics
            analytics = self._generate_analytics(reports)
            analytics['files_processed'] = len(reports)
            analytics['parse_errors'] = parse_errors
            
            return analytics
            
        except Exception as e:
            self.logger.error(f'Error in process_files: {str(e)}')
            return {
                'error': f'Processing failed: {str(e)}',
                'files_processed': 0
            }
    
    def _extract_files(self, file_path, extract_dir):
        """
        Extract files from ZIP, GZ, TAR archives
        Returns list of XML file paths
        """
        xml_files = []
        filename = os.path.basename(file_path)
        
        try:
            # Handle ZIP files
            if filename.endswith('.zip'):
                self.logger.info(f'Extracting ZIP: {filename}')
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                xml_files = self._find_xml_files(extract_dir)
            
            # Handle GZ files
            elif filename.endswith('.gz'):
                self.logger.info(f'Extracting GZ: {filename}')
                output_path = os.path.join(extract_dir, filename[:-3])
                with gzip.open(file_path, 'rb') as f_in:
                    with open(output_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                
                # If extracted file is XML, add it
                if output_path.endswith('.xml'):
                    xml_files.append(output_path)
                else:
                    # Recursively extract if it's another archive
                    xml_files.extend(self._extract_files(output_path, extract_dir))
            
            # Handle TAR files
            elif filename.endswith('.tar') or filename.endswith('.tar.gz'):
                self.logger.info(f'Extracting TAR: {filename}')
                with tarfile.open(file_path, 'r:*') as tar_ref:
                    tar_ref.extractall(extract_dir)
                xml_files = self._find_xml_files(extract_dir)
            
            # Handle XML files directly
            elif filename.endswith('.xml'):
                xml_files.append(file_path)
            
            else:
                self.logger.warning(f'Unknown file type: {filename}')
            
            return xml_files
            
        except Exception as e:
            self.logger.error(f'Error extracting {filename}: {str(e)}')
            return xml_files
    
    def _find_xml_files(self, directory):
        """Recursively find all XML files in directory"""
        xml_files = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.xml'):
                    xml_files.append(os.path.join(root, file))
        return xml_files
    
    def _parse_dmarc_xml(self, xml_file):
        """Parse a single DMARC XML report"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Handle namespace
            ns = {'ns': 'urn:ietf:params:xml:ns:dmarc-2.0'} if root.tag.startswith('{') else {}
            
            def find_text(element, path, namespaces=None):
                """Helper to find text in element with optional namespace"""
                if namespaces:
                    elem = element.find(path, namespaces)
                else:
                    elem = element.find(path)
                return elem.text if elem is not None else None
            
            # Parse metadata
            metadata = root.find('report_metadata') or root.find('ns:report_metadata', ns)
            if metadata is None:
                self.logger.warning(f'No metadata found in {xml_file}')
                return None
            
            org_name = find_text(metadata, 'org_name') or find_text(metadata, 'ns:org_name', ns)
            report_id = find_text(metadata, 'report_id') or find_text(metadata, 'ns:report_id', ns)
            
            date_range = metadata.find('date_range') or metadata.find('ns:date_range', ns)
            begin = int(find_text(date_range, 'begin') or find_text(date_range, 'ns:begin', ns) or 0)
            end = int(find_text(date_range, 'end') or find_text(date_range, 'ns:end', ns) or 0)
            
            # Parse policy
            policy = root.find('policy_published') or root.find('ns:policy_published', ns)
            domain = find_text(policy, 'domain') or find_text(policy, 'ns:domain', ns)
            policy_p = find_text(policy, 'p') or find_text(policy, 'ns:p', ns)
            
            # Parse records
            records = []
            for record in root.findall('record') or root.findall('ns:record', ns):
                row = record.find('row') or record.find('ns:row', ns)
                source_ip = find_text(row, 'source_ip') or find_text(row, 'ns:source_ip', ns)
                count = int(find_text(row, 'count') or find_text(row, 'ns:count', ns) or 0)
                
                policy_eval = row.find('policy_evaluated') or row.find('ns:policy_evaluated', ns)
                disposition = find_text(policy_eval, 'disposition') or find_text(policy_eval, 'ns:disposition', ns)
                dkim = find_text(policy_eval, 'dkim') or find_text(policy_eval, 'ns:dkim', ns)
                spf = find_text(policy_eval, 'spf') or find_text(policy_eval, 'ns:spf', ns)
                
                identifiers = record.find('identifiers') or record.find('ns:identifiers', ns)
                header_from = find_text(identifiers, 'header_from') or find_text(identifiers, 'ns:header_from', ns)
                
                records.append({
                    'source_ip': source_ip,
                    'count': count,
                    'disposition': disposition,
                    'dkim': dkim,
                    'spf': spf,
                    'header_from': header_from
                })
            
            return {
                'org_name': org_name,
                'report_id': report_id,
                'domain': domain,
                'policy': policy_p,
                'date_begin': begin,
                'date_end': end,
                'records': records
            }
            
        except Exception as e:
            self.logger.error(f'Error parsing XML {xml_file}: {str(e)}')
            raise
    
    def _generate_analytics(self, reports):
        """Generate comprehensive analytics from parsed reports"""
        
        # Initialize counters
        total_messages = 0
        dkim_pass = 0
        dkim_fail = 0
        spf_pass = 0
        spf_fail = 0
        dmarc_pass = 0
        dmarc_fail = 0
        
        ip_data = defaultdict(lambda: {
            'count': 0,
            'dkim_pass': 0,
            'spf_pass': 0,
            'dmarc_pass': 0
        })
        
        source_orgs = defaultdict(int)
        domains = set()
        dispositions = defaultdict(int)
        date_range = {'earliest': None, 'latest': None}
        
        daily_stats = defaultdict(lambda: {
            'total': 0,
            'dkim_pass': 0,
            'spf_pass': 0,
            'dmarc_pass': 0
        })
        
        # Process all reports
        for report in reports:
            source_orgs[report['org_name']] += 1
            domains.add(report['domain'])
            
            # Update date range
            if date_range['earliest'] is None or report['date_begin'] < date_range['earliest']:
                date_range['earliest'] = report['date_begin']
            if date_range['latest'] is None or report['date_end'] > date_range['latest']:
                date_range['latest'] = report['date_end']
            
            # Process records
            for record in report['records']:
                count = record['count']
                total_messages += count
                
                # DKIM stats
                if record['dkim'] == 'pass':
                    dkim_pass += count
                else:
                    dkim_fail += count
                
                # SPF stats
                if record['spf'] == 'pass':
                    spf_pass += count
                else:
                    spf_fail += count
                
                # DMARC pass = both DKIM and SPF pass
                if record['dkim'] == 'pass' and record['spf'] == 'pass':
                    dmarc_pass += count
                else:
                    dmarc_fail += count
                
                # IP statistics
                ip = record['source_ip']
                ip_data[ip]['count'] += count
                if record['dkim'] == 'pass':
                    ip_data[ip]['dkim_pass'] += count
                if record['spf'] == 'pass':
                    ip_data[ip]['spf_pass'] += count
                if record['dkim'] == 'pass' and record['spf'] == 'pass':
                    ip_data[ip]['dmarc_pass'] += count
                
                # Disposition stats
                dispositions[record['disposition']] += count
                
                # Daily stats
                date_str = datetime.fromtimestamp(report['date_begin']).strftime('%Y-%m-%d')
                daily_stats[date_str]['total'] += count
                if record['dkim'] == 'pass':
                    daily_stats[date_str]['dkim_pass'] += count
                if record['spf'] == 'pass':
                    daily_stats[date_str]['spf_pass'] += count
                if record['dkim'] == 'pass' and record['spf'] == 'pass':
                    daily_stats[date_str]['dmarc_pass'] += count
        
        # Prepare IP list with additional info
        ip_list = []
        for ip, stats in ip_data.items():
            ip_info = {
                'ip': ip,
                'count': stats['count'],
                'dkim_pass': stats['dkim_pass'],
                'spf_pass': stats['spf_pass'],
                'dmarc_pass': stats['dmarc_pass'],
                'compliance_rate': round((stats['dmarc_pass'] / stats['count'] * 100), 2) if stats['count'] > 0 else 0
            }
            
            # Try to get hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                ip_info['hostname'] = hostname
            except:
                ip_info['hostname'] = 'Unknown'
            
            ip_list.append(ip_info)
        
        # Sort IPs by count
        ip_list.sort(key=lambda x: x['count'], reverse=True)
        
        # Prepare daily timeline
        timeline = []
        for date_str in sorted(daily_stats.keys()):
            stats = daily_stats[date_str]
            timeline.append({
                'date': date_str,
                'total': stats['total'],
                'dkim_pass': stats['dkim_pass'],
                'spf_pass': stats['spf_pass'],
                'dmarc_pass': stats['dmarc_pass'],
                'compliance_rate': round((stats['dmarc_pass'] / stats['total'] * 100), 2) if stats['total'] > 0 else 0
            })
        
        # Calculate percentages
        dkim_pass_rate = round((dkim_pass / total_messages * 100), 2) if total_messages > 0 else 0
        spf_pass_rate = round((spf_pass / total_messages * 100), 2) if total_messages > 0 else 0
        dmarc_compliance = round((dmarc_pass / total_messages * 100), 2) if total_messages > 0 else 0
        
        return {
            'summary': {
                'total_messages': total_messages,
                'total_reports': len(reports),
                'domains': list(domains),
                'date_range': {
                    'start': datetime.fromtimestamp(date_range['earliest']).strftime('%Y-%m-%d') if date_range['earliest'] else None,
                    'end': datetime.fromtimestamp(date_range['latest']).strftime('%Y-%m-%d') if date_range['latest'] else None
                }
            },
            'authentication': {
                'dkim': {
                    'pass': dkim_pass,
                    'fail': dkim_fail,
                    'pass_rate': dkim_pass_rate
                },
                'spf': {
                    'pass': spf_pass,
                    'fail': spf_fail,
                    'pass_rate': spf_pass_rate
                },
                'dmarc_compliance': dmarc_compliance
            },
            'dispositions': dict(dispositions),
            'source_organizations': dict(source_orgs),
            'top_sources': ip_list[:20],  # Top 20 IPs
            'timeline': timeline,
            'threats': self._identify_threats(ip_list, dmarc_compliance)
        }
    
    def _identify_threats(self, ip_list, dmarc_compliance):
        """Identify potential security threats"""
        threats = []
        
        # Check for low compliance rate
        if dmarc_compliance < 80:
            threats.append({
                'level': 'warning',
                'title': 'Low DMARC Compliance',
                'description': f'Only {dmarc_compliance}% of emails are fully compliant. Consider strengthening your DMARC policy.'
            })
        
        # Check for IPs with high failure rates
        for ip_info in ip_list[:10]:  # Check top 10 IPs
            if ip_info['compliance_rate'] < 50 and ip_info['count'] > 10:
                threats.append({
                    'level': 'high',
                    'title': f'Suspicious IP: {ip_info["ip"]}',
                    'description': f'Low compliance rate ({ip_info["compliance_rate"]}%) with {ip_info["count"]} messages. Potential spoofing attempt.'
                })
        
        if not threats:
            threats.append({
                'level': 'success',
                'title': 'No Major Threats Detected',
                'description': 'Your email authentication is working well!'
            })
        
        return threats
